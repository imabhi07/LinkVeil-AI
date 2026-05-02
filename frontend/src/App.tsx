import { useState, useEffect, useCallback, useRef, memo, Component, type ErrorInfo } from 'react';
import { Search, AlertCircle, Shield, Globe, Terminal, Moon, Sun, ArrowRight, Bot, BarChart3, Mail } from 'lucide-react';
import type { AnalysisResult, ScanHistoryItem, BackendScanResponse, HistoryItem, EmailScanHistoryItem, EmailScanResponse } from './types';
import { ResultDetails } from './components/ResultDetails';
import { HistorySidebar } from './components/HistorySidebar';
import { AnalyticsPanel } from './components/AnalyticsPanel';
import { EmailScan } from './components/EmailScan';
import { BackgroundPaths } from './components/ui/background-paths';
import { mapToAnalysisResult } from './utils/mapper';
import './App.css';

const generateId = () => Math.random().toString(36).substr(2, 9);

// ── Error Boundary ──
class ErrorBoundary extends Component<{ children: React.ReactNode }, { hasError: boolean }> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(_: Error) {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("ErrorBoundary caught an error:", error, errorInfo);
  }

  handleReset = () => {
    // Selectively clear app-specific data instead of localStorage.clear()
    localStorage.removeItem('linkveil_history');
    localStorage.removeItem('linkveil_email_history');
    // Keep 'theme' to preserve user preference
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-12 text-center glass-panel border-rose-500/50 bg-rose-500/5 my-8 rounded-3xl mx-4">
          <AlertCircle className="w-12 h-12 text-rose-500 mx-auto mb-4" />
          <h2 className="text-xl font-bold mb-2 text-rose-500 uppercase tracking-tight">Interface Subsystem Failure</h2>
          <p className="text-zinc-400 mb-6 text-sm">A component failed to render. We've isolated the error to keep the platform stable.</p>
          <button 
            onClick={this.handleReset}
            className="px-8 py-3 bg-rose-600 text-white rounded-full font-bold hover:bg-rose-500 transition-all shadow-lg shadow-rose-500/20 uppercase tracking-widest text-xs"
          >
            Recover Session
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

const SECURITY_TIPS = [
  "Attackers often use homoglyphs (e.g., 'l' vs '1') to mimic legitimate services.",
  "Check the URL carefully. 'paypa1.com' is not 'paypal.com'.",
  "Legitimate companies will never ask for your password via email.",
  "Hover over links in emails to see the actual destination URL before clicking.",
  "Enable Multi-Factor Authentication (MFA) on all your sensitive accounts.",
  "If a deal looks too good to be true, it probably is a phishing attempt.",
  "Be wary of urgent requests demanding immediate action to prevent account closure.",
  "Verify the SSL certificate details if a website looks suspicious.",
  "Avoid clicking on shortened URLs from unknown sources.",
  "Keep your browser and antivirus software up to date."
];

const AGENT_STEPS = [
  "Initializing Agent...",
  "Spawning Headless Browser...",
  "Navigating to Target URL...",
  "Detecting Login Forms...",
  "Injecting Fake Credentials (User: test_admin)...",
  "Analyzing Server Response...",
  "Performing Visual Forensics...",
  "Finalizing Verdict..."
];



// ---------------------------------------------------------------------------
// Memoized FeatureCard - prevents re-renders when parent state changes
// ---------------------------------------------------------------------------
const FeatureCard = memo(({ icon, title, desc }: { icon: React.ReactNode, title: string, desc: string }) => (
  <div className="p-6 rounded-2xl glass-panel frosted-card-light dark:bg-black/40 card-gradient-border group h-full transition-all duration-500 hover:shadow-xl hover:-translate-y-1">
    <div className="flex items-start gap-4 mb-4">
      <div className="p-2.5 bg-white/80 dark:bg-ornex-black rounded-xl border border-zinc-100 dark:border-white/10 group-hover:border-[#00C853]/50 dark:group-hover:border-ornex-green/50 transition-all shadow-sm">
        {icon}
      </div>
      <div className="pt-1">
        <h3 className="text-[13px] font-black text-cyber-light-heading dark:text-zinc-100 mb-1 font-mono uppercase tracking-[0.1em]">{title}</h3>
        <div className="h-[2px] w-6 bg-[#00C853]/40 dark:bg-ornex-green/40 group-hover:w-full transition-all duration-700"></div>
      </div>
    </div>
    <p className="text-[13px] text-cyber-light-text dark:text-zinc-400 leading-relaxed font-sans opacity-90">{desc}</p>
  </div>
));
FeatureCard.displayName = 'FeatureCard';

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [currentResult, setCurrentResult] = useState<AnalysisResult | null>(null);
  const [currentEmailResult, setCurrentEmailResult] = useState<EmailScanResponse | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('linkveil_history');
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          return parsed
            .filter((i: any) => !i.type || i.type === 'url')
            .map((i: any) => ({ ...i, type: 'url' }));
        } catch (e) {
          console.error("Failed to parse history", e);
        }
      }
    }
    return [];
  });

  const [emailHistory, setEmailHistory] = useState<EmailScanHistoryItem[]>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('linkveil_email_history');
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          return parsed.map((i: any) => ({ ...i, type: 'email' }));
        } catch (e) {
          console.error("Failed to parse email history", e);
        }
      }
    }
    return [];
  });
  const [currentTip, setCurrentTip] = useState("");
  const [showAnalytics, setShowAnalytics] = useState(false);
  const [scanMode, setScanMode] = useState<'url' | 'email'>('url');

  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    if (typeof window !== 'undefined') {
      return (localStorage.getItem('theme') as 'dark' | 'light') || 'dark';
    }
    return 'dark';
  });

  // ── AbortController ref to cancel stale requests ──
  const abortRef = useRef<AbortController | null>(null);

  // Apply theme class to document
  useEffect(() => {
    const root = window.document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    localStorage.setItem('theme', theme);
  }, [theme]);

  // Set random tip on mount and cycle every 10 seconds
  useEffect(() => {
    const updateTip = () => setCurrentTip(SECURITY_TIPS[Math.floor(Math.random() * SECURITY_TIPS.length)]);
    updateTip();
    const interval = setInterval(updateTip, 10000);
    return () => clearInterval(interval);
  }, []);

  // Agent Loading Animation
  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    if (loading) {
      setLoadingStep(0);
      interval = setInterval(() => {
        setLoadingStep((prev) => (prev + 1) % AGENT_STEPS.length);
      }, 800);
    }
    return () => clearInterval(interval);
  }, [loading]);

  const toggleTheme = useCallback(() => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark');
  }, []);

  // Save histories on update
  useEffect(() => {
    const id = requestIdleCallback(() => {
      localStorage.setItem('linkveil_history', JSON.stringify(history));
    });
    return () => cancelIdleCallback(id);
  }, [history]);

  useEffect(() => {
    const id = requestIdleCallback(() => {
      localStorage.setItem('linkveil_email_history', JSON.stringify(emailHistory));
    });
    return () => cancelIdleCallback(id);
  }, [emailHistory]);

  const handleAnalyze = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    if (!url.includes('.') || url.length < 4) {
      setError("Please enter a valid URL.");
      return;
    }

    // Cancel any in-flight request
    if (abortRef.current) {
      abortRef.current.abort();
    }
    const controller = new AbortController();
    abortRef.current = controller;

    setLoading(true);
    setError(null);
    setCurrentResult(null);

    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
      const response = await fetch(`${API_BASE_URL}/api/v1/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.includes('://') ? url : `https://${url}` }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const errBody = await response.json().catch(() => ({}));
        throw new Error(errBody.detail || `Server error (${response.status})`);
      }

      const raw: BackendScanResponse = await response.json();
      const result = mapToAnalysisResult(raw);
      const historyItem: ScanHistoryItem = { ...result, id: generateId(), type: 'url' };

      setCurrentResult(result);
      setHistory(prev => {
        const filtered = prev.filter(item => item.url !== result.url);
        return [historyItem, ...filtered].slice(0, 50);
      });
      
      // Focus on the new result
      setTimeout(() => {
        const element = document.getElementById('url-results');
        element?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 100);
    } catch (err: any) {
      if (err.name === 'AbortError') return; // Silently ignore cancelled requests
      setError(err.message || "An error occurred during analysis.");
    } finally {
      setLoading(false);
    }
  }, [url]);

  const clearHistory = useCallback(() => {
    if (window.confirm("Are you sure you want to clear your scan history?")) {
      if (scanMode === 'url') {
        setHistory([]);
        setCurrentResult(null);
      } else {
        setEmailHistory([]);
        setCurrentEmailResult(null);
      }
    }
  }, [scanMode]);

  const handleDeleteHistoryItem = useCallback((id: string) => {
    if (scanMode === 'url') {
      setHistory(prev => {
        const itemToDelete = prev.find(item => item.id === id);
        if (itemToDelete && currentResult?.url === itemToDelete.url) {
          setCurrentResult(null);
        }
        return prev.filter(item => item.id !== id);
      });
    } else {
      setEmailHistory(prev => {
        const itemToDelete = prev.find(item => item.id === id);
        if (itemToDelete && currentEmailResult === itemToDelete.result) {
          setCurrentEmailResult(null);
        }
        return prev.filter(item => item.id !== id);
      });
    }
  }, [scanMode, currentResult, currentEmailResult]);

  // Memoize the onSelect handler
  const handleSelectHistory = useCallback((item: HistoryItem) => {
    if (!item) return;
    
    if (item.type === 'email') {
      setScanMode('email');
      setCurrentEmailResult(item.result);
      setCurrentResult(null); // Clear URL result when switching to email
    } else {
      setScanMode('url');
      setCurrentResult(item as ScanHistoryItem);
      setCurrentEmailResult(null); // Clear email result when switching to URL
    }

    // Automatically scroll to the results
    setTimeout(() => {
      const id = item.type === 'email' ? 'email-results' : 'url-results';
      const element = document.getElementById(id);
      element?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
  }, []);

  const handleEmailResult = useCallback((res: EmailScanResponse) => {
    const historyItem: EmailScanHistoryItem = {
      id: generateId(),
      type: 'email',
      timestamp: Date.now(),
      result: res
    };
    
    setEmailHistory(prev => {
      // Deduplicate emails by subject + sender (like URL dedupe)
      const filtered = prev.filter(item => {
        const sameSubject = item.result.parsed_email?.subject === res.parsed_email?.subject;
        const sameSender = item.result.parsed_email?.from_email === res.parsed_email?.from_email;
        return !(sameSubject && sameSender);
      });
      return [historyItem, ...filtered].slice(0, 50);
    });

    // Automatically focus on the new forensic result
    setCurrentEmailResult(res);
    setTimeout(() => {
      const element = document.getElementById('email-results');
      element?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
  }, []);

  return (
    <div className={`min-h-screen ${theme === 'light' ? 'light-hero-gradient' : 'bg-black'} transition-colors duration-500 overflow-x-hidden relative text-cyber-light-heading dark:text-zinc-100 font-sans pb-20`}>

      {/* 4K Grain Texture Overlay */}
      <div className="fixed inset-0 pointer-events-none z-[100] opacity-[0.03] mix-blend-overlay bg-[url('https://grainy-gradients.vercel.app/noise.svg')]"></div>

      {/* Background Glows - Absolute to scroll with content */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden h-[1200px]">
        {/* Main Hero Glow */}
        <div className="absolute -top-[10%] left-[10%] w-[1200px] h-[1000px] bg-cyber-light-accent/15 dark:bg-ornex-green/20 rounded-full blur-[180px] animate-pulse opacity-80"></div>
        {/* Secondary Side Glow */}
        <div className="absolute top-[0%] -left-[10%] w-[600px] h-[600px] bg-cyber-light-accent/10 dark:bg-ornex-green/15 rounded-full blur-[140px] animate-pulse animation-delay-2000 opacity-60"></div>
      </div>

      {/* Animated SVG paths - full bleed */}
      <div className="absolute inset-x-0 top-0 h-[1000px] pointer-events-none overflow-hidden opacity-50 dark:opacity-35 z-0">
        <BackgroundPaths />
        <div className="absolute inset-x-0 bottom-0 h-96 bg-gradient-to-t from-cyber-light-bg dark:from-black to-transparent" />
      </div>

      {/* Top scroll mask */}
      <div className="fixed top-0 inset-x-0 h-24 bg-gradient-to-b from-cyber-light-bg dark:from-black to-transparent z-40 pointer-events-none"></div>

      {/* Navbar */}
      <nav className="fixed top-6 left-0 right-0 z-50 flex justify-center px-4 pointer-events-none">
        <div className="w-full max-w-7xl frosted-nav dark:bg-ornex-panel dark:border-white/10 rounded-full px-6 h-16 flex items-center justify-between shadow-2xl shadow-black/5 dark:shadow-black/20 pointer-events-auto">
          <div className="flex items-center gap-3">
             <div className="w-8 h-8 rounded bg-cyber-light-accent dark:bg-ornex-green flex items-center justify-center text-white dark:text-ornex-black shadow-[0_0_15px_rgba(0,200,83,0.4)] dark:shadow-[0_0_15px_rgba(57,255,20,0.5)]">
               <Shield className="w-5 h-5 fill-current" />
             </div>
            <span className="text-xl font-bold tracking-tight text-cyber-light-heading dark:text-white">
              LinkVeil AI
            </span>
          </div>

          <div className="flex items-center gap-4">
            <span className="hidden sm:inline-flex items-center gap-1.5 text-xs font-mono text-cyber-light-accent dark:text-zinc-500 uppercase tracking-wider">
              <span className="w-2 h-2 bg-cyber-light-accent dark:bg-ornex-green rounded-full animate-pulse shadow-[0_0_8px_rgba(0,200,83,0.5)] dark:shadow-[0_0_8px_#39FF14]"></span>
              System Active
            </span>
            <div className="flex items-center gap-3">
              <button 
                onClick={() => setShowAnalytics(true)}
                className="flex items-center gap-2 px-4 py-2 bg-cyber-light-accent/10 hover:bg-cyber-light-accent/20 text-cyber-light-accent dark:text-ornex-green border border-cyber-light-accent/20 rounded-full transition-all text-sm font-medium"
              >
                <BarChart3 className="w-4 h-4" />
                <span>Analytics</span>
              </button>
              <button
                onClick={toggleTheme}
                className="p-2 rounded-full bg-cyber-light-bg dark:bg-white/5 text-cyber-light-text dark:text-zinc-400 hover:bg-white dark:hover:bg-white/10 transition-colors border border-transparent dark:border-white/5"
                aria-label="Toggle theme"
              >
                {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-32 lg:pt-40 relative z-10">
        <ErrorBoundary>
          <div className="w-full mx-auto flex flex-col gap-12">

            {/* Main Content */}
            <div className="w-full space-y-12">

              {/* Hero Section */}
              <div className="text-center space-y-8 flex flex-col items-center relative z-10">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyber-light-accent/30 bg-cyber-light-accent/10 text-cyber-light-accent dark:border-ornex-green/30 dark:bg-ornex-green/10 dark:text-ornex-green text-xs font-mono tracking-widest uppercase transition-colors">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-light-accent dark:bg-ornex-green opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-cyber-light-accent dark:bg-ornex-green"></span>
                  </span>
                  Defend Yourself From Phishing
                </div>

                <h1 className="text-5xl md:text-6xl font-black tracking-tighter text-cyber-light-heading dark:text-white leading-[0.95] uppercase tracking-[-0.01em]">
                  Cyber Defense <br />
                  <span className="text-[#8A9E8A] dark:text-zinc-500">That Evolves</span> <br />
                  <span className="text-[#00A846] dark:text-ornex-green drop-shadow-[0_0_20px_rgba(0,168,70,0.15)] dark:drop-shadow-[0_0_20px_rgba(57,255,20,0.3)]">Daily.</span>
                </h1>

                <p className="text-cyber-light-text dark:text-zinc-400 max-w-xl text-lg leading-relaxed">
                  AI-driven protection that learns, adapts, and grows stronger every single day - so you stay one step ahead of every digital threat.
                </p>
              </div>

              {/* Scan Container */}
              <div className="flex flex-col items-center w-full space-y-8 relative z-20">
                {/* Mode Toggle Tabs */}
                <div className="flex p-1.5 bg-zinc-200/50 dark:bg-white/5 backdrop-blur-md rounded-2xl border border-zinc-200 dark:border-white/10 relative z-20">
                  <button
                    onClick={() => {
                      setScanMode('url');
                      setCurrentEmailResult(null); // Clear other mode's result
                    }}
                    className={`flex items-center gap-2 px-6 py-2.5 rounded-xl text-sm font-bold uppercase tracking-widest transition-all
                      ${scanMode === 'url' 
                        ? 'bg-white dark:bg-ornex-green text-cyber-light-accent dark:text-ornex-black shadow-lg shadow-black/5 dark:shadow-ornex-green/20' 
                        : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'
                      }`}
                  >
                    <Search className="w-4 h-4" />
                    URL Scan
                  </button>
                  <button
                    onClick={() => {
                      setScanMode('email');
                      setCurrentResult(null); // Clear other mode's result
                    }}
                    className={`flex items-center gap-2 px-6 py-2.5 rounded-xl text-sm font-bold uppercase tracking-widest transition-all
                      ${scanMode === 'email' 
                        ? 'bg-white dark:bg-ornex-green text-cyber-light-accent dark:text-ornex-black shadow-lg shadow-black/5 dark:shadow-ornex-green/20' 
                        : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'
                      }`}
                  >
                    <Mail className="w-4 h-4" />
                    Email Scan
                  </button>
                </div>

                {scanMode === 'url' ? (
                  <>
                    <form onSubmit={handleAnalyze} className="max-w-2xl w-full relative group">
                      <div className="relative flex items-center p-2 glass-panel dark:bg-black/40 rounded-full dark:border-white/15 transition-all duration-300 hover:border-cyber-light-accent/50 dark:hover:border-ornex-green/50 hover:shadow-[0_0_30px_rgba(0,200,83,0.15)] dark:hover:shadow-[0_0_30px_rgba(57,255,20,0.1)]">
                        <div className="pl-6 text-cyber-light-text dark:text-zinc-500">
                          <Search className="w-5 h-5" />
                        </div>
                        <input
                          type="text"
                          value={url}
                          onChange={(e) => setUrl(e.target.value)}
                          placeholder="ENTER TARGET URL..."
                          className="flex-1 w-full bg-transparent border-none outline-none focus:outline-none focus:ring-0 ring-0 shadow-none appearance-none py-3 px-4 text-cyber-light-heading dark:text-white placeholder-cyber-light-text/60 dark:placeholder-zinc-600 text-base font-mono tracking-wide"
                          autoComplete="off"
                          id="url-input"
                        />

                        <button
                          type="submit"
                          disabled={loading || !url}
                          id="scan-button"
                          className={`px-8 py-3 font-black rounded-full transition-all flex items-center gap-2 uppercase tracking-widest text-xs
                            ${loading
                              ? 'bg-[#00C853] dark:bg-ornex-green text-white dark:text-ornex-black cursor-wait shadow-[0_4px_20px_rgba(0,180,80,0.35)]'
                              : !url
                                ? 'bg-[#E0E8E0] text-[#8CA58C] dark:bg-white/10 dark:text-zinc-600 cursor-not-allowed'
                                : 'bg-gradient-to-br from-[#00C853] to-[#00A846] dark:bg-gradient-to-r dark:from-[#00C853] dark:to-ornex-green text-white dark:text-ornex-black shadow-[0_4px_20px_rgba(0,180,80,0.35)] hover:scale-105 active:scale-95'
                            }`}
                        >
                          {loading ? (
                            <div className="w-5 h-5 border-[3px] border-white/30 dark:border-black/30 border-t-white dark:border-t-black rounded-full animate-spin" />
                          ) : (
                            <>
                              SCAN <ArrowRight className="w-4 h-4" />
                            </>
                          )}
                        </button>
                      </div>
                    </form>

                    {/* Agent Status Display */}
                    {loading && (
                      <div className="max-w-xl pl-4 flex items-center gap-3 text-emerald-600 dark:text-ornex-green font-mono text-xs animate-pulse">
                        <Bot className="w-4 h-4" />
                        <span className="uppercase tracking-widest">
                          {AGENT_STEPS[loadingStep]}
                        </span>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="w-full">
                    <EmailScan 
                      mapToAnalysisResult={mapToAnalysisResult} 
                      onResult={handleEmailResult}
                      initialResult={currentEmailResult}
                    />
                  </div>
                )}
              </div>

              {/* Error Message */}
              {error && (
                <div className="relative bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-500/30 text-rose-600 dark:text-rose-400 px-6 py-4 rounded-xl flex items-start gap-3 animate-fade-in backdrop-blur-md" role="alert">
                  <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <h3 className="font-semibold uppercase tracking-wider text-xs mb-1">System Alert</h3>
                    <p className="text-sm opacity-90">{error}</p>
                  </div>
                  <button
                    onClick={() => setError(null)}
                    className="p-1 rounded-md hover:bg-rose-100 dark:hover:bg-rose-500/20 transition-colors text-lg leading-none"
                    aria-label="Dismiss error"
                  >
                    ✕
                  </button>
                </div>
              )}

              {/* Results Display */}
              <div id="url-results" className="scroll-mt-32">
                {currentResult && !loading && (
                  <div className="animate-fade-in">
                     <ResultDetails result={currentResult} />
                  </div>
                )}
              </div>

              {/* Empty State / Features */}
              {!currentResult && !loading && !error && (
                <div className="relative pt-12 border-t border-zinc-200 dark:border-white/5 overflow-hidden">
                  
                  <div className="relative z-10 space-y-8">
                    <div className="flex items-center gap-6 px-4">
                        <div className="h-px flex-1 bg-gradient-to-r from-transparent via-zinc-400/20 dark:via-white/10 to-transparent"></div>
                        <div className="flex flex-col items-center gap-1">
                          <span className="text-[12px] font-mono text-[#00C853] dark:text-ornex-green uppercase tracking-[0.3em] font-black opacity-80 flex items-center gap-2">
                             <span className="w-1.5 h-1.5 bg-[#00C853] dark:bg-ornex-green rounded-full shadow-[0_0_8px_#00C853]"></span>
                             System Core
                          </span>
                          <span className="text-[11px] font-mono text-zinc-400 dark:text-zinc-500 uppercase tracking-[0.2em] font-bold">Forensic Capabilities</span>
                        </div>
                        <div className="h-px flex-1 bg-gradient-to-r from-transparent via-zinc-400/20 dark:via-white/10 to-transparent"></div>
                    </div>
                    
                    {/* Marquee Container */}
                    <div className="relative marquee-mask">
                      <div className="animate-marquee gap-8 py-6">
                        {[1, 2].map((set) => (
                          <div key={set} className="flex gap-8">
                            {[
                              { icon: <Terminal className="w-4 h-4" />, title: "Pattern Logic", desc: "Heuristic identification of obfuscated JS and homograph attacks." },
                              { icon: <Mail className="w-4 h-4" />, title: "Email Forensics", desc: "Deep parsing of raw headers, SPF/DKIM verification, and spoofing detection." },
                              { icon: <Shield className="w-4 h-4" />, title: "SSRF Hardening", desc: "DNS-level rebinding protection and isolation of private network ranges." },
                              { icon: <Bot className="w-4 h-4" />, title: "Visual AI", desc: "Computer vision powered brand matching to detect UI-level impersonation." },
                              { icon: <BarChart3 className="w-4 h-4" />, title: "Hybrid Fusion", desc: "Correlation of XGBoost pattern scoring with threat intelligence feeds." },
                              { icon: <Globe className="w-4 h-4" />, title: "Global Intel", desc: "Active reputation lookups across global databases for known malicious domains." }
                            ].map((feature, idx) => (
                              <div key={idx} className="w-[320px] flex-shrink-0">
                                <FeatureCard
                                  icon={feature.icon}
                                  title={feature.title}
                                  desc={feature.desc}
                                />
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

            </div>

            {/* Bottom Section */}
            <div className="w-full space-y-6 pb-12">
               <HistorySidebar
                  history={scanMode === 'url' ? history : emailHistory}
                  mode={scanMode}
                  onSelect={handleSelectHistory}
                  onClear={clearHistory}
                  onDelete={handleDeleteHistoryItem}
               />

               {/* Info Panel */}
               <div className="glass-panel p-6 rounded-2xl transition-colors relative overflow-hidden group">
                 <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                    <Shield className="w-24 h-24 text-cyber-light-accent dark:text-ornex-green" />
                 </div>
                 <h3 className="text-xs font-bold text-cyber-light-accent dark:text-ornex-green uppercase tracking-widest mb-4 flex items-center gap-2">
                   <span className="w-1.5 h-1.5 bg-cyber-light-accent dark:bg-ornex-green rounded-full"></span>
                   Security Intel
                 </h3>
                 <p className="text-sm text-cyber-light-text dark:text-zinc-400 leading-relaxed font-mono">
                   // ADVISORY <br/>
                   {currentTip || "Loading security tips..."}
                 </p>
               </div>
            </div>

          </div>
        </ErrorBoundary>
      </main>


      {/* Analytics Overlay */}
      {showAnalytics && <AnalyticsPanel onClose={() => setShowAnalytics(false)} />}
    </div>
  );
}

export default App;
