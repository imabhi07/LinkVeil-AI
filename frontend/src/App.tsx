import { useState, useEffect, useCallback, useRef, memo } from 'react';
import { Search, AlertCircle, Shield, Globe, Terminal, Moon, Sun, ArrowRight, Bot, BarChart3 } from 'lucide-react';
import type { AnalysisResult, ScanHistoryItem, RiskLevel, BackendScanResponse, AgentReport } from './types';
import { ResultDetails } from './components/ResultDetails';
import { HistorySidebar } from './components/HistorySidebar';
import { AnalyticsPanel } from './components/AnalyticsPanel';
import { BackgroundPaths } from './components/ui/background-paths';
import './App.css';

const generateId = () => Math.random().toString(36).substr(2, 9);

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
// Map the backend's ScanResponse → prototype's AnalysisResult
// ---------------------------------------------------------------------------

function mapToAnalysisResult(raw: BackendScanResponse): AnalysisResult {
  let riskLevel: RiskLevel;
  let verdictTitle: string;
  switch (raw.risk_level?.toLowerCase()) {
    case 'high':
      riskLevel = 'MALICIOUS';
      verdictTitle = 'Malicious Site Detected';
      break;
    case 'medium':
      riskLevel = 'SUSPICIOUS';
      verdictTitle = 'Suspicious Activity Found';
      break;
    case 'low':
      riskLevel = 'SAFE';
      verdictTitle = 'Verified Safe';
      break;
    default:
      riskLevel = 'UNKNOWN';
      verdictTitle = 'Analysis Inconclusive';
  }
  
  if (raw.verdictTitle) {
    if (riskLevel === 'MALICIOUS' && raw.verdictTitle.toUpperCase().includes('SUSPICIOUS')) {
      verdictTitle = raw.verdictTitle.replace(/suspicious/i, 'MALICIOUS');
    } else if (riskLevel === 'SUSPICIOUS' && raw.verdictTitle.toUpperCase().includes('MALICIOUS')) {
      verdictTitle = raw.verdictTitle.replace(/malicious/i, 'SUSPICIOUS');
    } else {
      verdictTitle = raw.verdictTitle;
    }
  }

  const reasoning = raw.explanation
    ? raw.explanation.split(/\n+/).filter((s: string) => s.trim().length > 0)
    : ['No detailed findings available.'];

  // Map backend agent report - Stop fabricating outcomes
  const rawAgentData = raw.agentReport || {};
  const activeProbing = rawAgentData.activeProbing || rawAgentData; // Handle both nested and flat for compatibility during transition
  
  const mappedAgentReport: AgentReport = {
    activeProbing: {
      performed: !!activeProbing.performed,
      credentialsUsed: activeProbing.credentialsUsed || 'test_admin@linkveil.local / ●●●●●●●●',
      outcome: activeProbing.outcome || 'No outcome reported by agent.',
      behaviorRisk: (activeProbing.behaviorRisk || 'Unknown') as any,
      ...activeProbing
    }
  };

  let urlStructure = raw.url;
  try {
    const u = new URL(raw.url.includes('://') ? raw.url : `http://${raw.url}`);
    urlStructure = `Protocol: ${u.protocol} | Host: ${u.hostname} | Path: ${u.pathname}`;
  } catch { /* use raw url */ }

  const technicalDetails = {
    urlStructure,
    domainReputation: raw.whois_info?.domain_age_days != null
      ? `Domain age: ${raw.whois_info.domain_age_days} days. Registrar: ${raw.whois_info.registrar || 'Unknown'}.${raw.whois_info.is_new_domain ? ' ⚠️ Recently registered.' : ''}${raw.whois_info.has_privacy ? ' ⚠️ Uses privacy protection.' : ''}`
      : (riskLevel === 'SAFE' ? 'Domain registration appears legitimate.' : 'Domain reputation check inconclusive.'),
    socialEngineeringTricks: raw.brand_impersonation
      ? `Impersonates ${raw.brand_name} branding to trick users into submitting credentials.`
      : reasoning[0] || 'No social engineering patterns detected.',
    visualPrediction: raw.visual_forensics?.brand_match 
      ? `Visual match for ${raw.visual_forensics.brand_match} logo detected (score: ${raw.visual_forensics.score})`
      : 'No visual logo matches detected.'
  };

  return {
    url: raw.url,
    riskScore: Math.round(raw.risk_score),
    riskLevel,
    verdictTitle,
    reasoning,
    technicalDetails,
    agentReport: mappedAgentReport,
    timestamp: Date.now(),
    whois_info: raw.whois_info,
    threat_intel: raw.threat_intel,
    visual_forensics: raw.visual_forensics,
    fusion_trace: raw.fusion_trace,
    mitigationAdvice: raw.mitigationAdvice,
    probe_artifacts: raw.probe_artifacts
  };
}

// ---------------------------------------------------------------------------
// Memoized FeatureCard — prevents re-renders when parent state changes
// ---------------------------------------------------------------------------
const FeatureCard = memo(({ icon, title, desc }: { icon: React.ReactNode, title: string, desc: string }) => (
  <div className="p-6 rounded-2xl glass-panel dark:bg-white/5 dark:border-white/5 hover:border-cyber-light-accent/30 dark:hover:border-ornex-green/30 transition-all hover:bg-white/80 dark:hover:bg-white/10 group h-full">
    <div className="mb-4 p-3 bg-cyber-light-bg dark:bg-black w-fit rounded-lg border border-cyber-light-border dark:border-white/10 group-hover:border-cyber-light-accent/50 dark:group-hover:border-ornex-green/50 transition-colors shadow-lg">
      {icon}
    </div>
    <h3 className="text-lg font-bold text-cyber-light-heading dark:text-white mb-2 font-mono uppercase tracking-tight">{title}</h3>
    <p className="text-sm text-cyber-light-text dark:text-zinc-400 leading-relaxed">{desc}</p>
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
  const [history, setHistory] = useState<ScanHistoryItem[]>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('linkveil_history');
      if (saved) {
        try {
          return JSON.parse(saved);
        } catch (e) {
          console.error("Failed to parse history", e);
        }
      }
    }
    return [];
  });
  const [currentTip, setCurrentTip] = useState("");
  const [showAnalytics, setShowAnalytics] = useState(false);

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

  // Save history on update (debounced via requestIdleCallback for perf)
  useEffect(() => {
    const id = requestIdleCallback(() => {
      localStorage.setItem('linkveil_history', JSON.stringify(history));
    });
    return () => cancelIdleCallback(id);
  }, [history]);

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
      const historyItem: ScanHistoryItem = { ...result, id: generateId() };

      setCurrentResult(result);
      setHistory(prev => {
        const filtered = prev.filter(item => item.url !== result.url);
        return [historyItem, ...filtered].slice(0, 50);
      });
    } catch (err: any) {
      if (err.name === 'AbortError') return; // Silently ignore cancelled requests
      setError(err.message || "An error occurred during analysis.");
    } finally {
      setLoading(false);
    }
  }, [url]);

  const clearHistory = useCallback(() => {
    if (window.confirm("Are you sure you want to clear your scan history?")) {
      setHistory([]);
      setCurrentResult(null);
    }
  }, []);

  const handleDeleteHistoryItem = useCallback((id: string) => {
    setHistory(prev => {
      const itemToDelete = prev.find(item => item.id === id);
      if (itemToDelete && currentResult?.url === itemToDelete.url) {
        setCurrentResult(null);
      }
      return prev.filter(item => item.id !== id);
    });
  }, [currentResult]);

  // Memoize the onSelect handler
  const handleSelectHistory = useCallback((item: ScanHistoryItem) => {
    setCurrentResult(item);
  }, []);

  return (
    <div className="min-h-screen bg-cyber-light-bg dark:bg-ornex-black text-cyber-light-heading dark:text-zinc-100 font-sans pb-20 transition-colors duration-300 relative">

      {/* Background Glows */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -top-[20%] -left-[10%] w-[800px] h-[800px] bg-cyber-light-accent/15 dark:bg-ornex-green/10 rounded-full blur-[120px] animate-blob mix-blend-multiply dark:mix-blend-screen opacity-60"></div>
        <div className="absolute top-[40%] -right-[10%] w-[600px] h-[600px] bg-cyber-light-accent/10 dark:bg-ornex-green/5 rounded-full blur-[100px] animate-blob animation-delay-2000 mix-blend-multiply dark:mix-blend-screen opacity-40"></div>
      </div>

      {/* Animated SVG paths — full bleed */}
      <div className="absolute inset-x-0 top-0 h-[900px] pointer-events-none overflow-hidden opacity-50 dark:opacity-35 z-0">
        <BackgroundPaths />
        <div className="absolute inset-x-0 bottom-0 h-64 bg-gradient-to-t from-cyber-light-bg dark:from-ornex-black to-transparent" />
      </div>

      {/* Navbar */}
      <nav className="fixed top-6 left-0 right-0 z-50 flex justify-center px-4 pointer-events-none">
        <div className="w-full max-w-7xl glass-panel dark:bg-[#0a0a0a] dark:border-white/10 rounded-full px-6 h-16 flex items-center justify-between shadow-2xl shadow-black/5 dark:shadow-black/20 pointer-events-auto">
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
        <div className="w-full mx-auto flex flex-col gap-12">

          {/* Main Content */}
          <div className="w-full space-y-12">

            {/* Hero / Input Section */}
            <div className="text-center space-y-8 flex flex-col items-center relative z-10">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyber-light-accent/30 bg-cyber-light-accent/10 text-cyber-light-accent dark:border-ornex-green/30 dark:bg-ornex-green/10 dark:text-ornex-green text-xs font-mono tracking-widest uppercase transition-colors">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-light-accent dark:bg-ornex-green opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-cyber-light-accent dark:bg-ornex-green"></span>
                </span>
                Defend Yourself From Phishing
              </div>

              <h1 className="text-5xl md:text-7xl font-bold tracking-tighter text-cyber-light-heading dark:text-white leading-[0.95] uppercase">
                Cyber Defense <br />
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-zinc-500 to-zinc-800 dark:from-zinc-400 dark:to-zinc-700">That Evolves</span> <br />
                <span className="text-cyber-light-accent dark:text-ornex-green drop-shadow-[0_0_15px_rgba(0,200,83,0.25)] dark:drop-shadow-[0_0_15px_rgba(57,255,20,0.4)]">Daily.</span>
              </h1>

              <p className="text-cyber-light-text dark:text-zinc-400 max-w-xl text-lg leading-relaxed">
                AI-driven protection that learns, adapts, and grows stronger every single day—so you stay one step ahead of every digital threat.
              </p>

              <form onSubmit={handleAnalyze} className="max-w-2xl w-full relative group mt-8">
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
                    className={`px-8 py-3 font-bold rounded-full transition-all flex items-center gap-2 
                      ${loading
                        ? 'bg-cyber-light-accent dark:bg-ornex-green text-white dark:text-ornex-black cursor-wait shadow-[0_0_15px_rgba(0,200,83,0.4)] dark:shadow-[0_0_15px_rgba(57,255,20,0.4)]'
                        : !url
                          ? 'bg-[#E0E8E0] text-[#8CA58C] dark:bg-white/10 dark:text-zinc-600 cursor-not-allowed'
                          : 'bg-cyber-light-accent hover:bg-cyber-light-accentHover dark:bg-ornex-green dark:hover:bg-[#32e010] text-white dark:text-ornex-black hover:shadow-[0_0_25px_rgba(0,200,83,0.6)] dark:hover:shadow-[0_0_25px_rgba(57,255,20,0.6)] hover:scale-105 active:scale-95 shadow-[0_0_15px_rgba(0,200,83,0.4)] dark:shadow-[0_0_15px_rgba(57,255,20,0.4)]'
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
                 <div className="max-w-xl mt-4 pl-4 flex items-center gap-3 text-emerald-600 dark:text-ornex-green font-mono text-xs animate-pulse">
                    <Bot className="w-4 h-4" />
                    <span className="uppercase tracking-widest">
                       {AGENT_STEPS[loadingStep]}
                    </span>
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
            {currentResult && !loading && (
              <div className="animate-fade-in">
                 <ResultDetails result={currentResult} />
              </div>
            )}

            {/* Empty State / Features */}
            {!currentResult && !loading && !error && (
              <div className="flex flex-col md:grid md:grid-cols-2 lg:grid-cols-3 gap-6 pt-12 border-t border-zinc-200 dark:border-white/5">
                <div className="col-span-1 md:col-span-2 lg:col-span-3 text-center md:text-left mb-4">
                    <span className="text-xs font-mono text-zinc-400 uppercase tracking-widest">Capabilities</span>
                </div>
                <FeatureCard
                  icon={<Terminal className="w-5 h-5 text-emerald-600 dark:text-ornex-green" />}
                  title="Pattern Recognition"
                  desc="Detects obfuscation and homograph attacks designed to deceive users."
                />
                <FeatureCard
                  icon={<Globe className="w-5 h-5 text-emerald-600 dark:text-ornex-green" />}
                  title="Domain Analysis"
                  desc="Identifies suspicious TLDs and excessive subdomain usage in real-time."
                />
                <FeatureCard
                  icon={<Shield className="w-5 h-5 text-emerald-600 dark:text-ornex-green" />}
                  title="Zero-Touch Safety"
                  desc="Analyzes links without visiting them, keeping your device completely isolated."
                />
              </div>
            )}

          </div>

          {/* Bottom Section */}
          <div className="w-full space-y-6 pb-12">
             <HistorySidebar
                history={history}
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
      </main>


      {/* Analytics Overlay */}
      {showAnalytics && <AnalyticsPanel onClose={() => setShowAnalytics(false)} />}
    </div>
  );
}

export default App;
