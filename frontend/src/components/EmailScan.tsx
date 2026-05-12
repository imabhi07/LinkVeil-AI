import { useState, useRef, useEffect } from 'react';
import { Mail, Shield, AlertCircle, ChevronDown, AlertTriangle, FileUp, Clipboard, Layout, ArrowRight, Info, CheckCircle2, Zap, Copy, ExternalLink, ShieldAlert, ShieldCheck, ShieldX, Fingerprint, MessageSquare, Link2, RefreshCcw, X } from 'lucide-react';
import type { EmailScanRequest, EmailScanResponse, AnalysisResult } from '../types';
import { ResultDetails } from './ResultDetails';
import { InfoTip } from './InfoTip';
import { RiskGauge } from './RiskGauge';
import { EmailForensicInsight } from './EmailForensicInsight';

interface EmailScanProps {
  onResult?: (result: EmailScanResponse, inputData?: string) => void;
  mapToAnalysisResult: (raw: any) => AnalysisResult;
  initialResult?: EmailScanResponse | null;
  initialInputData?: string;
  onShowPrivacy?: () => void;
}

type ScanMode = 'paste' | 'upload';

export function EmailScan({ mapToAnalysisResult, onResult, initialResult, initialInputData, onShowPrivacy }: EmailScanProps) {
  const [scanMode, setScanMode] = useState<ScanMode>('paste');
  const [rawEmail, setRawEmail] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<EmailScanResponse | null>(initialResult || null);
  const [error, setError] = useState<string | null>(null);
  const [showGuide, setShowGuide] = useState(false);

  useEffect(() => {
    if (initialResult) {
      setResult(initialResult);
      setError(null);
      // Clear selected file when loading a result to avoid UI confusion
      setSelectedFile(null);
    }
    
    // Always sync rawEmail with initialInputData, even if it's undefined (clears stale data)
    setRawEmail(initialInputData || '');
  }, [initialResult, initialInputData]);
  
  const [expandedUrls, setExpandedUrls] = useState<Record<string, boolean>>({});
  const [linkSort, setLinkSort] = useState<'risk-desc' | 'risk-asc'>('risk-desc');
  const [sortDropdownOpen, setSortDropdownOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const sortDropdownRef = useRef<HTMLDivElement>(null);
  
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (sortDropdownRef.current && !sortDropdownRef.current.contains(event.target as Node)) {
        setSortDropdownOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleSubmit = async (e?: React.FormEvent, force: boolean = false) => {
    if (e) e.preventDefault();
    
    // Track the actual input data for history persistence to avoid React state closure/batching issues
    let inputDataForHistory = rawEmail;
    
    // Effective mode handling:
    // 1. If rescanning (force=true) and we have stored raw email data, always use paste mode
    // 2. Otherwise, if we're in upload mode but have no file object (common when opening history) 
    //    but have raw content, fall back to paste/raw analysis.
    const effectiveMode = (force && rawEmail.trim()) 
      ? 'paste' 
      : (scanMode === 'upload' && !selectedFile && rawEmail.trim()) 
        ? 'paste' 
        : scanMode;

    // Validation
    if (effectiveMode === 'paste' && !rawEmail.trim()) {
      setError("Please paste the raw email content.");
      return;
    }
    if (effectiveMode === 'upload' && !selectedFile) {
      setError("Please select a .eml file to upload.");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
      let response;

      if (effectiveMode === 'upload' && selectedFile) {
        // Capture EML text for future rescan from history
        const emlText = await selectedFile.text();
        setRawEmail(emlText);
        inputDataForHistory = emlText;

        const uploadData = new FormData();
        uploadData.append('file', selectedFile);
        
        // EML endpoint supports force_refresh via query param
        const emlUrl = `${API_BASE_URL}/api/v1/scan/eml${force ? '?force_refresh=true' : ''}`;
        response = await fetch(emlUrl, {
          method: 'POST',
          body: uploadData,
        });
      } else {
        const payload: EmailScanRequest = { 
          raw_email: rawEmail,
          force_refresh: force 
        };
        const url = `${API_BASE_URL}/api/v1/scan/email${force ? '?force_refresh=true' : ''}`;
        response = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      }

      if (!response.ok) {
        const errBody = await response.json().catch(() => ({}));
        throw new Error(errBody.detail || `Server error (${response.status})`);
      }

      const data: EmailScanResponse = await response.json();
      setResult(data);
      // Pass the correct captured data to history, not the potentially stale state
      onResult?.(data, inputDataForHistory);

      // Auto-expand the link with the highest risk score
    } catch (err: any) {
      setError(err.message || "An error occurred during email analysis.");
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (level: string) => {
    const normalized = level?.toLowerCase();
    switch (normalized) {
      case 'high':
      case 'malicious': 
        return 'text-rose-700 dark:text-rose-500 bg-rose-50 dark:bg-rose-500/10 border-rose-200 dark:border-rose-500/20';
      case 'medium':
      case 'suspicious':
        return 'text-amber-900 dark:text-amber-500 bg-amber-50 dark:bg-amber-500/10 border-amber-200 dark:border-amber-500/20';
      case 'low':
      case 'safe':
        return 'text-emerald-900 dark:text-ornex-green bg-emerald-50 dark:bg-ornex-green/10 border-emerald-200 dark:border-ornex-green/20';
      case 'inconclusive': 
        return 'text-blue-700 dark:text-blue-400 bg-blue-50 dark:bg-blue-500/10 border-blue-200 dark:border-blue-500/20';
      default: return 'text-zinc-700 dark:text-zinc-500 bg-zinc-50 dark:bg-zinc-500/10 border-zinc-200 dark:border-zinc-500/20';
    }
  };

  const getAuthColor = (status: string) => {
    if (status === 'pass') return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
    if (status === 'fail') return 'text-rose-500 bg-rose-500/10 border-rose-500/20';
    return 'text-zinc-500 bg-zinc-500/10 border-zinc-500/20';
  };

  const copyToClipboard = async (text: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      console.error("Failed to copy to clipboard:", err);
    }
  };

  const formatUrl = (url: string) => {
    try {
      const parsed = new URL(url);
      const path = parsed.pathname === '/' ? '' : (parsed.pathname.length > 20 ? parsed.pathname.substring(0, 20) + '...' : parsed.pathname);
      return (
        <span className="flex items-center min-w-0">
          <span className="text-cyber-light-heading dark:text-white font-bold truncate">{parsed.hostname}</span>
          <span className="text-zinc-500 font-normal shrink-0">{path}</span>
        </span>
      );
    } catch {
      return <span className="truncate min-w-0">{url}</span>;
    }
  };

  return (
    <div className="space-y-8 animate-fade-in">
      <div className="glass-panel p-4 sm:p-6 md:p-8 rounded-2xl md:rounded-3xl dark:bg-zinc-900/40 border-zinc-200 dark:border-white/10 shadow-xl shadow-black/5">
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-6 mb-8 md:mb-10">
          <div className="flex items-center gap-3 md:gap-4">
            <div className="p-2.5 md:p-3 bg-cyber-light-accent/10 dark:bg-ornex-green/10 rounded-xl md:rounded-2xl border border-cyber-light-accent/20 dark:border-ornex-green/20 shrink-0">
              <Mail className="w-5 h-5 md:w-6 md:h-6 text-cyber-light-accent dark:text-ornex-green" />
            </div>
            <div className="space-y-0.5 md:space-y-1">
              <h2 className="text-xl md:text-2xl font-bold text-cyber-light-heading dark:text-white uppercase tracking-tight leading-none">Email Forensic Scan</h2>
              <p className="text-[10px] md:text-[11px] text-cyber-light-text dark:text-zinc-400 font-mono opacity-70">Detect phishing artifacts and malicious links</p>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 w-full lg:w-auto">
            <button
              onClick={() => setShowGuide(!showGuide)}
              className={`flex items-center justify-center gap-2 px-4 py-2.5 md:py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all border
                ${showGuide 
                  ? 'bg-cyber-light-accent/10 border-cyber-light-accent/30 text-cyber-light-accent dark:bg-ornex-green/10 dark:border-ornex-green/30 dark:text-ornex-green' 
                  : 'bg-zinc-100 dark:bg-white/5 border-zinc-200 dark:border-white/10 text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'
                }`}
            >
              <Info className="w-3.5 h-3.5" />
              {showGuide ? 'Hide Guide' : 'How to Scan'}
            </button>

            <div className="flex p-1 bg-zinc-100 dark:bg-white/5 rounded-xl border border-zinc-200 dark:border-white/10 relative">
              { [
                { id: 'paste', icon: Clipboard, label: 'Paste', fullLabel: 'Paste Raw Source', tip: 'Highest accuracy; parses full email headers + body.' },
                { id: 'upload', icon: FileUp, label: 'Upload', fullLabel: 'Upload .EML', tip: 'Most secure; upload an authentic .eml file directly.' }
              ].map((tab) => (
                <InfoTip 
                  key={tab.id} 
                  title={tab.fullLabel + " Mode"} 
                  content={tab.tip}
                  placement="bottom"
                  className={`flex-1 sm:flex-none flex items-center relative`}
                >
                  <button
                    type="button"
                    onClick={() => setScanMode(tab.id as any)}
                    aria-label={`Switch to ${tab.fullLabel} mode`}
                    className={`w-full flex items-center justify-center gap-2 px-3 md:px-4 py-2 rounded-lg text-[10px] md:text-xs font-bold uppercase tracking-widest transition-all ${scanMode === tab.id ? 'bg-white dark:bg-white/10 shadow-sm text-cyber-light-accent dark:text-ornex-green' : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'}`}
                  >
                    <tab.icon className="w-3.5 h-3.5" />
                    <span className="hidden xs:inline">{tab.fullLabel}</span>
                    <span className="inline xs:hidden">{tab.label}</span>
                  </button>
                </InfoTip>
              ))}
            </div>
          </div>
        </div>

        {showGuide && (
          <div className="mb-8 space-y-6 animate-slide-down" role="dialog" aria-labelledby="privacy-modal-title" aria-modal="true" onKeyDown={(e) => { if (e.key === 'Escape') setShowGuide(false); }}>
            <div className="p-5 md:p-8 rounded-2xl md:rounded-[2rem] bg-zinc-50 dark:bg-zinc-900/40 border border-[#00C853]/20 dark:border-ornex-green/20 shadow-2xl relative overflow-hidden group">
              {/* Background Decoration */}
              <div className="absolute top-0 right-0 w-64 h-64 bg-cyber-light-accent/5 dark:bg-ornex-green/5 blur-[100px] -mr-32 -mt-32 pointer-events-none" />
              
              <div className="relative space-y-6 md:space-y-8">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-200 dark:border-white/5 pb-6">
                  <div className="flex items-center gap-4">
                    <div className="p-3 bg-[#00C853]/10 dark:bg-ornex-green/20 rounded-2xl shrink-0">
                      <Zap className="w-5 h-5 text-[#00C853] dark:text-ornex-green" />
                    </div>
                    <div>
                      <h4 id="privacy-modal-title" className="text-base md:text-lg font-black uppercase tracking-tighter text-cyber-light-heading dark:text-white">
                        {scanMode === 'paste' ? 'Raw Source Analysis Guide' : 'EML File Upload Protocol'}
                      </h4>
                      <p className="text-[10px] md:text-[11px] font-mono uppercase tracking-widest text-zinc-500">Forensic Instructions • Level 1 Intelligence</p>
                    </div>
                  </div>
                  <div className="flex items-center self-start md:self-center gap-2 px-3 py-1 bg-zinc-100 dark:bg-white/5 rounded-full border border-zinc-200 dark:border-white/10">
                    <button
                      onClick={() => setShowGuide(false)}
                      aria-label="Close Privacy Modal"
                      className="p-1 hover:bg-zinc-200 dark:hover:bg-white/10 rounded-full transition-colors text-zinc-500"
                    >
                      <X className="w-4 h-4" />
                    </button>
                    <div className="w-1.5 h-1.5 rounded-full bg-cyber-light-accent dark:bg-ornex-green animate-pulse" />
                    <span className="text-[10px] md:text-[11px] font-bold text-zinc-500 dark:text-zinc-400 uppercase tracking-widest">Active Assistant</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
                  {scanMode === 'paste' ? (
                    <>
                      <div className="space-y-6">
                        <div className="space-y-4">
                          <div className="flex items-center gap-2 text-cyber-light-accent dark:text-ornex-green">
                            <Shield className="w-4 h-4" />
                            <span className="text-[11px] font-black uppercase tracking-[0.2em]">Why use Paste?</span>
                          </div>
                          <p className="text-xs text-zinc-600 dark:text-zinc-400 leading-relaxed">
                            This is the <span className="text-cyber-light-heading dark:text-white font-bold">Gold Standard</span>. It exposes hidden headers like <span className="font-mono text-[11px] text-cyber-light-heading dark:text-white/80">Return-Path</span> and <span className="font-mono text-[11px] text-cyber-light-heading dark:text-white/80">X-Originating-IP</span> that scammers can't hide.
                          </p>
                        </div>
                        <div className="p-4 rounded-2xl bg-[#FFFBEB] dark:bg-amber-500/5 border border-amber-200 dark:border-amber-500/10 text-[#92400E] dark:text-amber-500/80">
                          <div className="flex items-center gap-2 mb-1">
                            <AlertTriangle className="w-3.5 h-3.5" />
                            <span className="text-[11px] font-black uppercase tracking-widest">Security Note</span>
                          </div>
                          <p className="text-[11px] leading-tight font-medium opacity-90">Headers contain your email address. We process this locally and never store or share your forensic data.</p>
                        </div>
                      </div>
                      <div className="lg:col-span-2 space-y-4">
                        <div className="flex items-center gap-2 text-cyber-light-accent dark:text-ornex-green">
                          <Clipboard className="w-4 h-4" />
                          <span className="text-[11px] font-black uppercase tracking-[0.2em]">Quick Extraction (Select Your Client)</span>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-start">
                          {[
                            { name: 'Gmail', steps: ['Open Email', 'Click ⋮ (More)', 'Show original'] },
                            { name: 'Outlook', steps: ['Open Email', 'Click ... (More)', 'View message source'] },
                            { name: 'Apple Mail', steps: ['Menu: View', 'Message', 'Raw Source'] }
                          ].map((client) => (
                            <div key={client.name} className="p-4 rounded-2xl bg-zinc-100 dark:bg-white/5 border border-zinc-200 dark:border-white/5 hover:border-cyber-light-accent/30 dark:hover:border-ornex-green/30 transition-all group/card">
                              <span className="text-[11px] font-black text-cyber-light-heading dark:text-white uppercase tracking-widest block mb-3 border-b border-zinc-200 dark:border-white/5 pb-2">{client.name}</span>
                              <div className="space-y-2">
                                {client.steps.map((step, i) => (
                                  <div key={i} className="flex items-center gap-2 text-[11px] text-zinc-600 dark:text-zinc-500 font-medium">
                                    <span className="w-4 h-4 rounded-full bg-zinc-200 dark:bg-white/5 flex items-center justify-center text-[10px] font-black text-zinc-500 dark:text-zinc-400">{i+1}</span>
                                    {step}
                                  </div>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="space-y-4">
                        <div className="flex items-center gap-2 text-cyber-light-accent dark:text-ornex-green">
                          <FileUp className="w-4 h-4" />
                          <span className="text-[10px] font-black uppercase tracking-[0.2em]">EML Benefits</span>
                        </div>
                        <p className="text-xs text-zinc-600 dark:text-zinc-400 leading-relaxed">
                          EML files are <span className="text-cyber-light-heading dark:text-white font-bold">untampered forensic artifacts</span>. They preserve the exact structure of the email, including tracking pixels and multi-part MIME boundaries.
                        </p>
                      </div>
                      <div className="lg:col-span-2 space-y-4">
                        <div className="flex items-center gap-2 text-cyber-light-accent dark:text-ornex-green">
                          <ArrowRight className="w-4 h-4" />
                          <span className="text-[10px] font-black uppercase tracking-[0.2em]">How to export</span>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-start">
                          <div className="p-4 rounded-2xl bg-zinc-100 dark:bg-white/5 border border-zinc-200 dark:border-white/5 flex flex-col gap-3">
                            <div className="flex items-center gap-3">
                              <div className="p-2 bg-zinc-200 dark:bg-white/5 rounded-lg text-cyber-light-accent dark:text-ornex-green">
                                <Mail className="w-4 h-4" />
                              </div>
                              <span className="text-[11px] font-bold text-cyber-light-heading dark:text-white uppercase tracking-widest">Gmail Export</span>
                            </div>
                            <p className="text-[11px] text-zinc-600 dark:text-zinc-500 leading-relaxed">Open email - Click ⋮ (More) - Select <span className="font-bold text-cyber-light-heading dark:text-white">Download message</span> to save as .eml.</p>
                          </div>
                          <div className="p-4 rounded-2xl bg-zinc-100 dark:bg-white/5 border border-zinc-200 dark:border-white/5 flex flex-col gap-3">
                            <div className="flex items-center gap-3">
                              <div className="p-2 bg-zinc-200 dark:bg-white/5 rounded-lg text-zinc-500 dark:text-zinc-400">
                                <Layout className="w-4 h-4" />
                              </div>
                              <span className="text-[11px] font-bold text-cyber-light-heading dark:text-white uppercase tracking-widest">Desktop Clients</span>
                            </div>
                            <p className="text-[11px] text-zinc-600 dark:text-zinc-500 leading-relaxed">Simply drag the email from your inbox to your desktop. It will automatically create an <span className="font-bold text-cyber-light-heading dark:text-white">.eml</span> file.</p>
                          </div>
                          <div className="p-4 rounded-2xl bg-zinc-100 dark:bg-white/5 border border-zinc-200 dark:border-white/5 flex flex-col gap-3">
                            <div className="flex items-center gap-3">
                              <div className="p-2 bg-zinc-200 dark:bg-white/5 rounded-lg text-zinc-500 dark:text-zinc-400">
                                <ExternalLink className="w-4 h-4" />
                              </div>
                              <span className="text-[11px] font-bold text-cyber-light-heading dark:text-white uppercase tracking-widest">Manual Save</span>
                            </div>
                            <p className="text-[11px] text-zinc-600 dark:text-zinc-500 leading-relaxed">Go to <span className="font-bold text-cyber-light-heading dark:text-white">File - Save As</span> and select <span className="font-bold text-cyber-light-heading dark:text-white">Email Message (.eml)</span> from the dropdown.</p>
                          </div>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          {scanMode === 'paste' && (
            <div className="animate-fade-in space-y-2">
              <label className="text-[10px] font-mono uppercase tracking-widest text-zinc-500 ml-1">Raw Email (Headers + Body)</label>
              <textarea
                value={rawEmail}
                onChange={e => setRawEmail(e.target.value)}
                placeholder="Paste the full source content (including headers) from your email client..."
                rows={8}
                className="w-full bg-cyber-light-bg dark:bg-white/5 border border-zinc-200 dark:border-white/10 rounded-2xl px-4 py-4 text-xs md:text-sm font-mono focus:border-cyber-light-accent/50 dark:focus:border-ornex-green/50 outline-none transition-all resize-none md:rows-[12]"
              />
            </div>
          )}

          {scanMode === 'upload' && (
            <div 
              onClick={() => fileInputRef.current?.click()}
              className="animate-fade-in group cursor-pointer p-8 md:p-12 border-2 border-dashed border-zinc-200 dark:border-white/10 rounded-2xl md:rounded-3xl bg-zinc-50 dark:bg-white/5 hover:border-cyber-light-accent/40 dark:hover:border-ornex-green/40 transition-all flex flex-col items-center justify-center gap-4"
            >
              <input 
                type="file" 
                ref={fileInputRef} 
                onChange={handleFileChange} 
                accept=".eml" 
                className="hidden" 
              />
              <div className="p-4 md:p-5 rounded-2xl bg-cyber-light-accent/5 dark:bg-ornex-green/5 border border-cyber-light-accent/10 dark:border-ornex-green/10 group-hover:scale-110 transition-transform">
                <FileUp className="w-6 h-6 md:w-8 md:h-8 text-cyber-light-accent dark:text-ornex-green" />
              </div>
              <div className="text-center">
                <p className="text-xs md:text-sm font-bold text-cyber-light-heading dark:text-white uppercase tracking-widest mb-1">
                  {selectedFile ? selectedFile.name : 'Select .eml File'}
                </p>
                <p className="text-[10px] md:text-xs text-zinc-500 font-mono">
                  {selectedFile ? `${(selectedFile.size / 1024).toFixed(1)} KB` : 'Drag and drop or click to browse'}
                </p>
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className={`w-full py-3.5 md:py-4 rounded-xl md:rounded-full font-bold uppercase tracking-widest transition-all shadow-lg flex items-center justify-center gap-3
              ${loading 
                ? 'bg-zinc-200 dark:bg-white/10 text-zinc-400 cursor-wait' 
                : 'bg-cyber-light-accent dark:bg-gradient-to-r dark:from-[#00C853] dark:to-ornex-green text-white dark:text-ornex-black hover:shadow-[0_0_25px_rgba(0,200,83,0.4)] dark:hover:shadow-[0_0_25px_rgba(57,255,20,0.4)] hover:scale-[1.01] active:scale-[0.99]'
              }`}
          >
            <div className="relative flex items-center justify-center gap-3">
              {loading ? (
                <>
                  <div className="w-4 h-4 md:w-5 md:h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span className="text-xs md:text-sm">Analyzing Forensic Payload...</span>
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4 md:w-5 md:h-5" />
                  <div className="flex items-center gap-2">
                    <InfoTip title="Forensic Payload" content="We extract email headers, body text, and embedded links to scan for malicious indicators.">
                      <span className="text-xs md:text-sm">Analyze Forensic Payload</span>
                    </InfoTip>
                  </div>
                </>
              )}
            </div>
          </button>
        </form>

        {error && (
          <div className="mt-6 p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-500 text-sm flex items-center gap-3 font-mono">
            <AlertCircle className="w-5 h-5" />
            {error}
          </div>
        )}
      </div>

      {result && (
        <div id="email-results" className="animate-fade-in space-y-8 pb-12 scroll-mt-32">
          {/* Unified Forensic Command Center - Compact Overall Email Verdict */}
          {/* Unified Forensic Command Center - Compact Overall Email Verdict */}
          <div className={`p-5 sm:p-8 lg:p-10 rounded-2xl sm:rounded-[2rem] md:rounded-[2.5rem] border-2 shadow-2xl flex flex-col lg:flex-row items-center lg:items-stretch justify-between gap-8 animate-in zoom-in-95 duration-500 transition-all ${
            result.verdict_label === 'safe' ? 'bg-emerald-50/50 dark:bg-emerald-500/5 border-emerald-500/20 shadow-emerald-500/5' :
            result.verdict_label === 'suspicious' ? 'bg-amber-50/50 dark:bg-amber-500/5 border-amber-500/20 shadow-amber-500/5' :
            'bg-rose-50/50 dark:bg-rose-500/5 border-rose-500/20 shadow-rose-500/10'
          }`}>
          <div className="flex flex-col md:flex-row items-center md:items-start gap-6 md:gap-8 flex-1 w-full md:w-auto">
            <div className={`p-5 md:p-8 rounded-2xl md:rounded-[2rem] shadow-2xl border-4 shrink-0 transition-colors duration-500 ${
              result.verdict_label === 'safe' ? 'bg-emerald-500/10 dark:bg-emerald-500/10 border-emerald-500/20 dark:border-emerald-500/30 text-emerald-600 dark:text-emerald-500' :
              result.verdict_label === 'suspicious' ? 'bg-amber-500/10 dark:bg-amber-500/10 border-amber-500/20 dark:border-amber-500/30 text-amber-600 dark:text-amber-500' :
              'bg-rose-500/10 dark:bg-rose-500/10 border-rose-500/20 dark:border-rose-500/30 text-rose-600 dark:text-rose-500'
            }`}>
              {result.verdict_label === 'safe' ? <ShieldCheck className="w-8 h-8 md:w-10 md:h-10" /> :
               result.verdict_label === 'suspicious' ? <AlertTriangle className="w-8 h-8 md:w-10 md:h-10" /> :
               <ShieldX className="w-8 h-8 md:w-10 md:h-10" />}
            </div>
            
            <div className="space-y-4 text-center md:text-left flex-1 min-w-0 w-full">
              <div className="flex flex-wrap items-center justify-center md:justify-start gap-2">
                {/* Primary Action Pill */}
                {result.verdict_label === 'malicious' ? (
                  <div className="px-3 md:px-5 py-1.5 md:py-2 bg-rose-600 text-white rounded-full font-bold font-tektur text-[9px] md:text-[11px] uppercase tracking-[0.2em] shadow-lg shadow-rose-600/20 flex items-center gap-2 border border-rose-500 transition-all hover:scale-105 active:scale-95">
                    <ShieldX className="w-3 md:w-4 h-3 md:h-4" /> BLOCK EMAIL
                  </div>
                ) : (
                  <div className={`px-3 md:px-5 py-1.5 md:py-2 rounded-full font-bold font-tektur text-[9px] md:text-[11px] uppercase tracking-[0.2em] flex items-center gap-2 border transition-all hover:scale-105 active:scale-95 ${
                    result.verdict_label === 'suspicious'
                    ? 'bg-amber-500/10 border-amber-500/30 text-amber-600'
                    : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-400'
                  }`}>
                    { result.verdict_label === 'suspicious' ? <AlertTriangle className="w-3 md:w-4 h-3 md:h-4" /> : <ShieldCheck className="w-3 md:w-4 h-3 md:h-4" /> }
                    { result.verdict_label === 'suspicious' ? 'TRIAGE REQUIRED' : 'SECURE CONTENT' }
                  </div>
                )}
                
                {result.identity.is_safe_harbor && (
                  <div className="px-3 md:px-5 py-1.5 md:py-2 bg-blue-600/10 border border-blue-500/30 text-blue-600 dark:text-blue-400 rounded-full font-black text-[9px] md:text-[11px] uppercase tracking-widest flex items-center gap-2">
                    <ShieldCheck className="w-3 md:w-4 h-3 md:h-4" /> SAFE HARBOR
                  </div>
                )}

                {(result.identity.mismatches || []).map((m: string, i: number) => (
                  <span key={i} className="px-2 md:px-4 py-1 md:py-1.5 rounded-full bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-[8px] md:text-[10px] font-bold uppercase tracking-widest text-zinc-500 dark:text-zinc-400 whitespace-nowrap">
                    {m.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
              
              <div className="space-y-3">
                <p className="text-[9px] md:text-[11px] font-bold font-tektur uppercase tracking-[0.3em] text-zinc-500 dark:text-white/60">
                  Forensic Findings & Conclusion
                </p>
                <h1 className="text-xl sm:text-2xl md:text-4xl font-black font-tektur tracking-tight uppercase leading-[1.1] text-zinc-900 dark:text-white" title={result.identity.subject}>
                  {result.verdict_label === 'malicious' ? 'MALICIOUS THREAT DETECTED' : 
                   result.verdict_label === 'suspicious' ? 'SUSPICIOUS SCAN RESULT' : 
                   'SECURE SCAN RESULT'}
                </h1>
                <div className="flex items-center justify-center md:justify-start gap-2.5 opacity-70">
                  <Mail className="w-3.5 h-3.5 md:w-4 md:h-4 text-cyber-light-accent dark:text-ornex-green" />
                  <p className="text-[11px] md:text-[14px] font-mono font-bold text-zinc-600 dark:text-zinc-300 truncate max-w-xl tracking-tighter">
                    {result.identity.subject || 'No Subject Specified'}
                  </p>
                </div>
              </div>
              
              {/* Overall Email Intent Description */}
              {result.functional_description && (
                <div className="flex gap-3 md:gap-5 group/intent pt-2">
                  <div className="w-0.5 md:w-1 rounded-full bg-gradient-to-b from-cyber-light-accent/50 dark:from-ornex-green/50 to-transparent shrink-0" />
                  <div className="flex-1 text-left">
                    <p className="text-[13px] md:text-[16px] font-medium leading-relaxed text-zinc-600 dark:text-zinc-300 italic">
                      "{result.functional_description}"
                    </p>
                  </div>
                </div>
              )}

              <div className="p-4 md:p-6 rounded-2xl md:rounded-3xl bg-zinc-100/50 dark:bg-white/5 border border-zinc-200 dark:border-white/5 backdrop-blur-sm shadow-inner relative overflow-hidden group/tip">
                <div className="absolute top-0 left-0 w-1 h-full bg-cyber-light-accent dark:bg-ornex-green opacity-20" />
                <p className="text-[12px] md:text-[15px] font-semibold leading-relaxed text-zinc-700 dark:text-zinc-200 relative z-10">
                  {result.verdict_label === 'malicious'
                    ? 'Critical threat indicators identified. Automated recommendation: Immediate Block.' 
                    : result.verdict_label === 'suspicious'
                      ? 'Suspicious patterns detected. Exercise caution before interacting with links.'
                      : (result.identity.mismatches || []).length > 0
                        ? 'Technical forensic discrepancies found in mail headers. Verify sender authenticity.'
                        : 'No active threats or evasion tactics identified in this forensic session.'}
                </p>
              </div>

              {/* Score Breakdown - Tactical Transparency */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 md:gap-8 pt-6 border-t border-black/5 dark:border-white/5 mt-2 items-start">
                {[
                  { icon: Fingerprint, label: 'Identity', score: result.score_identity },
                  { icon: MessageSquare, label: 'Linguistic', score: result.score_linguistic },
                  { icon: Link2, label: 'Links', score: result.link_risk_score }
                ].map((item, i) => (
                  <div key={i} className="space-y-2 md:space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 opacity-80">
                        <item.icon className="w-3 h-3 md:w-4 md:h-4 text-zinc-500 dark:text-zinc-400" />
                        <span className="text-[9px] md:text-[11px] font-bold font-tektur uppercase tracking-[0.2em] md:tracking-[0.3em] text-zinc-500 dark:text-zinc-400">{item.label}</span>
                      </div>
                      <span className="text-[10px] md:text-[12px] font-mono font-black text-zinc-700 dark:text-white">{Math.round(item.score)}%</span>
                    </div>
                    <div className="w-full h-1 md:h-1.5 bg-zinc-200 dark:bg-white/5 rounded-full overflow-hidden shadow-inner">
                      <div 
                        className={`h-full transition-all duration-1000 shadow-[0_0_8px_rgba(0,0,0,0.1)] ${item.score >= 75 ? 'bg-rose-500 shadow-rose-500/20' : item.score >= 40 ? 'bg-amber-500 shadow-amber-500/20' : 'bg-emerald-500 shadow-emerald-500/20'}`}
                        style={{ width: `${Math.min(item.score, 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Centered Risk Gauge & Rescan - Tactical Command */}
          <div className="flex flex-col items-center justify-center shrink-0 pt-6 lg:pt-0 border-t lg:border-t-0 lg:border-l border-zinc-200 dark:border-white/10 lg:pl-10 gap-6 w-full lg:w-auto">
             <div className="w-24 h-24 md:w-32 md:h-32 flex items-center justify-center bg-white/5 rounded-full p-2 border border-white/5 shadow-2xl shrink-0">
                <RiskGauge 
                  score={result.final_risk_score ?? 0} 
                  level={result.verdict_label.toUpperCase() as any} 
                  size={window.innerWidth < 768 ? 90 : 120}
                />
             </div>
             
             <button 
                onClick={() => handleSubmit(undefined, true)}
                disabled={loading}
                className="flex items-center justify-center gap-2 w-full sm:w-auto px-5 py-2.5 bg-zinc-100 dark:bg-white/5 hover:bg-zinc-200 dark:hover:bg-white/10 border border-zinc-200 dark:border-white/10 rounded-xl transition-all text-[10px] font-black uppercase tracking-[0.2em] text-zinc-600 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-white shadow-sm"
             >
               {loading ? (
                 <div className="w-3.5 h-3.5 border-2 border-zinc-400 border-t-transparent rounded-full animate-spin" />
               ) : (
                 <RefreshCcw className="w-3.5 h-3.5" />
               )}
               {loading ? 'Analyzing...' : 'Rescan Payload'}
             </button>
          </div>
        </div>

          {/* Main Forensic Details Card */}
          <div className="p-5 md:p-10 bg-white dark:bg-zinc-900 rounded-2xl md:rounded-3xl border border-zinc-200 dark:border-white/10 shadow-2xl relative group">
            <div className="space-y-8 relative">
              {/* Triage Stats */}
              <div className="flex flex-wrap gap-3 items-center">
                  <InfoTip title="Total Links" content="Total unique raw links identified in the email body.">
                    <div className="flex items-center gap-2 px-3 py-1.5 bg-zinc-100 dark:bg-white/5 rounded-xl border border-zinc-200 dark:border-white/10">
                      <Zap className="w-3 h-3 text-cyber-light-accent dark:text-ornex-green" />
                      <span className="text-[9px] font-bold font-tektur uppercase tracking-[0.3em] text-zinc-500 dark:text-zinc-400">Total:</span>
                      <span className="text-xs font-bold text-cyber-light-heading dark:text-white">{result.triage_stats.total_found}</span>
                    </div>
                  </InfoTip>
                  <InfoTip title="Scanned Destinations" content="High-priority unique destinations subjected to full forensic analysis.">
                    <div className="flex items-center gap-2 px-3 py-1.5 bg-cyber-light-accent/5 dark:bg-ornex-green/5 rounded-xl border border-cyber-light-accent/10 dark:border-ornex-green/10 text-cyber-light-accent dark:text-ornex-green">
                      <Shield className="w-3 h-3" />
                      <span className="text-[9px] font-bold font-tektur uppercase tracking-[0.3em]">Scanned:</span>
                      <span className="text-xs font-bold">{result.triage_stats.analyzed}</span>
                    </div>
                  </InfoTip>
                {(result.triage_stats?.wrappers_unwrapped ?? 0) > 0 && (
                  <InfoTip title="Tracking Wrappers" content="Tracking URLs unwrapped to reveal and scan their true destinations.">
                    <div className="flex items-center gap-2 px-3 py-1.5 bg-purple-500/5 rounded-xl border border-purple-500/10 text-purple-400">
                      <ExternalLink size={12} />
                      <span className="text-[9px] font-bold font-tektur uppercase tracking-[0.3em]">Unwrapped:</span>
                      <span className="text-xs font-bold">{result.triage_stats?.wrappers_unwrapped}</span>
                    </div>
                  </InfoTip>
                )}
                 {(result.triage_stats?.pii_scrubbed ?? 0) > 0 && (
                  <InfoTip title="Identity Protection" content="Personal data (such as your email address) was securely removed from these links prior to analysis to ensure your privacy.">
                    <button 
                      onClick={onShowPrivacy}
                      aria-label={`Show privacy details: ${result.triage_stats?.pii_scrubbed} PII items scrubbed`}
                      className="flex items-center gap-2 px-3 py-1.5 bg-blue-500/5 rounded-xl border border-blue-500/10 text-blue-400 hover:bg-blue-500/10 transition-all hover:scale-105 active:scale-95 group relative overflow-hidden"
                    >
                      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-blue-400/10 to-transparent -translate-x-full group-hover:animate-shimmer" />
                      <ShieldAlert size={12} className="group-hover:animate-digital-pulse" />
                      <span className="text-[9px] font-bold font-tektur uppercase tracking-[0.3em]">Privacy Protected:</span>
                      <span className="text-xs font-bold">{result.triage_stats?.pii_scrubbed}</span>
                    </button>
                  </InfoTip>
                )}
                  <InfoTip title="Skipped Assets" content="Redundant or known-safe links (like WhatsApp/socials) skipped to save quota.">
                    <div className="flex items-center gap-2 px-3 py-1.5 bg-zinc-100 dark:bg-white/5 rounded-xl border border-zinc-200 dark:border-white/10 opacity-60">
                      <CheckCircle2 className="w-3 h-3 text-zinc-400" />
                      <span className="text-[9px] font-bold font-tektur uppercase tracking-[0.3em] text-zinc-500 dark:text-zinc-400">Skipped:</span>
                      <span className="text-xs font-bold text-zinc-600 dark:text-zinc-400">{(result.triage_stats.total_found ?? 0) - (result.triage_stats.analyzed ?? 0)}</span>
                    </div>
                  </InfoTip>
              </div>

              {/* Forensic Warnings */}
              {result.forensic_errors && result.forensic_errors.length > 0 && (
                <div className="p-4 rounded-2xl border border-amber-300/50 dark:border-amber-500/20 bg-amber-50/80 dark:bg-amber-500/5 flex items-center gap-4 transition-all duration-300">
                  <AlertTriangle className="w-5 h-5 text-amber-600 dark:text-amber-500 flex-shrink-0" />
                  <div>
                    <p className="text-[10px] font-bold font-tektur uppercase tracking-[0.3em] text-amber-700 dark:text-amber-400 mb-0.5">
                      Partial Analysis
                    </p>
                    <p className="text-[11.5px] text-amber-800/70 dark:text-amber-500/80 font-semibold leading-tight">
                      Some checks failed ({[...new Set(result.forensic_errors.map(e => e.engine))].join(', ')}). 
                      Displaying available forensic markers.
                    </p>
                  </div>
                </div>
              )}

              {/* Auth Signals */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 items-start">
                {[
                  { key: 'spf', title: 'SPF (Sender Policy Framework)', content: 'A DNS record that specifies which mail servers are authorized to send email on behalf of your domain.' },
                  { key: 'dkim', title: 'DKIM (DomainKeys Identified Mail)', content: 'A cryptographic signature that ensures the email content was not tampered with and truly originated from the domain.' },
                  { key: 'dmarc', title: 'DMARC Policy', content: 'A protocol that uses SPF and DKIM to tell receiving servers how to handle emails that fail authentication.' }
                ].map(({ key, title, content }) => (
                  <InfoTip key={key} title={title} content={content} className="w-full relative flex items-center">
                    <div className={`flex items-center justify-between p-3.5 rounded-2xl border w-full transition-all duration-300 ${getAuthColor(result.auth?.[key as keyof typeof result.auth] as string || 'none')}`}>
                      <span className="text-[10px] font-bold font-tektur uppercase tracking-[0.3em]">{key}</span>
                      <span className="text-[10px] font-bold font-tektur uppercase opacity-80">{result.auth?.[key as keyof typeof result.auth] as string || 'none'}</span>
                    </div>
                  </InfoTip>
                ))}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-stretch">
                {/* Detection Reasons */}
                <div className="glass-panel p-6 rounded-3xl dark:bg-zinc-900/20 border-zinc-200 dark:border-white/10 space-y-4 flex flex-col h-full">
                  <h4 className="text-[10px] font-bold font-tektur uppercase tracking-[0.3em] text-zinc-500 dark:text-zinc-400 flex items-center gap-2 mb-6">
                    <AlertCircle className="w-4 h-4 opacity-70" />
                    Forensic Detection Logs
                  </h4>
                  <ul className="space-y-3">
                    {(result.reasons || []).map((reason: string, idx: number) => (
                      <li key={idx} className="flex items-start gap-3 text-sm text-cyber-light-text dark:text-zinc-300">
                        <ArrowRight className="w-4 h-4 text-cyber-light-accent dark:text-ornex-green mt-0.5 flex-shrink-0" />
                        <span className="leading-relaxed">{reason}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="glass-panel p-6 rounded-3xl dark:bg-zinc-900/20 border-zinc-200 dark:border-white/10 space-y-4 flex flex-col h-full">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                    <h4 className="text-[10px] font-bold font-tektur uppercase tracking-[0.3em] text-zinc-500 dark:text-zinc-400 flex items-center gap-2">
                      <Layout className="w-4 h-4 opacity-70" />
                      Analyzed Link Profile
                    </h4>
                    <div className="relative w-full sm:w-auto" ref={sortDropdownRef}>
                      <button 
                        onClick={() => setSortDropdownOpen(!sortDropdownOpen)}
                        className="flex items-center justify-between w-full sm:w-44 gap-2 bg-zinc-100 dark:bg-zinc-800/50 border border-zinc-200 dark:border-white/10 text-zinc-600 dark:text-zinc-300 text-[10px] uppercase font-bold tracking-widest rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-cyber-light-accent dark:focus:ring-ornex-green cursor-pointer transition-colors hover:bg-zinc-200 dark:hover:bg-zinc-800"
                      >
                        <span>{linkSort === 'risk-desc' ? 'Risk: High to Low' : 'Risk: Low to High'}</span>
                        <ChevronDown className={`w-3.5 h-3.5 text-zinc-400 transition-transform ${sortDropdownOpen ? 'rotate-180' : ''}`} />
                      </button>
                      
                      {sortDropdownOpen && (
                        <div className="absolute right-0 top-full mt-2 w-full sm:w-44 bg-white dark:bg-[#1a1a1a] border border-zinc-200 dark:border-white/10 rounded-xl shadow-xl overflow-hidden z-50 animate-in fade-in slide-in-from-top-2 duration-200">
                          <button
                            onClick={() => { setLinkSort('risk-desc'); setSortDropdownOpen(false); }}
                            className={`w-full text-left px-4 py-2.5 text-[10px] font-bold uppercase tracking-widest transition-colors ${linkSort === 'risk-desc' ? 'bg-cyber-light-accent/10 dark:bg-ornex-green/10 text-cyber-light-accent dark:text-ornex-green' : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-white/5'}`}
                          >
                            Risk: High to Low
                          </button>
                          <button
                            onClick={() => { setLinkSort('risk-asc'); setSortDropdownOpen(false); }}
                            className={`w-full text-left px-4 py-2.5 text-[10px] font-bold uppercase tracking-widest transition-colors ${linkSort === 'risk-asc' ? 'bg-cyber-light-accent/10 dark:bg-ornex-green/10 text-cyber-light-accent dark:text-ornex-green' : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-white/5'}`}
                          >
                            Risk: Low to High
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="space-y-3 max-h-[300px] overflow-y-auto pr-2 custom-scrollbar">
                    {result.link_results.length > 0 ? (
                      [...result.link_results].sort((a, b) => {
                        if (linkSort === 'risk-desc') return b.risk_score - a.risk_score;
                        return a.risk_score - b.risk_score;
                      }).map((link, idx) => {
                        const unwrapEvent = result.unwrap_events?.find((e: any) => e.destination_url === link.url);
                        const isExpanded = expandedUrls[link.url];
                        
                        return (
                          <div 
                            key={idx} 
                            onClick={() => setExpandedUrls({ ...expandedUrls, [link.url]: !isExpanded })}
                            className={`group cursor-pointer p-4 rounded-2xl border transition-all duration-300 ${
                              isExpanded 
                                ? 'bg-cyber-light-accent/5 dark:bg-white/5 border-cyber-light-accent/30 dark:border-white/20' 
                                : 'bg-zinc-50 dark:bg-white/[0.02] border-zinc-100 dark:border-white/5 hover:border-zinc-300 dark:hover:border-white/10'
                            }`}
                          >
                            <div className="flex items-start justify-between gap-4">
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 mb-1 min-w-0">
                                  <div className="p-1.5 rounded-lg bg-zinc-200 dark:bg-white/5 text-zinc-500 shrink-0">
                                    <Link2 className="w-3.5 h-3.5" />
                                  </div>
                                  <div className="flex items-center gap-2 min-w-0 flex-1">
                                    <div className="min-w-0 flex-1 flex items-center font-mono text-xs">
                                      {formatUrl(link.url)}
                                    </div>
                                    <button 
                                      onClick={(e) => copyToClipboard(link.url, e)} 
                                      className="p-1.5 hover:bg-zinc-200 dark:hover:bg-white/10 rounded-lg transition-colors group/copy shrink-0"
                                      title="Copy Clean URL"
                                    >
                                      <Copy size={11} className="text-zinc-400 group-hover/copy:text-cyber-light-accent dark:group-hover/copy:text-ornex-green" />
                                    </button>
                                  </div>
                                  {unwrapEvent && (
                                    <span className="px-1.5 py-0.5 rounded bg-purple-500/10 text-[9px] font-black text-purple-400 border border-purple-500/20 uppercase tracking-widest shrink-0 ml-1">
                                      UNWRAPPED
                                    </span>
                                  )}
                                  {link.risk_level === 'INCONCLUSIVE' && (
                                    <span className="px-1.5 py-0.5 rounded bg-zinc-500/10 text-[9px] font-black text-zinc-500 border border-zinc-500/20 uppercase tracking-widest shrink-0 ml-1">
                                      INCONCLUSIVE
                                    </span>
                                  )}
                                </div>

                                {unwrapEvent && (
                                  <div className="flex items-center gap-2 mt-2 ml-1 text-[10px] text-zinc-500 font-medium">
                                    <ArrowRight className="w-3 h-3 opacity-30" />
                                    <span className="opacity-40 uppercase tracking-tighter">Source:</span>
                                    <span className="truncate opacity-60 font-mono italic max-w-[200px]" title={unwrapEvent.found_url}>
                                      {unwrapEvent.found_url}
                                    </span>
                                  </div>
                                )}
                              </div>

                              <div className="flex items-center gap-3 shrink-0 mt-1">
                                <div className={`px-2 py-0.5 rounded-lg text-[10px] font-black uppercase tracking-widest border ${getRiskColor(link.risk_level)}`}>
                                  {link.risk_level}
                                </div>
                                <ChevronDown className={`w-4 h-4 text-zinc-400 transition-transform duration-300 ${isExpanded ? 'rotate-180' : ''}`} />
                              </div>
                            </div>

                            {/* Expanded Details - Quick Forensic Summary */}
                            {isExpanded && (
                              <div className="mt-4 pt-4 border-t border-zinc-200 dark:border-white/5 animate-in slide-in-from-top-2 duration-200">
                                <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed italic">
                                  {link.explanation || "No deep-dive explanation available for this asset."}
                                </p>
                              </div>
                            )}
                          </div>
                        );
                      })
                    ) : (
                      <div className="flex flex-col items-center justify-center py-10 text-center space-y-4">
                        <div className="p-4 bg-zinc-100 dark:bg-white/5 rounded-3xl border border-zinc-200 dark:border-white/10">
                          <Shield className="w-8 h-8 text-zinc-400 opacity-50" />
                        </div>
                        <div className="space-y-1">
                          <p className="text-xs font-black uppercase tracking-[0.2em] text-zinc-500">No Forensic Links Identified</p>
                          <p className="text-[11px] text-zinc-500 max-w-[280px] leading-relaxed mx-auto">
                            All extracted URLs ({result.triage_stats.total_found}) were identified as low-risk assets (CSS, Images, Tracking Pixels) and skipped to optimize forensic efficiency.
                          </p>
                        </div>
                        <div className="pt-2">
                           <div className="px-4 py-1.5 rounded-full bg-emerald-500/5 border border-emerald-500/10 text-[10px] font-bold text-emerald-500 uppercase tracking-widest">
                             Safe Baseline Confirmed
                           </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Advanced Forensic Insights (Forensics++) */}
              <EmailForensicInsight result={result} />

              {/* Expanded Deep Dives */}
              <div className="space-y-8 pt-4">
                {result.link_results.map((link, idx) => expandedUrls[link.url] && (
                  <div key={idx} className="animate-slide-down relative glass-panel rounded-3xl border border-zinc-200 dark:border-white/10 bg-zinc-50/80 dark:bg-zinc-900/40 shadow-xl overflow-hidden group/dive">
                    
                    {/* Top gradient bar based on risk */}
                    <div className={`absolute top-0 left-0 right-0 h-1.5 ${
                      link.risk_level?.toLowerCase() === 'high' ? 'bg-rose-500' :
                      link.risk_level?.toLowerCase() === 'medium' ? 'bg-amber-500' :
                      link.risk_level?.toLowerCase() === 'low' ? 'bg-emerald-500' : 'bg-zinc-500'
                    }`} />
                    
                    <div className="p-6 md:p-8">
                      {/* Deep Dive Header */}
                      <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 mb-8 pb-6 border-b border-zinc-200 dark:border-white/10">
                        <div className="flex flex-col gap-3 flex-1 min-w-0">
                          <div className="flex items-center gap-4">
                            <span className="text-[10px] font-bold font-tektur uppercase tracking-[0.3em] text-zinc-600 dark:text-zinc-500 bg-zinc-200/50 dark:bg-white/5 px-3 py-1.5 rounded-lg border border-zinc-300/50 dark:border-white/10 shrink-0">
                              Scan #{idx + 1}
                            </span>
                            <span className="text-[15px] font-bold text-cyber-light-heading dark:text-white uppercase tracking-tight truncate">
                              {link.verdictTitle || (() => {
                                const mapped = mapToAnalysisResult(link);
                                const flags = [];
                                if (mapped.threat_intel?.is_known_malicious) flags.push("Threat Intel Match");
                                if (mapped.visual_forensics?.brand_match) flags.push("Visual Brand Match");
                                else if (link.brand_impersonation) flags.push("Deceptive Phishing Lure");
                                if (mapped.agentReport?.activeProbing?.acceptedFakeCredentials) flags.push("Credential Harvester");
                                else if (mapped.agentReport?.activeProbing?.loginFormFound) flags.push("Suspicious Login Form");
                                if (mapped.whois_info?.is_new_domain) flags.push("New Domain");
                                if (mapped.whois_info?.has_privacy) flags.push("Hidden WHOIS");
                                
                                if (flags.length > 0) return flags.join(" • ");
                                
                                const level = link.risk_level?.toLowerCase();
                                if (level === 'high' || level === 'malicious') return "Multiple High-Risk Indicators";
                                if (level === 'medium' || level === 'suspicious') return "Suspicious Heuristics Detected";
                                if (level === 'low' || level === 'safe') return "Safe Baseline Confirmed";
                                return "Analysis Inconclusive";
                              })()}
                            </span>
                            {link.functional_category && (
                              <span className="px-2 py-0.5 rounded-md bg-cyber-light-accent/10 dark:bg-ornex-green/10 text-[9px] font-black text-cyber-light-accent dark:text-ornex-green border border-cyber-light-accent/20 dark:border-ornex-green/20 uppercase tracking-widest">
                                {link.functional_category}
                              </span>
                            )}
                          </div>
                          <span className="text-sm font-mono text-zinc-500 dark:text-zinc-400 truncate" title={link.url}>
                            {link.url}
                          </span>
                          {link.explanation && (
                            <p className="text-xs text-zinc-500 dark:text-zinc-400 leading-relaxed pr-8 border-l-2 border-zinc-200 dark:border-white/10 pl-3 mt-1">
                              {link.explanation.split('\n')[0]} {/* Show just the first paragraph/line of explanation */}
                            </p>
                          )}
                        </div>
                        
                        <div className="flex flex-col items-end gap-3 shrink-0 pt-1">
                          <div className="flex items-center gap-3">
                            <span className="text-[10px] font-black uppercase tracking-widest text-zinc-400">Verdict:</span>
                            <div className={`px-3 py-1.5 rounded-lg text-[11px] font-black uppercase tracking-widest border ${
                              (() => {
                                const l = link.risk_level?.toLowerCase();
                                if (l === 'high' || l === 'malicious') return 'bg-rose-500/10 border-rose-500/20 text-rose-600';
                                if (l === 'medium' || l === 'suspicious') return 'bg-amber-500/10 border-amber-500/20 text-amber-600';
                                if (l === 'low' || l === 'safe') return 'bg-emerald-500/10 border-emerald-500/20 text-emerald-600';
                                return 'bg-zinc-500/10 border-zinc-500/20 text-zinc-600';
                              })()
                            } shadow-sm`}>
                              {link.risk_level}
                            </div>
                          </div>
                          
                          {/* Integrated Action Button */}
                          {link.risk_level?.toLowerCase() === 'malicious' || link.risk_level?.toLowerCase() === 'high' ? (
                            <div className="px-4 py-2 bg-rose-600 text-white rounded-xl font-bold font-tektur text-[10px] uppercase tracking-[0.2em] animate-pulse shadow-lg shadow-rose-600/20 flex items-center gap-2">
                              <ShieldX className="w-3 h-3" /> BLOCK LINK
                            </div>
                          ) : (
                            <div className="px-4 py-2 bg-emerald-600/10 dark:bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 dark:text-emerald-400 rounded-xl font-bold font-tektur text-[10px] uppercase tracking-[0.2em] flex items-center gap-2 transition-all duration-300">
                              <ShieldCheck className="w-3 h-3" /> SECURE CONTENT
                            </div>
                          )}
                        </div>
                      </div>
                      
                      
                      {/* Detailed Purpose Description */}
                      {link.functional_description && (
                        <div className="mb-8 flex gap-5 group/purpose">
                          <div className="w-1.5 rounded-full bg-gradient-to-b from-purple-500/50 to-transparent shrink-0" />
                          <div className="flex-1 text-left">
                            <p className="text-[15px] font-medium leading-relaxed text-zinc-600 dark:text-zinc-300 italic">
                              "{link.functional_description}"
                            </p>
                          </div>
                        </div>
                      )}
                      
                      {/* Forensic Details */}
                      <ResultDetails result={mapToAnalysisResult(link)} hideHeader={true} />
                    </div>
                  </div>
                ))}
              </div>

            </div>
          </div>
        </div>
      )}
    </div>
  );
}
