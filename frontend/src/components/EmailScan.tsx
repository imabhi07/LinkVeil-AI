import { useState, useRef, useEffect } from 'react';
import { Mail, Shield, AlertCircle, ChevronDown, AlertTriangle, FileUp, Clipboard, Layout, ArrowRight, Info, CheckCircle2, Zap, Copy, ExternalLink, ShieldAlert } from 'lucide-react';
import type { EmailScanRequest, EmailScanResponse, AnalysisResult } from '../types';
import { ResultDetails } from './ResultDetails';
import { InfoTip } from './InfoTip';

interface EmailScanProps {
  onResult?: (result: EmailScanResponse) => void;
  mapToAnalysisResult: (raw: any) => AnalysisResult;
  initialResult?: EmailScanResponse | null;
}

type ScanMode = 'manual' | 'paste' | 'upload';

export function EmailScan({ mapToAnalysisResult, onResult, initialResult }: EmailScanProps) {
  const [scanMode, setScanMode] = useState<ScanMode>('manual');
  const [formData, setFormData] = useState<EmailScanRequest>({
    from_name: '',
    from_email: '',
    reply_to: '',
    subject: '',
    body: ''
  });
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
      
      // Auto-expand the deep dive target if provided
      if (initialResult.deep_dive_target) {
        setExpandedUrls({ [initialResult.deep_dive_target]: true });
      } else if (initialResult.link_results && initialResult.link_results.length > 0) {
        // Fallback to highest risk link
        const topLink = [...initialResult.link_results].sort((a, b) => b.risk_score - a.risk_score)[0];
        setExpandedUrls({ [topLink.url]: true });
      }
    }
  }, [initialResult]);
  
  const [expandedUrls, setExpandedUrls] = useState<Record<string, boolean>>({});
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Validation
    if (scanMode === 'manual' && !formData.body?.trim()) {
      setError("Email body is required for manual analysis.");
      return;
    }
    if (scanMode === 'paste' && !rawEmail.trim()) {
      setError("Please paste the raw email content.");
      return;
    }
    if (scanMode === 'upload' && !selectedFile) {
      setError("Please select a .eml file to upload.");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
      let response;

      if (scanMode === 'upload' && selectedFile) {
        const uploadData = new FormData();
        uploadData.append('file', selectedFile);
        response = await fetch(`${API_BASE_URL}/api/v1/scan/eml`, {
          method: 'POST',
          body: uploadData,
        });
      } else {
        const payload: EmailScanRequest = scanMode === 'paste' 
          ? { raw_email: rawEmail }
          : formData;
          
        response = await fetch(`${API_BASE_URL}/api/v1/scan/email`, {
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
      onResult?.(data);

      // Auto-expand the link with the highest risk score
      if (data.link_results && data.link_results.length > 0) {
        const topLink = [...data.link_results].sort((a, b) => b.risk_score - a.risk_score)[0];
        setExpandedUrls({ [topLink.url]: true });
      }
    } catch (err: any) {
      setError(err.message || "An error occurred during email analysis.");
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'high': return 'text-rose-500 bg-rose-500/10 border-rose-500/20';
      case 'medium': return 'text-amber-500 bg-amber-500/10 border-amber-500/20';
      case 'low': return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20 dark:text-ornex-green';
      case 'inconclusive': return 'text-zinc-500 bg-zinc-500/10 border-zinc-500/20';
      default: return 'text-zinc-500 bg-zinc-500/10 border-zinc-500/20';
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
        <span className="flex items-center gap-1">
          <span className="text-cyber-light-heading dark:text-white font-bold">{parsed.hostname}</span>
          <span className="text-zinc-500 font-normal">{path}</span>
        </span>
      );
    } catch {
      return url.length > 40 ? url.substring(0, 25) + '...' + url.substring(url.length - 10) : url;
    }
  };

  return (
    <div className="space-y-8 animate-fade-in">
      <div className="glass-panel p-8 rounded-3xl dark:bg-black/40 border-zinc-200 dark:border-white/10 shadow-xl shadow-black/5">
        <div className="flex flex-col md:flex-row justify-between items-center gap-6 mb-10">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-cyber-light-accent/10 dark:bg-ornex-green/10 rounded-2xl border border-cyber-light-accent/20 dark:border-ornex-green/20">
              <Mail className="w-6 h-6 text-cyber-light-accent dark:text-ornex-green" />
            </div>
            <div className="space-y-1">
              <h2 className="text-2xl font-bold text-cyber-light-heading dark:text-white uppercase tracking-tight leading-none">Email Forensic Scan</h2>
              <p className="text-[11px] text-cyber-light-text dark:text-zinc-400 font-mono opacity-70">Detect phishing artifacts and malicious links</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowGuide(!showGuide)}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all border
                ${showGuide 
                  ? 'bg-cyber-light-accent/10 border-cyber-light-accent/30 text-cyber-light-accent dark:bg-ornex-green/10 dark:border-ornex-green/30 dark:text-ornex-green' 
                  : 'bg-zinc-100 dark:bg-white/5 border-zinc-200 dark:border-white/10 text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'
                }`}
            >
              <Info className="w-3.5 h-3.5" />
              {showGuide ? 'Hide Guide' : 'How to Scan'}
            </button>
          </div>

          <div className="flex p-1 bg-zinc-100 dark:bg-white/5 rounded-xl border border-zinc-200 dark:border-white/10 w-full md:w-auto relative">
            { [
              { id: 'manual', icon: Layout, label: 'Manual', tip: 'Best for quick analysis of plain text subject/body.' },
              { id: 'paste', icon: Clipboard, label: 'Paste', tip: 'Highest accuracy; parses full email headers + body.' },
              { id: 'upload', icon: FileUp, label: 'Upload', tip: 'Most secure; upload an authentic .eml file directly.' }
            ].map((tab) => (
              <InfoTip 
                key={tab.id} 
                title={tab.label + " Mode"} 
                content={tab.tip}
                placement="bottom"
                className={`flex-1 md:flex-none flex items-center relative`}
              >
                <button
                  type="button"
                  onClick={() => setScanMode(tab.id as any)}
                  className={`w-full flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-widest transition-all ${scanMode === tab.id ? 'bg-white dark:bg-white/10 shadow-sm text-cyber-light-accent dark:text-ornex-green' : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'}`}
                >
                  <tab.icon className="w-3.5 h-3.5" />
                  {tab.label}
                </button>
              </InfoTip>
            ))}
          </div>
        </div>

        {showGuide && (
          <div className="mb-8 space-y-6 animate-slide-down">
            <div className="p-8 rounded-[2rem] bg-zinc-50 dark:bg-black/40 border border-[#00C853]/20 dark:border-ornex-green/20 backdrop-blur-xl shadow-2xl relative overflow-hidden group">
              {/* Background Decoration */}
              <div className="absolute top-0 right-0 w-64 h-64 bg-cyber-light-accent/5 dark:bg-ornex-green/5 blur-[100px] -mr-32 -mt-32 pointer-events-none" />
              
              <div className="relative space-y-8">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/5 pb-6">
                  <div className="flex items-center gap-4">
                    <div className="p-3 bg-[#00C853]/10 dark:bg-ornex-green/20 rounded-2xl">
                      <Zap className="w-5 h-5 text-[#00C853] dark:text-ornex-green" />
                    </div>
                    <div>
                      <h4 className="text-lg font-black uppercase tracking-tighter text-cyber-light-heading dark:text-white">
                        {scanMode === 'manual' ? 'Manual Entry Protocol' : scanMode === 'paste' ? 'Raw Source Analysis Guide' : 'EML File Upload Protocol'}
                      </h4>
                      <p className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">Forensic Instructions • Level 1 Intelligence</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 px-3 py-1 bg-white/5 rounded-full border border-white/10">
                    <div className="w-1.5 h-1.5 rounded-full bg-cyber-light-accent dark:bg-ornex-green animate-pulse" />
                    <span className="text-[9px] font-bold text-zinc-400 uppercase tracking-widest">Active Assistant</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                  {scanMode === 'manual' ? (
                    <>
                      <div className="space-y-4">
                        <div className="flex items-center gap-2 text-cyber-light-accent dark:text-ornex-green">
                          <Layout className="w-4 h-4" />
                          <span className="text-[10px] font-black uppercase tracking-[0.2em]">Context</span>
                        </div>
                        <p className="text-xs text-zinc-400 leading-relaxed font-medium">
                          Use this when you only have the visible message content. Our AI uses <span className="text-white">NLP (Natural Language Processing)</span> to detect urgency, threat patterns, and deceptive tone.
                        </p>
                      </div>
                      <div className="lg:col-span-2 space-y-4">
                        <div className="flex items-center gap-2 text-cyber-light-accent dark:text-ornex-green">
                          <CheckCircle2 className="w-4 h-4" />
                          <span className="text-[10px] font-black uppercase tracking-[0.2em]">Best Practice</span>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="p-4 rounded-2xl bg-white/5 border border-white/5 hover:border-white/10 transition-colors">
                            <span className="text-[9px] font-bold text-zinc-500 uppercase block mb-1">Body Intelligence</span>
                            <p className="text-[11px] text-zinc-300">Paste the <span className="font-bold text-white">full body</span>. Don't remove links - we need them to scan the final destination for malware.</p>
                          </div>
                          <div className="p-4 rounded-2xl bg-white/5 border border-white/5 hover:border-white/10 transition-colors">
                            <span className="text-[9px] font-bold text-zinc-500 uppercase block mb-1">Impersonation Check</span>
                            <p className="text-[11px] text-zinc-300">Providing the <span className="font-bold text-white">From Email</span> allows us to cross-reference known official brand domains.</p>
                          </div>
                        </div>
                      </div>
                    </>
                  ) : scanMode === 'paste' ? (
                    <>
                      <div className="space-y-6">
                        <div className="space-y-4">
                          <div className="flex items-center gap-2 text-cyber-light-accent dark:text-ornex-green">
                            <Shield className="w-4 h-4" />
                            <span className="text-[10px] font-black uppercase tracking-[0.2em]">Why use Paste?</span>
                          </div>
                          <p className="text-xs text-zinc-400 leading-relaxed">
                            This is the <span className="text-white font-bold">Gold Standard</span>. It exposes hidden headers like <span className="font-mono text-[10px]">Return-Path</span> and <span className="font-mono text-[10px]">X-Originating-IP</span> that scammers can't hide.
                          </p>
                        </div>
                        <div className="p-4 rounded-2xl bg-amber-500/5 border border-amber-500/10 text-amber-500/80">
                          <div className="flex items-center gap-2 mb-1">
                            <AlertTriangle className="w-3.5 h-3.5" />
                            <span className="text-[10px] font-black uppercase tracking-widest">Security Note</span>
                          </div>
                          <p className="text-[10px] leading-tight opacity-80">Headers contain your email address. We process this locally and never store or share your forensic data.</p>
                        </div>
                      </div>
                      <div className="lg:col-span-2 space-y-4">
                        <div className="flex items-center gap-2 text-cyber-light-accent dark:text-ornex-green">
                          <Clipboard className="w-4 h-4" />
                          <span className="text-[10px] font-black uppercase tracking-[0.2em]">Quick Extraction (Select Your Client)</span>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          {[
                            { name: 'Gmail', steps: ['Open Email', 'Click ⋮ (More)', 'Show original'] },
                            { name: 'Outlook', steps: ['Open Email', 'Click ... (More)', 'View message source'] },
                            { name: 'Apple Mail', steps: ['Menu: View', 'Message', 'Raw Source'] }
                          ].map((client) => (
                            <div key={client.name} className="p-4 rounded-2xl bg-white/5 border border-white/5 hover:border-cyber-light-accent/30 dark:hover:border-ornex-green/30 transition-all group/card">
                              <span className="text-[10px] font-black text-white uppercase tracking-widest block mb-3 border-b border-white/5 pb-2">{client.name}</span>
                              <div className="space-y-2">
                                {client.steps.map((step, i) => (
                                  <div key={i} className="flex items-center gap-2 text-[10px] text-zinc-500">
                                    <span className="w-4 h-4 rounded-full bg-white/5 flex items-center justify-center text-[8px] font-black text-zinc-400">{i+1}</span>
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
                        <p className="text-xs text-zinc-400 leading-relaxed">
                          EML files are <span className="text-white">untampered forensic artifacts</span>. They preserve the exact structure of the email, including tracking pixels and multi-part MIME boundaries.
                        </p>
                      </div>
                      <div className="lg:col-span-2 space-y-4">
                        <div className="flex items-center gap-2 text-cyber-light-accent dark:text-ornex-green">
                          <ArrowRight className="w-4 h-4" />
                          <span className="text-[10px] font-black uppercase tracking-[0.2em]">How to export</span>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <div className="p-4 rounded-2xl bg-white/5 border border-white/5 flex flex-col gap-3">
                            <div className="flex items-center gap-3">
                              <div className="p-2 bg-white/5 rounded-lg text-cyber-light-accent dark:text-ornex-green">
                                <Mail className="w-4 h-4" />
                              </div>
                              <span className="text-[10px] font-bold text-white uppercase tracking-widest">Gmail Export</span>
                            </div>
                            <p className="text-[11px] text-zinc-500 leading-relaxed">Open email - Click ⋮ (More) - Select <span className="font-bold text-white">Download message</span> to save as .eml.</p>
                          </div>
                          <div className="p-4 rounded-2xl bg-white/5 border border-white/5 flex flex-col gap-3">
                            <div className="flex items-center gap-3">
                              <div className="p-2 bg-white/5 rounded-lg text-zinc-400">
                                <Layout className="w-4 h-4" />
                              </div>
                              <span className="text-[10px] font-bold text-white uppercase tracking-widest">Desktop Clients</span>
                            </div>
                            <p className="text-[11px] text-zinc-500 leading-relaxed">Simply drag the email from your inbox to your desktop. It will automatically create an <span className="font-bold text-white">.eml</span> file.</p>
                          </div>
                          <div className="p-4 rounded-2xl bg-white/5 border border-white/5 flex flex-col gap-3">
                            <div className="flex items-center gap-3">
                              <div className="p-2 bg-white/5 rounded-lg text-zinc-400">
                                <ExternalLink className="w-4 h-4" />
                              </div>
                              <span className="text-[10px] font-bold text-white uppercase tracking-widest">Manual Save</span>
                            </div>
                            <p className="text-[11px] text-zinc-500 leading-relaxed">Go to <span className="font-bold text-white">File - Save As</span> and select <span className="font-bold text-white">Email Message (.eml)</span> from the dropdown.</p>
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
          {scanMode === 'manual' && (
            <div className="animate-fade-in space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <label className="text-xs font-mono uppercase tracking-widest text-zinc-500 ml-1">From Name</label>
                  <input
                    type="text"
                    value={formData.from_name}
                    onChange={e => setFormData({ ...formData, from_name: e.target.value })}
                    placeholder="e.g. PayPal Support"
                    className="w-full bg-cyber-light-bg dark:bg-white/5 border border-zinc-200 dark:border-white/10 rounded-xl px-4 py-3 text-sm focus:border-cyber-light-accent/50 dark:focus:border-ornex-green/50 outline-none transition-all font-mono"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs font-mono uppercase tracking-widest text-zinc-500 ml-1">From Email</label>
                  <input
                    type="text"
                    value={formData.from_email}
                    onChange={e => setFormData({ ...formData, from_email: e.target.value })}
                    placeholder="e.g. security@paypal.com"
                    className="w-full bg-cyber-light-bg dark:bg-white/5 border border-zinc-200 dark:border-white/10 rounded-xl px-4 py-3 text-sm focus:border-cyber-light-accent/50 dark:focus:border-ornex-green/50 outline-none transition-all font-mono"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs font-mono uppercase tracking-widest text-zinc-500 ml-1">Reply-To Address</label>
                  <input
                    type="text"
                    value={formData.reply_to}
                    onChange={e => setFormData({ ...formData, reply_to: e.target.value })}
                    placeholder="Check for mismatches..."
                    className="w-full bg-cyber-light-bg dark:bg-white/5 border border-zinc-200 dark:border-white/10 rounded-xl px-4 py-3 text-sm focus:border-cyber-light-accent/50 dark:focus:border-ornex-green/50 outline-none transition-all font-mono"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs font-mono uppercase tracking-widest text-zinc-500 ml-1">Subject</label>
                  <input
                    type="text"
                    value={formData.subject}
                    onChange={e => setFormData({ ...formData, subject: e.target.value })}
                    placeholder="Action Required: Account Verification"
                    className="w-full bg-cyber-light-bg dark:bg-white/5 border border-zinc-200 dark:border-white/10 rounded-xl px-4 py-3 text-sm focus:border-cyber-light-accent/50 dark:focus:border-ornex-green/50 outline-none transition-all font-mono"
                  />
                </div>
              </div>
              <div className="space-y-2">
                <label className="text-xs font-mono uppercase tracking-widest text-zinc-500 ml-1">Email Body</label>
                <textarea
                  value={formData.body}
                  onChange={e => setFormData({ ...formData, body: e.target.value })}
                  placeholder="Paste the message content here..."
                  rows={6}
                  className="w-full bg-cyber-light-bg dark:bg-white/5 border border-zinc-200 dark:border-white/10 rounded-2xl px-4 py-4 text-sm focus:border-cyber-light-accent/50 dark:focus:border-ornex-green/50 outline-none transition-all font-mono resize-none"
                />
              </div>
            </div>
          )}

          {scanMode === 'paste' && (
            <div className="animate-fade-in space-y-2">
              <label className="text-xs font-mono uppercase tracking-widest text-zinc-500 ml-1">Raw Email (Headers + Body)</label>
              <textarea
                value={rawEmail}
                onChange={e => setRawEmail(e.target.value)}
                placeholder="Paste the full source content (including headers) from your email client..."
                rows={12}
                className="w-full bg-cyber-light-bg dark:bg-white/5 border border-zinc-200 dark:border-white/10 rounded-2xl px-4 py-4 text-sm font-mono focus:border-cyber-light-accent/50 dark:focus:border-ornex-green/50 outline-none transition-all resize-none"
              />
            </div>
          )}

          {scanMode === 'upload' && (
            <div 
              onClick={() => fileInputRef.current?.click()}
              className="animate-fade-in group cursor-pointer p-12 border-2 border-dashed border-zinc-200 dark:border-white/10 rounded-3xl bg-zinc-50 dark:bg-white/5 hover:border-cyber-light-accent/40 dark:hover:border-ornex-green/40 transition-all flex flex-col items-center justify-center gap-4"
            >
              <input 
                type="file" 
                ref={fileInputRef} 
                onChange={handleFileChange} 
                accept=".eml" 
                className="hidden" 
              />
              <div className="p-5 rounded-2xl bg-cyber-light-accent/5 dark:bg-ornex-green/5 border border-cyber-light-accent/10 dark:border-ornex-green/10 group-hover:scale-110 transition-transform">
                <FileUp className="w-8 h-8 text-cyber-light-accent dark:text-ornex-green" />
              </div>
              <div className="text-center">
                <p className="text-sm font-bold text-cyber-light-heading dark:text-white uppercase tracking-widest mb-1">
                  {selectedFile ? selectedFile.name : 'Select .eml File'}
                </p>
                <p className="text-xs text-zinc-500 font-mono">
                  {selectedFile ? `${(selectedFile.size / 1024).toFixed(1)} KB` : 'Drag and drop or click to browse'}
                </p>
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className={`w-full py-4 rounded-full font-bold uppercase tracking-widest transition-all shadow-lg flex items-center justify-center gap-3
              ${loading 
                ? 'bg-zinc-200 dark:bg-white/10 text-zinc-400 cursor-wait' 
                : 'bg-cyber-light-accent dark:bg-gradient-to-r dark:from-[#00C853] dark:to-ornex-green text-white dark:text-ornex-black hover:shadow-[0_0_25px_rgba(0,200,83,0.4)] dark:hover:shadow-[0_0_25px_rgba(57,255,20,0.4)] hover:scale-[1.01] active:scale-[0.99]'
              }`}
          >
            <div className="relative flex items-center justify-center gap-3">
              {loading ? (
                <>
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Analyzing Forensic Payload...</span>
                </>
              ) : (
                <>
                  <Shield className="w-5 h-5" />
                  <div className="flex items-center gap-2">
                    <InfoTip title="Forensic Payload" content="We extract email headers, body text, and embedded links to scan for malicious indicators.">
                      <span>Analyze Forensic Payload</span>
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
          {/* Main Risk Banner */}
          {((result.email_risk_score >= 65 || result.link_score >= 65) || (result.email_risk_level.toLowerCase() !== 'low')) && (
            <div className={`p-4 rounded-2xl border-2 flex items-center gap-4 shadow-lg backdrop-blur-md animate-pulse-subtle ${
              (result.email_risk_score >= 75 || result.link_score >= 75) 
                ? 'bg-rose-500/10 border-rose-500/20 text-rose-500' 
                : 'bg-amber-500/10 border-amber-500/20 text-amber-500'
            }`}>
              <AlertTriangle className="w-6 h-6 flex-shrink-0" />
              <div className="flex flex-col">
                <p className="text-xs font-black uppercase tracking-widest">
                  {result.email_risk_score >= 75 ? 'Critical Threat Detected' : 'Suspicious - Proceed with Caution'}
                </p>
                <p className="text-[10px] opacity-80 font-medium">
                  {result.email_risk_score >= 75 
                    ? 'This content matches high-confidence phishing patterns. Immediate isolation recommended.' 
                    : result.link_score >= 65 
                      ? 'Link analysis indicates potential deception or tracking markers. Handle with care.'
                      : 'Heuristic analysis detected unusual patterns in the email structure.'}
                </p>
              </div>
            </div>
          )}

          {/* Subtle Caution Banner */}
          {result.email_risk_level.toLowerCase() === 'low' && result.link_score >= 30 && result.link_score < 65 && (
            <div className="p-4 rounded-2xl border-2 bg-amber-500/5 border-amber-500/10 text-amber-500/80 flex items-center gap-4">
              <Info className="w-5 h-5 flex-shrink-0" />
              <p className="text-[10px] font-bold uppercase tracking-widest">
                Caution: One link looks slightly unusual (tracking/long URL markers)
              </p>
            </div>
          )}

          {/* Summary Header */}
          <div className={`relative p-8 rounded-3xl border-2 backdrop-blur-md ${getRiskColor(result.email_risk_level)} shadow-xl group`}>
            {/* Glow Container - Handles masking */}
            <div className="absolute inset-0 rounded-3xl overflow-hidden pointer-events-none">
              <div className="absolute top-0 right-0 w-32 h-32 bg-current opacity-10 blur-3xl -mr-16 -mt-16 transition-opacity group-hover:opacity-20" />
            </div>
            
            <div className="relative flex flex-col lg:flex-row justify-between items-start lg:items-center gap-8">
              <div className="flex items-center gap-6">
                <div className="flex flex-col items-center justify-center w-20 h-20 rounded-2xl bg-white/10 border border-current/20 shadow-inner backdrop-blur-sm relative">
                  <span className="text-3xl font-black leading-none tracking-tighter">{Math.round(result.email_risk_score)}</span>
                  <span className="text-[8px] font-mono opacity-60 uppercase tracking-tighter mt-1">Forensic</span>
                </div>
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <h3 className="text-3xl font-black uppercase tracking-tighter">{result.email_risk_level} RISK</h3>
                    <div className="h-4 w-px bg-current opacity-20" />
                    <span className="text-[9px] font-mono uppercase tracking-widest opacity-60">Verdict</span>
                  </div>
                  <div className="flex flex-wrap items-center gap-4 text-[9px] font-mono opacity-60 pt-1">
                    <InfoTip title="Heuristic Analysis" content="Score based on email headers, auth signals, and linguistic threat markers.">
                      <span className="flex items-center gap-1.5">
                        Heuristics: {result.heuristic_score}/40
                      </span>
                    </InfoTip>
                    <InfoTip title="Link Intelligence" content="Worst-case risk score identified across all scanned destination URLs.">
                      <span className="flex items-center gap-1.5">
                        Link Risk: {result.link_score}/100
                      </span>
                    </InfoTip>
                  </div>
                </div>
              </div>
              <div className="flex flex-wrap gap-2 lg:justify-end max-w-sm">
                {Object.entries(result.suspicious_indicators).map(([key, active]) => active && (
                  <span key={key} className="px-2.5 py-1 rounded-lg border bg-white/10 border-current/20 text-current text-[9px] font-bold uppercase tracking-widest whitespace-nowrap">
                    {key.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Main Forensic Details Card */}
          <div className="p-10 bg-white dark:bg-zinc-900 rounded-3xl border border-zinc-200 dark:border-white/10 shadow-2xl relative group">
            <div className="space-y-8 relative">
              {/* Triage Stats */}
              <div className="flex flex-wrap gap-3 items-center">
                  <InfoTip title="Total Links" content="Total unique raw links identified in the email body.">
                    <div className="flex items-center gap-2 px-3 py-1.5 bg-zinc-100 dark:bg-white/5 rounded-xl border border-zinc-200 dark:border-white/10">
                      <Zap className="w-3 h-3 text-cyber-light-accent dark:text-ornex-green" />
                      <span className="text-[9px] font-black uppercase tracking-widest text-zinc-400">Total:</span>
                      <span className="text-xs font-black text-cyber-light-heading dark:text-white">{result.total_extracted}</span>
                    </div>
                  </InfoTip>
                  <InfoTip title="Scanned Destinations" content="High-priority unique destinations subjected to full forensic analysis.">
                    <div className="flex items-center gap-2 px-3 py-1.5 bg-cyber-light-accent/5 dark:bg-ornex-green/5 rounded-xl border border-cyber-light-accent/10 dark:border-ornex-green/10 text-cyber-light-accent dark:text-ornex-green">
                      <Shield className="w-3 h-3" />
                      <span className="text-[9px] font-black uppercase tracking-widest">Scanned:</span>
                      <span className="text-xs font-black">{result.scanned_count}</span>
                    </div>
                  </InfoTip>
                {(result.triage_stats?.wrappers_unwrapped ?? 0) > 0 && (
                  <InfoTip title="Tracking Wrappers" content="Tracking URLs unwrapped to reveal and scan their true destinations.">
                    <div className="flex items-center gap-2 px-3 py-1.5 bg-purple-500/5 rounded-xl border border-purple-500/10 text-purple-400">
                      <ExternalLink size={12} />
                      <span className="text-[9px] font-black uppercase tracking-widest">Unwrapped:</span>
                      <span className="text-xs font-black">{result.triage_stats?.wrappers_unwrapped}</span>
                    </div>
                  </InfoTip>
                )}
                {(result.triage_stats?.pii_scrubbed_count ?? 0) > 0 && (
                  <InfoTip title="Privacy Scrubbing" content="Sensitive PII (emails/tokens) scrubbed from URLs before analysis.">
                    <div className="flex items-center gap-2 px-3 py-1.5 bg-blue-500/5 rounded-xl border border-blue-500/10 text-blue-400">
                      <ShieldAlert size={12} />
                      <span className="text-[9px] font-black uppercase tracking-widest">Scrubbed:</span>
                      <span className="text-xs font-black">{result.triage_stats?.pii_scrubbed_count}</span>
                    </div>
                  </InfoTip>
                )}
                  <InfoTip title="Filtered Assets" content="Redundant or low-risk assets (CSS, Images) skipped for efficiency.">
                    <div className="flex items-center gap-2 px-3 py-1.5 bg-zinc-100 dark:bg-white/5 rounded-xl border border-zinc-200 dark:border-white/10 opacity-60">
                      <CheckCircle2 className="w-3 h-3 text-zinc-400" />
                      <span className="text-[9px] font-black uppercase tracking-widest text-zinc-400">Filtered:</span>
                      <span className="text-xs font-black text-zinc-600 dark:text-zinc-400">{(result.total_extracted ?? 0) - (result.scanned_count ?? 0)}</span>
                    </div>
                  </InfoTip>
              </div>

              {/* Forensic Warnings */}
              {result.forensic_errors && result.forensic_errors.length > 0 && (
                <div className="space-y-3">
                  {result.forensic_errors.map((err, i) => (
                    <div key={i} className="flex items-center gap-3 p-3 rounded-xl bg-amber-500/5 border border-amber-500/10 text-amber-500/80 text-[10px] font-mono">
                      <AlertCircle className="w-4 h-4" />
                      <span className="uppercase font-bold">[{err.stage}]:</span>
                      <span>{err.message}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Auth Signals */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[
                  { key: 'spf', title: 'SPF (Sender Policy Framework)', content: 'A DNS record that specifies which mail servers are authorized to send email on behalf of your domain.' },
                  { key: 'dkim', title: 'DKIM (DomainKeys Identified Mail)', content: 'A cryptographic signature that ensures the email content was not tampered with and truly originated from the domain.' },
                  { key: 'dmarc', title: 'DMARC Policy', content: 'A protocol that uses SPF and DKIM to tell receiving servers how to handle emails that fail authentication.' }
                ].map(({ key, title, content }) => (
                  <InfoTip key={key} title={title} content={content} className="w-full relative flex items-center">
                    <div className={`flex items-center justify-between p-3.5 rounded-2xl border backdrop-blur-sm w-full ${getAuthColor(result.auth_results?.[key as keyof typeof result.auth_results] || 'none')}`}>
                      <span className="text-[10px] font-black uppercase tracking-widest">{key}</span>
                      <span className="text-[10px] font-bold uppercase opacity-80">{result.auth_results?.[key as keyof typeof result.auth_results] || 'none'}</span>
                    </div>
                  </InfoTip>
                ))}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Detection Reasons */}
                <div className="glass-panel p-6 rounded-3xl dark:bg-black/20 border-zinc-200 dark:border-white/10 space-y-4">
                  <h4 className="text-[11px] font-black uppercase tracking-[0.2em] text-zinc-400 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4" />
                    Forensic Detection Logs
                  </h4>
                  <ul className="space-y-3">
                    {result.reasons.map((reason, idx) => (
                      <li key={idx} className="flex items-start gap-3 text-sm text-cyber-light-text dark:text-zinc-300">
                        <ArrowRight className="w-4 h-4 text-cyber-light-accent dark:text-ornex-green mt-0.5 flex-shrink-0" />
                        <span className="leading-relaxed">{reason}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Link Profile */}
                <div className="glass-panel p-6 rounded-3xl dark:bg-black/20 border-zinc-200 dark:border-white/10 space-y-4">
                  <h4 className="text-[11px] font-black uppercase tracking-[0.2em] text-zinc-400 flex items-center gap-2">
                    <Layout className="w-4 h-4" />
                    Analyzed Link Profile
                  </h4>
                  <div className="space-y-3 max-h-[300px] overflow-y-auto pr-2 custom-scrollbar">
                    {result.link_results.map((link, idx) => (
                      <div 
                        key={idx} 
                        onClick={() => setExpandedUrls({ ...expandedUrls, [link.url]: !expandedUrls[link.url] })}
                        className={`group cursor-pointer p-4 rounded-2xl border transition-all ${expandedUrls[link.url] ? 'bg-cyber-light-accent/5 dark:bg-ornex-green/5 border-cyber-light-accent/30 dark:border-ornex-green/30' : 'bg-zinc-50 dark:bg-white/5 border-zinc-100 dark:border-white/5'}`}
                      >
                        <div className="flex flex-col gap-2">
                          {(() => {
                            const unwrapEvent = result.unwrap_events?.find(e => e.destination_url === link.url);
                            return (
                              <div className="space-y-2 overflow-hidden">
                                {unwrapEvent && (
                                  <div className="flex flex-col gap-1 p-2 rounded-lg bg-zinc-500/5 border border-zinc-500/10 mb-1">
                                    <span className="text-[8px] font-black uppercase text-zinc-400 flex items-center gap-1">
                                      Found Original URL:
                                      <InfoTip title="Tracking Source" content="The raw URL found in the email body, containing tracking parameters." />
                                    </span>
                                    <span className="text-[10px] text-zinc-500 truncate font-mono opacity-60">
                                      {unwrapEvent.found_url}
                                    </span>
                                  </div>
                                )}
                                <div className="flex justify-between items-center gap-4">
                                  <div className="space-y-1 overflow-hidden">
                                    <div className="flex items-center gap-2">
                                      <span className="text-[8px] font-black uppercase text-cyber-light-accent dark:text-ornex-green">
                                        {unwrapEvent ? 'Scanned Destination:' : 'Scanned URL:'}
                                      </span>
                                      {formatUrl(link.url)}
                                      <button onClick={(e) => copyToClipboard(link.url, e)} className="p-1 hover:bg-zinc-200 dark:hover:bg-white/10 rounded transition-colors">
                                        <Copy size={10} className="text-zinc-400" />
                                      </button>
                                      {unwrapEvent && (
                                        <span className="px-1.5 py-0.5 rounded bg-purple-500/10 text-[8px] font-black text-purple-400 border border-purple-500/20">UNWRAPPED</span>
                                      )}
                                    </div>
                                    {link.risk_level === 'INCONCLUSIVE' && (
                                      <span className="px-2 py-0.5 rounded bg-zinc-500/10 text-[9px] font-bold uppercase text-zinc-500 border border-zinc-500/20">FETCH ERROR (404)</span>
                                    )}
                                  </div>
                                  <div className="flex items-center gap-3">
                                    <div className={`px-2 py-1 rounded-lg text-[9px] font-black uppercase tracking-widest border ${getRiskColor(link.risk_level)}`}>
                                      {link.risk_level}
                                    </div>
                                    <ChevronDown className={`w-4 h-4 text-zinc-400 transition-transform ${expandedUrls[link.url] ? 'rotate-180' : ''}`} />
                                  </div>
                                </div>
                              </div>
                            );
                          })()}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Expanded Deep Dives */}
              <div className="space-y-8 pt-4">
                {result.link_results.map((link, idx) => expandedUrls[link.url] && (
                  <div key={idx} className="space-y-6 animate-slide-down">
                    <div className="flex items-center gap-3">
                      <div className="h-px flex-1 bg-zinc-200 dark:bg-white/10" />
                      <span className="text-[10px] font-black uppercase tracking-widest text-zinc-400">Deep Dive: #{idx + 1}</span>
                      <div className="h-px flex-1 bg-zinc-200 dark:bg-white/10" />
                    </div>
                    <ResultDetails result={mapToAnalysisResult(link)} hideHeader={true} />
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
