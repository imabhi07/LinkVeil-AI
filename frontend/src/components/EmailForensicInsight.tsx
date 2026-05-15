import { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, FileText, Code, AlertTriangle, Fingerprint, Paperclip, 
  Info, Search, UserCheck, Calculator, Globe, EyeOff, Terminal, Activity
} from 'lucide-react';
import type { EmailScanResponse } from '../types';
import { InfoTip } from './InfoTip';
import { CardCarousel } from './ui/CardCarousel';

interface EmailForensicInsightProps {
  result: EmailScanResponse;
}

export function EmailForensicInsight({ result }: EmailForensicInsightProps) {
  const [showMath, setShowMath] = useState(false);

  if (!result) return null;

  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-rose-500 bg-rose-500/10 border-rose-500/20';
    if (score >= 30) return 'text-amber-500 bg-amber-500/10 border-amber-500/20';
    return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
  };

  const getLureColor = (category: string) => {
    const cat = category.toLowerCase();
    if (cat === 'urgency' || cat === 'fear' || cat === 'authority') return 'text-rose-500 bg-rose-500/10 border-rose-500/20';
    if (cat === 'financial' || cat === 'scarcity') return 'text-amber-500 bg-amber-500/10 border-amber-500/20';
    return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
  };

  const emailRawSum = (result.score_breakdown?.email || []).reduce((acc, s) => acc + s.points, 0);
  const emailBreakdown = (result.score_breakdown?.email || []).map(s => s.points).join(' + ');

  const fusionMath = (() => {
    const ls = result.link_risk_score;
    const es = result.email_risk_score;
    
    // Detailed Link Math
    const linkSignals = result.score_breakdown?.link || [];
    const linkMathStr = linkSignals.length > 1 
      ? `MAX(${linkSignals.map(l => l.points.toFixed(1)).join(', ')})` 
      : ls.toFixed(1);
    
    // Detailed Email Math
    const emailMathStr = emailBreakdown ? `(${emailBreakdown})` : '0';

    if (ls >= 70) {
      return { 
        type: 'Payload Override', 
        formula: 'Result = Link Score (Critical Payload)', 
        math: `Link[${linkMathStr}] wins over Intent[${emailMathStr} = ${emailRawSum.toFixed(1)}] → ${ls.toFixed(1)}` 
      };
    }
    
    if (es >= 80) {
      return { 
        type: 'Intent Override', 
        formula: 'Result = Email Score (High Intent)', 
        math: `Intent[${emailMathStr}] wins over Link[${linkMathStr}] → ${es.toFixed(1)}` 
      };
    }
    
    if ((ls ?? 0) === 0) {
      return {
        type: 'Email Intent Only',
        formula: 'Result = Email Score (No Links Extracted)',
        math: `Intent[${emailMathStr}] = ${es.toFixed(1)}`
      };
    }

    const weightL = (ls > 30 && es > 30) ? 0.5 : 0.6;
    const weightE = (ls > 30 && es > 30) ? 0.5 : 0.4;
    const total = (ls * weightL) + (es * weightE);
    
    return {
      type: 'Weighted Fusion',
      formula: `(${weightL * 100}% Link Payload) + (${weightE * 100}% Email Intent)`,
      math: `(${ls.toFixed(1)} × ${weightL}) + (${es.toFixed(1)} × ${weightE}) = ${total.toFixed(2)}`
    };
  })();

  return (
    <div className="space-y-8 animate-fade-in mt-4">
      <div className="flex items-center gap-3 mb-2">
        <div className="p-2 md:p-2.5 bg-cyber-light-accent/10 dark:bg-ornex-green/10 rounded-xl border border-cyber-light-accent/20 dark:border-ornex-green/20 shrink-0">
          <Fingerprint className="w-5 h-5 md:w-6 md:h-6 text-cyber-light-accent dark:text-ornex-green" />
        </div>
        <div className="flex flex-col min-w-0">
          <h3 className="text-lg md:text-xl font-bold text-cyber-light-heading dark:text-white uppercase tracking-tight leading-tight truncate">Forensic Intelligence Detail</h3>
          <p className="text-[10px] md:text-xs font-bold text-zinc-500 dark:text-zinc-500/80 truncate">
            {result.identity?.subject || "Manual Forensic Analysis"}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-stretch">
        
        {/* 1. Score Breakdown Section */}
        <div className="glass-panel p-4 md:p-5 rounded-2xl md:rounded-3xl dark:bg-zinc-900/40 border-zinc-200 dark:border-white/10 space-y-3 shadow-lg flex flex-col h-full">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 mb-1.5">
            <h4 className="text-[10px] md:text-[11px] font-black uppercase tracking-[0.2em] text-zinc-400 flex items-center gap-2">
              <Search className="w-4 h-4" />
              Weighted Signal Fusion
            </h4>
            <button 
              onClick={() => setShowMath(!showMath)}
              className={`flex items-center justify-center gap-1.5 px-2.5 py-1.5 md:py-1 rounded-lg border text-[9px] md:text-[10px] font-bold transition-all w-full sm:w-auto ${
                showMath 
                  ? 'bg-purple-500/20 border-purple-500/40 text-purple-400' 
                  : 'bg-zinc-500/5 border-zinc-500/10 text-zinc-400 hover:border-zinc-500/30'
              }`}
            >
              <Calculator className="w-3 h-3" />
              {showMath ? 'HIDE MATH' : 'VIEW MATH'}
            </button>
          </div>

          {showMath && (
            <div className="p-4 mb-4 rounded-2xl bg-purple-500/5 border border-purple-500/20 animate-in slide-in-from-top-2 duration-300">
              <div className="flex items-center gap-2 mb-3">
                <div className="p-1.5 rounded-lg bg-purple-500/20 text-purple-400">
                  <Calculator className="w-3.5 h-3.5" />
                </div>
                <div>
                  <p className="text-[10px] font-black uppercase tracking-widest text-purple-400 leading-none">Forensic Formula</p>
                  <p className="text-[11px] font-bold text-white/90">{fusionMath.type}</p>
                </div>
              </div>
              <div className="space-y-2 font-mono">
                <div className="flex justify-between text-[10px] text-zinc-500">
                  <span>Logic:</span>
                  <span className="text-purple-400/80">{fusionMath.formula}</span>
                </div>
                <div className="p-2.5 rounded-xl bg-black/40 border border-white/5 text-center">
                  <span className="text-xs font-bold text-white tracking-tight break-words">{fusionMath.math}</span>
                </div>
                <p className="text-[9px] text-zinc-500 leading-tight italic">
                  *Link Score is the max risk of all triaged URLs. Email Score is the sum of identity and linguistic anomalies.
                </p>
              </div>
            </div>
          )}
          
          <div className="space-y-4">
            {/* Email Intent Signals */}
            <div className="space-y-2">
              <div className="flex items-center justify-between border-b border-zinc-200 dark:border-white/5 pb-1">
                <p className="text-[9px] md:text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Email Intent Analysis</p>
                <InfoTip title="Email Intent" content="We analyze the email's hidden technical structure and linguistic tone to detect deceptive patterns.">
                  <Info className="w-3 h-3 text-zinc-500 cursor-help" />
                </InfoTip>
              </div>
              <CardCarousel>
                {(result.score_breakdown?.email || []).map((sig, i) => (
                  <div key={i} className="h-full flex flex-col justify-between gap-2 p-3.5 md:p-4 rounded-xl md:rounded-2xl bg-white dark:bg-white/5 border border-zinc-200 dark:border-white/10 hover:border-cyber-light-accent/40 transition-all duration-300 group/card relative overflow-hidden shadow-sm hover:shadow-md">
                    {/* Background Glow */}
                    <div className={`absolute -right-8 -top-8 w-24 h-24 rounded-full blur-3xl opacity-10 dark:opacity-10 transition-opacity group-hover/card:opacity-20 ${sig.points > 30 ? 'bg-rose-500' : sig.points > 0 ? 'bg-amber-500' : 'bg-emerald-500'}`} />
                    
                    <div className="space-y-2.5 relative z-10">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-xl flex-shrink-0 shadow-sm ${sig.points > 30 ? 'bg-rose-500/10 text-rose-600 dark:text-rose-500' : sig.points > 0 ? 'bg-amber-500/10 text-amber-600 dark:text-amber-500' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-500'}`}>
                          <Activity className="w-4 h-4" />
                        </div>
                        <div className="flex-1 min-w-0 flex items-center justify-between gap-2">
                          <p className="text-xs md:text-[13px] font-bold text-zinc-900 dark:text-white uppercase tracking-tight truncate">
                            {sig.signal}
                          </p>
                          <div className="flex flex-col items-end gap-1 flex-shrink-0">
                            {sig.signal.includes('Return-Path') && (
                              <span className="text-[9px] font-black uppercase tracking-tighter text-amber-500 bg-amber-500/10 px-2 py-0.5 rounded-md border border-amber-500/20 leading-none">identity</span>
                            )}
                            {sig.signal.includes('Hidden') && (
                              <span className="text-[9px] font-black uppercase tracking-tighter text-purple-500 bg-purple-500/10 px-2 py-0.5 rounded-md border border-purple-500/20 leading-none">evasion</span>
                            )}
                          </div>
                        </div>
                      </div>
                      
                      <div className="bg-zinc-50 dark:bg-black/20 p-2 md:p-2.5 rounded-lg md:rounded-xl border border-zinc-100 dark:border-white/5">
                        <p className="text-[10px] md:text-[11px] text-zinc-600 dark:text-zinc-400 leading-relaxed font-medium">
                          {sig.reason}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center justify-between mt-2 relative z-10">
                      <div className="flex items-center gap-2">
                        <div className={`w-1.5 h-1.5 rounded-full animate-pulse ${sig.points > 30 ? 'bg-rose-500' : sig.points > 0 ? 'bg-amber-500' : 'bg-emerald-500'}`} />
                        <span className="text-[9px] font-bold text-zinc-500 uppercase tracking-tighter">Signal Analysis Logged</span>
                      </div>
                      <span className={`text-[11px] font-mono font-black ${sig.points > 0 ? 'text-rose-500' : 'text-emerald-500'}`}>
                        {sig.points > 0 ? `+${sig.points}` : sig.points}
                      </span>
                    </div>
                  </div>
                ))}
              </CardCarousel>
            </div>

            {/* Link Payload Signals */}
            <div className="space-y-2">
              <div className="flex items-center justify-between border-b border-zinc-200 dark:border-white/5 pb-1">
                <p className="text-[9px] md:text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Payload Analysis (Links)</p>
                <InfoTip title="Link Payload" content="Analysis of the destination URLs found in the email, looking for redirection loops or phishing landing pages.">
                  <Info className="w-3 h-3 text-zinc-500 cursor-help" />
                </InfoTip>
              </div>
              
              <CardCarousel>
                {(result.score_breakdown?.link || []).map((sig, i) => (
                  <div key={i} className="h-full flex flex-col justify-between gap-2 p-3.5 md:p-4 rounded-xl md:rounded-2xl bg-white dark:bg-white/5 border border-zinc-200 dark:border-white/10 hover:border-cyber-light-accent/40 transition-all duration-300 group/card relative overflow-hidden shadow-sm hover:shadow-md">
                    {/* Background Glow */}
                    <div className={`absolute -right-8 -top-8 w-24 h-24 rounded-full blur-3xl opacity-10 dark:opacity-10 transition-opacity group-hover/card:opacity-20 ${sig.points > 40 ? 'bg-rose-500' : sig.points > 0 ? 'bg-amber-500' : 'bg-emerald-500'}`} />
                    
                    <div className="space-y-2.5 relative z-10">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-xl flex-shrink-0 shadow-sm ${sig.points > 40 ? 'bg-rose-500/10 text-rose-600 dark:text-rose-500' : sig.points > 0 ? 'bg-amber-500/10 text-amber-600 dark:text-amber-500' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-500'}`}>
                          <Globe className="w-4 h-4" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-[13px] font-bold text-zinc-900 dark:text-white truncate" title={sig.url}>
                            {sig.url.replace(/^https?:\/\//, '').split('/')[0]}
                          </p>
                          <p className={`text-[10px] font-black uppercase tracking-widest ${sig.points > 40 ? 'text-rose-600 dark:text-rose-500' : sig.points > 0 ? 'text-amber-600 dark:text-amber-500' : 'text-emerald-600 dark:text-emerald-500'}`}>
                            {sig.points > 40 ? 'Dangerous Link' : sig.points > 0 ? 'Suspicious Path' : 'Verified Domain'}
                          </p>
                        </div>
                      </div>
                      
                      <div className="bg-zinc-50 dark:bg-black/20 p-2.5 md:p-3 rounded-xl border border-zinc-100 dark:border-white/5">
                        <p className="text-[11px] text-zinc-600 dark:text-zinc-400 leading-relaxed font-medium">
                          {sig.reason}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center justify-between mt-2 relative z-10">
                      <div className="flex items-center gap-2">
                        <div className={`w-1.5 h-1.5 rounded-full animate-pulse ${sig.points > 40 ? 'bg-rose-500' : sig.points > 0 ? 'bg-amber-500' : 'bg-emerald-500'}`} />
                        <span className="text-[9px] font-bold text-zinc-500 uppercase tracking-tighter">Status Monitoring Active</span>
                      </div>
                      <span className={`text-[10px] font-mono font-black px-2.5 py-1 rounded-lg border tabular-nums ${getRiskColor(sig.points)}`}>
                        RISK {sig.points}
                      </span>
                    </div>
                  </div>
                ))}
              </CardCarousel>
            </div>
          </div>
        </div>

        {/* 2. Identity & Spoofing Section */}
        <div className="glass-panel p-4 md:p-5 rounded-2xl md:rounded-3xl dark:bg-zinc-900/40 border-zinc-200 dark:border-white/10 space-y-3 shadow-lg flex flex-col h-full">
          <div className="flex items-center justify-between mb-1.5">
            <h4 className="text-[10px] md:text-[11px] font-black uppercase tracking-[0.2em] text-zinc-400 flex items-center gap-2">
              <UserCheck className="w-4 h-4" />
              Identity Verification
            </h4>
            <InfoTip title="Identity Guard" content="We verify if the sender's visible name matches their actual technical sending address.">
              <Info className="w-3.5 h-3.5 text-zinc-500 cursor-help" />
            </InfoTip>
          </div>
          
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 md:gap-4">
              <div className="p-3.5 md:p-4 rounded-xl md:rounded-2xl bg-zinc-50 dark:bg-white/5 border border-zinc-100 dark:border-white/5">
                <span className="text-[9px] md:text-[10px] font-bold text-zinc-500 uppercase tracking-widest block mb-1">Friendly From</span>
                <p className="text-xs md:text-sm font-bold text-cyber-light-heading dark:text-white truncate">{result.identity.from.name || 'No Name'}</p>
                <p className="text-[10px] md:text-[11px] text-zinc-500 font-mono truncate">{result.identity.from.email}</p>
              </div>
              <div className="p-3.5 md:p-4 rounded-xl md:rounded-2xl bg-zinc-50 dark:bg-white/5 border border-zinc-100 dark:border-white/5">
                <span className="text-[9px] md:text-[10px] font-bold text-zinc-500 uppercase tracking-widest block mb-1">Reply-To Policy</span>
                <p className="text-xs md:text-sm font-bold text-cyber-light-heading dark:text-white truncate">
                  {result.identity.reply_to ? result.identity.reply_to.email : 'Standard (No Reply-To)'}
                </p>
                <p className="text-[10px] md:text-[11px] text-zinc-500 font-mono truncate">{result.identity.reply_to?.domain || 'Aligned'}</p>
              </div>
            </div>

            {/* Alignment Warnings */}
            <div className="space-y-2">
              <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest flex items-center justify-between">
                Spoofing Detection
                <span className="text-[9px] font-medium opacity-50 lowercase italic">checks for impersonation</span>
              </p>
              {result.identity.mismatches.length > 0 ? (
                result.identity.mismatches.map((m, i) => (
                  <div key={i} className="group/spoof relative">
                    <div className="flex items-center gap-3 p-3 rounded-xl bg-rose-500/5 border border-rose-500/20 text-rose-500">
                      <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                      <span className="text-xs font-bold uppercase tracking-tight">{m.replace(/_/g, ' ')}</span>
                    </div>
                    {m === 'return_path_mismatch' && (
                      <p className="mt-1 ml-7 text-[10px] text-zinc-500 leading-tight">
                        The "hidden" sender address differs from the visible one. Common in newsletters but also used by hackers to hide their identity.
                      </p>
                    )}
                  </div>
                ))
              ) : (
                <div className="flex items-center gap-3 p-3 rounded-xl bg-emerald-500/5 border border-emerald-500/20 text-emerald-500">
                  <ShieldCheck className="w-4 h-4" />
                  <span className="text-xs font-bold uppercase tracking-tight">No Identity Anomalies Detected</span>
                </div>
              )}
            </div>

            {/* Mailing List */}
            {result.identity.mailing_list_detected && (
              <div className="p-3 rounded-xl bg-blue-500/5 border border-blue-500/20 text-blue-400 flex flex-col gap-1">
                <div className="flex items-center gap-3">
                  <Info className="w-4 h-4" />
                  <span className="text-xs font-bold uppercase tracking-tight">Mass Mailing Signature Identified</span>
                </div>
                <p className="ml-7 text-[10px] text-blue-500/70 leading-tight italic">
                  This sender is using a verified bulk-mailing service (like Mailchimp). This usually indicates a legitimate newsletter or automated notification.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* 3. HTML Artifacts Section */}
        <div className="glass-panel p-5 md:p-6 rounded-2xl md:rounded-3xl dark:bg-zinc-900/40 border-zinc-200 dark:border-white/10 space-y-4 shadow-lg">
          <h4 className="text-[10px] md:text-[11px] font-black uppercase tracking-[0.2em] text-zinc-400 flex items-center gap-2 mb-2">
            <Code className="w-4 h-4" />
            HTML Forensic Artifacts
          </h4>
          
          <div className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-2 gap-3 md:gap-4">
              <div className={`p-3.5 md:p-4 rounded-xl md:rounded-2xl border flex flex-col items-center gap-2 text-center transition-all relative group/card ${result.html_findings.zero_width_chars_found ? 'bg-rose-500/5 border-rose-500/20 text-rose-500' : 'bg-emerald-500/5 border-emerald-500/20 text-emerald-500'}`}>
                <div className="absolute top-2 right-2">
                   <InfoTip title="Unicode Deception" content="Scammers use special 'look-alike' characters to trick filters.">
                      <Info className="w-3 h-3 opacity-30 hover:opacity-100 cursor-help transition-opacity" />
                   </InfoTip>
                </div>
                <Fingerprint className="w-4 h-4 md:w-5 md:h-5" />
                <span className="text-[8px] md:text-[10px] font-black uppercase tracking-widest leading-none">Unicode<br/>Obfuscation</span>
                <span className="text-[10px] md:text-xs font-bold">{result.html_findings.zero_width_chars_found ? 'DETECTED' : 'CLEAN'}</span>
              </div>
              <div className={`p-3.5 md:p-4 rounded-xl md:rounded-2xl border flex flex-col items-center gap-2 text-center transition-all relative group/card ${result.html_findings.form_tags_found ? 'bg-amber-500/5 border-amber-500/20 text-amber-500' : 'bg-zinc-500/5 border-zinc-500/10 text-zinc-500'}`}>
                <div className="absolute top-2 right-2">
                   <InfoTip title="Embedded Forms" content="Legitimate companies rarely put login forms inside an email.">
                      <Info className="w-3 h-3 opacity-30 hover:opacity-100 cursor-help transition-opacity" />
                   </InfoTip>
                </div>
                <FileText className="w-4 h-4 md:w-5 md:h-5" />
                <span className="text-[8px] md:text-[10px] font-black uppercase tracking-widest leading-none">Embedded<br/>Forms</span>
                <span className="text-[10px] md:text-xs font-bold">{result.html_findings.form_tags_found ? 'DETECTED' : 'NONE'}</span>
              </div>
            </div>

            {/* Hidden Elements */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Anti-Evasion Detection</p>
                <InfoTip title="Evasion Tactics" content="Techniques used by scammers to hide malicious content from security scanners while keeping it visible (or functional) for the victim.">
                  <Info className="w-3 h-3 text-zinc-500 cursor-help" />
                </InfoTip>
              </div>
              
              {result.html_findings.hidden_html.length > 0 ? (
                <CardCarousel>
                  {result.html_findings.hidden_html.map((h, i) => (
                    <div key={i} className="h-full flex flex-col justify-between gap-5 p-6 rounded-2xl bg-white dark:bg-zinc-900/40 border border-zinc-200 dark:border-white/10 group/evasion transition-all hover:border-amber-500/30 relative overflow-hidden shadow-sm hover:shadow-md">
                      {/* Decorative Side Accent */}
                      <div className="absolute left-0 top-0 bottom-0 w-1 bg-amber-500/20 group-hover/evasion:bg-amber-500/50 transition-colors" />
                      
                      <div className="space-y-4 relative z-10">
                        <div className="flex items-start justify-between">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <div className="p-1.5 rounded-lg bg-amber-500/10 text-amber-600 dark:text-amber-500">
                                <EyeOff className="w-4 h-4" />
                              </div>
                              <span className="text-xs font-black uppercase text-zinc-900 dark:text-white tracking-tight">
                                {h.technique === 'FONT-SIZE' ? 'Invisible Content' : 
                                 h.technique === 'DISPLAY' || h.technique === 'VISIBILITY' ? 'Hidden Layout' : 
                                 h.technique === 'OPACITY' ? 'Transparency Bypass' :
                                 h.technique === 'COLOR' ? 'Low-Contrast Text' : h.technique}
                              </span>
                            </div>
                            <p className="text-[10px] text-amber-600 dark:text-amber-500/80 font-bold uppercase tracking-widest pl-8">
                              {h.technique === 'FONT-SIZE' ? 'Strategy: Micro-Font Stuffing' : 'Strategy: CSS Obfuscation'}
                            </p>
                          </div>
                          
                          <InfoTip 
                            title={h.technique === 'FONT-SIZE' ? 'Invisible Text Attack' : 'Hidden Elements Risk'} 
                            content={h.technique === 'FONT-SIZE' ? 'Attackers use 0px or 1px fonts to hide malicious keywords from automated scanners while keeping the email readable for victims.' : 'Using CSS to hide phishing forms or fake buttons allows attackers to bypass simple keyword filters.'}
                          >
                            <div className="p-1.5 rounded-lg border border-zinc-200 dark:border-white/10 text-zinc-400 hover:text-amber-500 transition-colors">
                              <ShieldAlert className="w-3.5 h-3.5" />
                            </div>
                          </InfoTip>
                        </div>

                        <div className="space-y-2">
                          <div className="flex items-center justify-between px-1">
                            <p className="text-[10px] font-bold text-zinc-400 dark:text-zinc-500 uppercase tracking-[0.1em]">Forensic Snippet</p>
                            <span className="text-[9px] font-mono text-zinc-300 dark:text-zinc-600">source_snippet.html</span>
                          </div>
                          <div className="relative group/snippet">
                            <code className="text-[11px] font-mono text-zinc-700 dark:text-amber-200/80 break-all bg-zinc-50 dark:bg-black/60 p-4 rounded-xl block border border-zinc-200 dark:border-white/5 h-28 overflow-y-auto scrollbar-thin scrollbar-thumb-zinc-200 dark:scrollbar-thumb-amber-500/20 shadow-inner leading-relaxed">
                              {h.snippet}
                            </code>
                            <div className="absolute inset-x-0 bottom-0 h-8 bg-gradient-to-t from-zinc-50 dark:from-black/60 to-transparent pointer-events-none rounded-b-xl" />
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center justify-between pt-2 border-t border-zinc-100 dark:border-white/5 relative z-10">
                        <div className="flex items-center gap-2">
                          <Terminal className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500" />
                          <span className="text-[9px] font-bold text-zinc-400 dark:text-zinc-500 uppercase tracking-tighter">Automated Analysis Engine</span>
                        </div>
                        <div className="flex items-center gap-1.5 bg-amber-500/5 px-2 py-1 rounded-md border border-amber-500/10">
                          <div className="w-1 h-1 rounded-full bg-amber-500 animate-pulse" />
                          <span className="text-[9px] font-black uppercase text-amber-600 dark:text-amber-500">Technical Evidence</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </CardCarousel>
              ) : (
                <div className="p-3 rounded-xl bg-zinc-50 dark:bg-white/5 border border-zinc-100 dark:border-white/5 text-zinc-500 flex items-center gap-3">
                  <ShieldCheck className="w-4 h-4 opacity-50" />
                  <span className="text-xs font-bold uppercase tracking-tight">No Hidden Layout Deception</span>
                </div>
              )}
            </div>

            {/* Link Mismatches */}
            {result.html_findings.link_mismatches.length > 0 && (
              <div className="space-y-2">
                <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Mismatched Hyperlinks</p>
                {result.html_findings.link_mismatches.map((m, i) => (
                  <div key={i} className="p-3 rounded-xl bg-rose-500/5 border border-rose-500/20 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-black uppercase text-rose-500">Visual Mismatch</span>
                      <ShieldAlert className="w-3 h-3 text-rose-500" />
                    </div>
                    <p className="text-xs text-zinc-400 truncate"><span className="text-zinc-500">Text:</span> {m.visible_text}</p>
                    <p className="text-xs text-rose-400 truncate"><span className="text-zinc-500">Target:</span> {m.href}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* 4. Attachment Forensics Section */}
        <div className="glass-panel p-5 md:p-6 rounded-2xl md:rounded-3xl dark:bg-zinc-900/40 border-zinc-200 dark:border-white/10 space-y-4 shadow-lg">
          <h4 className="text-[10px] md:text-[11px] font-black uppercase tracking-[0.2em] text-zinc-400 flex items-center gap-2 mb-2">
            <Paperclip className="w-4 h-4" />
            Attachment Intelligence
          </h4>
          
          <div className="space-y-3">
            {result.attachments.length > 0 ? (
              result.attachments.map((a, i) => (
                <div key={i} className="p-4 rounded-2xl bg-zinc-50 dark:bg-white/5 border border-zinc-100 dark:border-white/5 flex items-center justify-between gap-4 group/file">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={`p-2.5 rounded-xl border ${a.risk === 'high' ? 'text-rose-500 bg-rose-500/10 border-rose-500/20' : a.risk === 'medium' ? 'text-amber-500 bg-amber-500/10 border-amber-500/20' : 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20'}`}>
                      <FileText className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-bold text-cyber-light-heading dark:text-white truncate" title={a.filename}>{a.filename}</p>
                      <p className="text-[10px] text-zinc-500 font-mono">{(a.size_bytes / 1024).toFixed(1)} KB • {a.mime_type}</p>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-1">
                    <span className={`text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded border ${a.risk === 'high' ? 'text-rose-500 bg-rose-500/10 border-rose-500/20' : a.risk === 'medium' ? 'text-amber-500 bg-amber-500/10 border-amber-500/20' : 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20'}`}>
                      {a.risk}
                    </span>
                    {a.reasons.length > 0 && (
                       <InfoTip title="Attachment Risk" content={a.reasons.join(', ')}>
                          <AlertTriangle className="w-3 h-3 text-amber-500" />
                       </InfoTip>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <div className="flex flex-col items-center justify-center py-10 text-center space-y-4">
                <div className="p-4 bg-zinc-100 dark:bg-white/5 rounded-3xl border border-zinc-200 dark:border-white/10">
                  <Paperclip className="w-8 h-8 text-zinc-400 opacity-50" />
                </div>
                <p className="text-[11px] text-zinc-500 font-black uppercase tracking-widest">No Attachments Detected</p>
              </div>
            )}
          </div>

          {result.attachments.length > 0 && (
            <div className="p-4 rounded-2xl bg-cyber-light-accent/5 dark:bg-ornex-green/5 border border-cyber-light-accent/10 dark:border-ornex-green/10">
              <p className="text-[11px] text-cyber-light-accent dark:text-ornex-green leading-relaxed">
                <span className="font-bold uppercase tracking-widest">Note:</span> We analyze file extensions, mime-types, and hashes. We do not execute files. Never open attachments from untrusted sources.
              </p>
            </div>
          )}
        </div>

      </div>

      {/* Social Engineering Signals */}
      <div className="glass-panel p-5 md:p-8 rounded-2xl md:rounded-[2.5rem] dark:bg-zinc-900/40 border border-cyber-light-accent/20 dark:border-ornex-green/20 shadow-2xl relative overflow-hidden group">
        <div className="absolute top-0 right-0 w-64 h-64 bg-cyber-light-accent/5 dark:bg-ornex-green/5 blur-[100px] -mr-32 -mt-32 pointer-events-none" />
        
        <div className="relative">
            <div className="flex flex-col sm:flex-row sm:items-center gap-3 mb-6">
              <div className="p-2.5 bg-cyber-light-accent/10 dark:bg-ornex-green/10 rounded-xl border border-cyber-light-accent/20 dark:border-ornex-green/20 shrink-0 self-start">
                <ShieldAlert className="w-5 h-5 text-cyber-light-accent dark:text-ornex-green" />
              </div>
              <div className="flex-1 min-w-0">
                 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <h4 className="text-[13px] md:text-sm font-black uppercase tracking-[0.2em] text-cyber-light-heading dark:text-white">Psychological Threat Analysis</h4>
                    <InfoTip title="Social Engineering" content="Attackers often don't use viruses; they use words. This section detects psychological tricks like creating fake panic or pretending to be a 'Support' desk to trick you into clicking.">
                      <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-light-accent/5 border border-cyber-light-accent/10 cursor-help self-start">
                         <Info className="w-3 h-3 text-cyber-light-accent dark:text-ornex-green" />
                         <span className="text-[9px] md:text-[10px] font-bold text-cyber-light-accent dark:text-ornex-green uppercase tracking-widest">Help</span>
                      </div>
                    </InfoTip>
                 </div>
                 <p className="text-[9px] md:text-[10px] text-zinc-500 font-mono uppercase tracking-widest mt-1">Tone & language analysis for manipulation patterns</p>
              </div>
            </div>

           {result.social_engineering.matches.length > 0 ? (
             <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                {(result.social_engineering?.matches || []).map((m, i) => (
                  <div key={i} className={`p-5 rounded-3xl bg-white dark:bg-black/20 border border-zinc-200 dark:border-white/5 hover:border-cyber-light-accent/30 dark:hover:border-ornex-green/30 transition-all group/lure relative ${m.confidence === 'HIGH' ? 'ring-1 ring-rose-500/20' : ''}`}>
                    <div className="flex items-center justify-between mb-3">
                       <div className="flex items-center gap-2">
                         <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest border transition-colors ${getLureColor(m.category)}`}>
                            {m.category}
                         </span>
                         <InfoTip title={m.category} content={
                           m.category === 'Urgency' ? 'Attackers use time pressure (e.g., "Act Now") to stop you from thinking clearly.' :
                           m.category === 'Authority' ? 'Scammers pretend to be someone powerful (CEO, Police, IT) to demand compliance.' :
                           m.category === 'Fear' ? 'Threats of account suspension or legal action are used to trigger panic.' :
                           m.category === 'Scarcity' ? 'Suggesting a limited offer to make you act impulsively.' :
                           'Linguistic pattern associated with psychological manipulation.'
                         }>
                           <Info className="w-3 h-3 text-zinc-400 opacity-50 cursor-help" />
                         </InfoTip>
                       </div>
                       <span className={`text-[10px] font-mono font-bold ${m.confidence === 'HIGH' ? 'text-rose-500' : 'text-zinc-400'}`}>{m.confidence || 'HIGH'} MATCH</span>
                    </div>
                    <p className={`text-xs font-bold mb-2 uppercase tracking-tight ${m.confidence === 'HIGH' ? 'text-rose-600 dark:text-rose-400' : 'text-cyber-light-heading dark:text-white'}`}>Target: "{m.keyword}"</p>
                    <p className="text-[11px] text-zinc-500 dark:text-zinc-400 italic leading-relaxed">
                       "...{m.snippet}..."
                     </p>
                  </div>
                ))}
             </div>
           ) : (
             <div className="flex flex-col items-center justify-center py-12 text-center space-y-4 bg-zinc-50 dark:bg-white/5 rounded-3xl border border-dashed border-zinc-200 dark:border-white/10">
                <div className="p-4 bg-emerald-500/10 rounded-full border border-emerald-500/20">
                  <ShieldCheck className="w-8 h-8 text-emerald-500" />
                </div>
                <div className="space-y-1">
                  <h5 className="text-xs font-black uppercase tracking-widest text-emerald-500">Safe Baseline Confirmed</h5>
                  <p className="text-[11px] text-zinc-500 max-w-[400px] leading-relaxed mx-auto">
                    Forensic linguistic analysis detected no patterns of urgency, fear-mongering, or impersonation lures. The email tone remains professional and neutral.
                  </p>
                </div>
              </div>
           )}
        </div>
      </div>
    </div>
  );
}
