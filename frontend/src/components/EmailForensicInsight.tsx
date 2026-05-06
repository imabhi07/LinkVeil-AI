import { 
  ShieldAlert, ShieldCheck, FileText, Code, AlertTriangle, Fingerprint, Paperclip, 
  Info, Search, UserCheck
} from 'lucide-react';
import type { EmailScanResponse } from '../types';
import { InfoTip } from './InfoTip';

interface EmailForensicInsightProps {
  result: EmailScanResponse;
}

export function EmailForensicInsight({ result }: EmailForensicInsightProps) {
  if (!result) return null;

  const getRiskColor = (risk: string) => {
    switch (risk?.toLowerCase()) {
      case 'high': return 'text-rose-500 bg-rose-500/10 border-rose-500/20';
      case 'medium': return 'text-amber-500 bg-amber-500/10 border-amber-500/20';
      case 'low': return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
      default: return 'text-zinc-500 bg-zinc-500/10 border-zinc-500/20';
    }
  };

  return (
    <div className="space-y-8 animate-fade-in mt-12">
      <div className="flex items-center gap-3 mb-2">
        <Fingerprint className="w-6 h-6 text-cyber-light-accent dark:text-ornex-green" />
        <h3 className="text-xl font-bold text-cyber-light-heading dark:text-white uppercase tracking-tight">Forensic Intelligence Detail</h3>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* 1. Score Breakdown Section */}
        <div className="glass-panel p-6 rounded-3xl dark:bg-zinc-900/40 border-zinc-200 dark:border-white/10 space-y-4 shadow-lg">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-[11px] font-black uppercase tracking-[0.2em] text-zinc-400 flex items-center gap-2">
              <Search className="w-4 h-4" />
              Weighted Signal Fusion
            </h4>
            <div className="px-2 py-0.5 rounded-lg bg-cyber-light-accent/10 text-cyber-light-accent dark:text-ornex-green text-[10px] font-bold border border-cyber-light-accent/20">
              CONFIDENCE: {result.confidence?.level?.toUpperCase() || 'MEDIUM'}
            </div>
          </div>
          
          <div className="space-y-6">
            {/* Email Intent Signals */}
            <div className="space-y-3">
              <div className="flex items-center justify-between border-b border-zinc-200 dark:border-white/5 pb-1">
                <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Email Intent Analysis</p>
                <InfoTip title="Email Intent" content="We analyze the email's hidden technical structure and linguistic tone to detect deceptive patterns.">
                  <Info className="w-3 h-3 text-zinc-500 cursor-help" />
                </InfoTip>
              </div>
              {(result.score_breakdown?.email || []).map((sig, i) => (
                <div key={i} className="flex items-start justify-between gap-4 p-3 rounded-xl bg-zinc-50 dark:bg-white/5 border border-zinc-100 dark:border-white/5 group/sig hover:border-cyber-light-accent/30 transition-colors">
                  <div className="space-y-1">
                    <p className="text-xs font-bold text-cyber-light-heading dark:text-white uppercase tracking-tight flex items-center gap-2">
                      {sig.signal}
                      {sig.signal.includes('Return-Path') && (
                        <span className="text-[9px] font-medium text-amber-500 lowercase bg-amber-500/10 px-1.5 rounded-full border border-amber-500/20">identity mismatch</span>
                      )}
                      {sig.signal.includes('Hidden') && (
                        <span className="text-[9px] font-medium text-purple-500 lowercase bg-purple-500/10 px-1.5 rounded-full border border-purple-500/20">evasion detection</span>
                      )}
                    </p>
                    <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-tight">
                      {sig.reason}
                    </p>
                  </div>
                  <span className={`text-xs font-mono font-bold ${sig.points > 0 ? 'text-rose-500' : 'text-emerald-500'}`}>
                    {sig.points > 0 ? `+${sig.points}` : sig.points}
                  </span>
                </div>
              ))}
            </div>

            {/* Link Payload Signals */}
            <div className="space-y-3">
              <div className="flex items-center justify-between border-b border-zinc-200 dark:border-white/5 pb-1">
                <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Payload Analysis (Links)</p>
                <InfoTip title="Link Payload" content="Analysis of the destination URLs found in the email, looking for redirection loops or phishing landing pages.">
                  <Info className="w-3 h-3 text-zinc-500 cursor-help" />
                </InfoTip>
              </div>
              {(result.score_breakdown?.link || []).map((sig, i) => (
                <div key={i} className="flex items-start justify-between gap-4 p-3 rounded-xl bg-zinc-50 dark:bg-white/5 border border-zinc-100 dark:border-white/5 hover:border-cyber-light-accent/30 transition-colors">
                  <div className="space-y-1">
                    <p className="text-xs font-bold text-cyber-light-heading dark:text-white uppercase tracking-tight truncate max-w-[200px]">{sig.url.replace('https://', '')}</p>
                    <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-tight">{sig.reason}</p>
                  </div>
                  <span className="text-xs font-mono font-bold text-rose-500">+{sig.points}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* 2. Identity & Spoofing Section */}
        <div className="glass-panel p-6 rounded-3xl dark:bg-zinc-900/40 border-zinc-200 dark:border-white/10 space-y-4 shadow-lg">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-[11px] font-black uppercase tracking-[0.2em] text-zinc-400 flex items-center gap-2">
              <UserCheck className="w-4 h-4" />
              Identity Verification
            </h4>
            <InfoTip title="Identity Guard" content="We verify if the sender's visible name matches their actual technical sending address.">
              <Info className="w-3.5 h-3.5 text-zinc-500 cursor-help" />
            </InfoTip>
          </div>
          
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-2xl bg-zinc-50 dark:bg-white/5 border border-zinc-100 dark:border-white/5">
                <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest block mb-1">Friendly From</span>
                <p className="text-sm font-bold text-cyber-light-heading dark:text-white">{result.identity.from.name || 'No Name'}</p>
                <p className="text-[11px] text-zinc-500 font-mono truncate">{result.identity.from.email}</p>
              </div>
              <div className="p-4 rounded-2xl bg-zinc-50 dark:bg-white/5 border border-zinc-100 dark:border-white/5">
                <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest block mb-1">Reply-To Policy</span>
                <p className="text-sm font-bold text-cyber-light-heading dark:text-white">
                  {result.identity.reply_to ? result.identity.reply_to.email : 'Standard (No Reply-To)'}
                </p>
                <p className="text-[11px] text-zinc-500 font-mono truncate">{result.identity.reply_to?.domain || 'Aligned'}</p>
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
        <div className="glass-panel p-6 rounded-3xl dark:bg-zinc-900/40 border-zinc-200 dark:border-white/10 space-y-4 shadow-lg">
          <h4 className="text-[11px] font-black uppercase tracking-[0.2em] text-zinc-400 flex items-center gap-2 mb-2">
            <Code className="w-4 h-4" />
            HTML Forensic Artifacts
          </h4>
          
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className={`p-4 rounded-2xl border flex flex-col items-center gap-2 text-center transition-all relative group/card ${result.html_findings.zero_width_chars_found ? 'bg-rose-500/5 border-rose-500/20 text-rose-500' : 'bg-emerald-500/5 border-emerald-500/20 text-emerald-500'}`}>
                <div className="absolute top-2 right-2">
                   <InfoTip title="Unicode Deception" content="Scammers use special 'look-alike' characters (like using a Cyrillic 'а' instead of a standard 'a') to trick filters and users into visiting fake websites.">
                      <Info className="w-3 h-3 opacity-30 hover:opacity-100 cursor-help transition-opacity" />
                   </InfoTip>
                </div>
                <Fingerprint className="w-5 h-5" />
                <span className="text-[10px] font-black uppercase tracking-widest leading-none">Unicode<br/>Obfuscation</span>
                <span className="text-xs font-bold">{result.html_findings.zero_width_chars_found ? 'DETECTED' : 'CLEAN'}</span>
              </div>
              <div className={`p-4 rounded-2xl border flex flex-col items-center gap-2 text-center transition-all relative group/card ${result.html_findings.form_tags_found ? 'bg-amber-500/5 border-amber-500/20 text-amber-500' : 'bg-zinc-500/5 border-zinc-500/10 text-zinc-500'}`}>
                <div className="absolute top-2 right-2">
                   <InfoTip title="Embedded Forms" content="Legitimate companies rarely put login forms inside an email. These are almost always used to steal your passwords or credit card info directly.">
                      <Info className="w-3 h-3 opacity-30 hover:opacity-100 cursor-help transition-opacity" />
                   </InfoTip>
                </div>
                <FileText className="w-5 h-5" />
                <span className="text-[10px] font-black uppercase tracking-widest leading-none">Embedded<br/>Forms</span>
                <span className="text-xs font-bold">{result.html_findings.form_tags_found ? 'DETECTED' : 'NONE'}</span>
              </div>
            </div>

            {/* Hidden Elements */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Anti-Evasion Detection</p>
                <InfoTip title="Evasion Tactics" content="Techniques used by scammers to hide malicious content from security scanners while keeping it visible (or functional) for the victim.">
                  <Info className="w-3 h-3 text-zinc-500 cursor-help" />
                </InfoTip>
              </div>
              {result.html_findings.hidden_html.length > 0 ? (
                result.html_findings.hidden_html.map((h, i) => (
                  <div key={i} className="space-y-1 p-3 rounded-xl bg-amber-500/5 border border-amber-500/20 group/evasion transition-all hover:bg-amber-500/10">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-black uppercase text-amber-500 flex items-center gap-2">
                        {h.technique === 'FONT-SIZE' ? 'Invisible Text Detection' : 
                         h.technique === 'DISPLAY' || h.technique === 'VISIBILITY' ? 'Hidden Layout Manipulation' : 
                         h.technique === 'OPACITY' ? 'Transparent Element Found' :
                         h.technique === 'COLOR' ? 'Low-Contrast Text' : h.technique}
                        <span className="text-[8px] font-medium opacity-60 lowercase px-1.5 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/20">
                          {h.technique === 'FONT-SIZE' ? 'micro-font usage' : 
                           h.technique === 'DISPLAY' || h.technique === 'VISIBILITY' ? 'css invisibility' : 
                           h.technique === 'OPACITY' ? 'transparency trick' : 'visual deception'}
                        </span>
                      </span>
                      <InfoTip 
                        title={h.technique === 'FONT-SIZE' ? 'Why hide text?' : 'Hidden Elements'} 
                        content={h.technique === 'FONT-SIZE' ? 'Attackers use 0px or 1px fonts to "stuff" keywords into an email to bypass spam filters without the user seeing them.' : 'Scammers use CSS to hide phishing forms or links from automated scanners.'}
                      >
                        <Info className="w-3 h-3 text-amber-500/50" />
                      </InfoTip>
                    </div>
                    <div className="mt-2 space-y-1.5">
                      <p className="text-[10px] text-zinc-500 italic">Forensic Snippet:</p>
                      <code className="text-[10px] font-mono text-zinc-400 break-all bg-black/40 p-2 rounded-lg block border border-white/5">
                        {h.snippet}
                      </code>
                    </div>
                  </div>
                ))
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
        <div className="glass-panel p-6 rounded-3xl dark:bg-zinc-900/40 border-zinc-200 dark:border-white/10 space-y-4 shadow-lg">
          <h4 className="text-[11px] font-black uppercase tracking-[0.2em] text-zinc-400 flex items-center gap-2 mb-2">
            <Paperclip className="w-4 h-4" />
            Attachment Intelligence
          </h4>
          
          <div className="space-y-3">
            {result.attachments.length > 0 ? (
              result.attachments.map((a, i) => (
                <div key={i} className="p-4 rounded-2xl bg-zinc-50 dark:bg-white/5 border border-zinc-100 dark:border-white/5 flex items-center justify-between gap-4 group/file">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={`p-2.5 rounded-xl border ${getRiskColor(a.risk)}`}>
                      <FileText className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-bold text-cyber-light-heading dark:text-white truncate" title={a.filename}>{a.filename}</p>
                      <p className="text-[10px] text-zinc-500 font-mono">{(a.size_bytes / 1024).toFixed(1)} KB • {a.mime_type}</p>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-1">
                    <span className={`text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded border ${getRiskColor(a.risk)}`}>
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
      <div className="glass-panel p-8 rounded-[2.5rem] dark:bg-zinc-900/40 border border-cyber-light-accent/20 dark:border-ornex-green/20 shadow-2xl relative overflow-hidden group">
        <div className="absolute top-0 right-0 w-64 h-64 bg-cyber-light-accent/5 dark:bg-ornex-green/5 blur-[100px] -mr-32 -mt-32 pointer-events-none" />
        
        <div className="relative">
           <div className="flex items-center gap-3 mb-6">
              <div className="p-2.5 bg-cyber-light-accent/10 dark:bg-ornex-green/10 rounded-xl border border-cyber-light-accent/20 dark:border-ornex-green/20">
                <ShieldAlert className="w-5 h-5 text-cyber-light-accent dark:text-ornex-green" />
              </div>
              <div className="flex-1">
                 <div className="flex items-center justify-between">
                    <h4 className="text-sm font-black uppercase tracking-[0.2em] text-cyber-light-heading dark:text-white">Psychological Threat Analysis</h4>
                    <InfoTip title="Social Engineering" content="Attackers often don't use viruses; they use words. This section detects psychological tricks like creating fake panic or pretending to be a 'Support' desk to trick you into clicking.">
                      <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-light-accent/5 border border-cyber-light-accent/10 cursor-help">
                         <Info className="w-3.5 h-3.5 text-cyber-light-accent dark:text-ornex-green" />
                         <span className="text-[10px] font-bold text-cyber-light-accent dark:text-ornex-green uppercase tracking-widest">What is this?</span>
                      </div>
                    </InfoTip>
                 </div>
                 <p className="text-[10px] text-zinc-500 font-mono uppercase tracking-widest mt-1">Tone & language analysis for manipulation patterns</p>
              </div>
           </div>

           {result.social_engineering.matches.length > 0 ? (
             <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {(result.social_engineering?.matches || []).map((m, i) => (
                  <div key={i} className="p-5 rounded-3xl bg-white dark:bg-black/20 border border-zinc-200 dark:border-white/5 hover:border-cyber-light-accent/30 dark:hover:border-ornex-green/30 transition-all group/lure relative">
                    <div className="flex items-center justify-between mb-3">
                       <div className="flex items-center gap-2">
                         <span className="px-3 py-1 rounded-full bg-zinc-100 dark:bg-white/5 text-[10px] font-black uppercase tracking-widest text-zinc-500 group-hover/lure:text-cyber-light-accent dark:group-hover/lure:text-ornex-green transition-colors">
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
                       <span className="text-[10px] font-mono text-zinc-400">{m.confidence || 'HIGH'} MATCH</span>
                    </div>
                    <p className="text-xs font-bold text-cyber-light-heading dark:text-white mb-2 uppercase tracking-tight">Target: "{m.keyword}"</p>
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
