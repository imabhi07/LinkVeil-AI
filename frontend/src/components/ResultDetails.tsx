import React, { memo, useState } from 'react';
import { createPortal } from 'react-dom';
import type { AnalysisResult } from '../types';
import { 
  ShieldCheck, ShieldX, Activity, Globe, AlertTriangle, 
  ExternalLink, ArrowRight, Bot, Eye, Terminal, Zap, Image as ImageIcon, Info, X, ChevronDown, RefreshCw
} from 'lucide-react';
import { RiskGauge } from './RiskGauge';
import { InfoTip } from './InfoTip';

interface ResultDetailsProps {
  result: AnalysisResult;
  hideHeader?: boolean;
  onRetry?: () => void;
}

export const ResultDetails: React.FC<ResultDetailsProps> = memo(({ result, hideHeader, onRetry }) => {
  const [isImageModalOpen, setIsImageModalOpen] = useState(false);
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['agentLog']));

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev);
      if (next.has(section)) {
        next.delete(section);
      } else {
        next.add(section);
      }
      return next;
    });
  };

  // Safety check for critical data
  if (!result) return null;

  const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

  return (
    <div className="w-full space-y-6">
      {/* Degradation Warning Banner */}
      {result.degraded_engines && result.degraded_engines.length > 0 && (
        <div className="p-4 rounded-2xl border border-amber-200 dark:border-amber-500/20 bg-amber-50 dark:bg-amber-500/5 flex items-center justify-between gap-4 animate-in slide-in-from-top-2 duration-300 backdrop-blur-md">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0" />
            <div>
              <p className="text-xs font-black uppercase tracking-widest text-amber-700 dark:text-amber-400">
                Partial Analysis
              </p>
              <p className="text-[11px] text-amber-600 dark:text-amber-500/80 font-medium">
                Some checks failed ({result.degraded_engines.map(e => 
                  e === 'llm' ? 'AI Analysis' : 
                  e === 'xgboost' ? 'ML Model' : 
                  e === 'bert' ? 'Deep Learning' :
                  e === 'probe' ? 'Active Probe' :
                  e.toUpperCase()
                ).join(', ')}). Showing results from available engines.
              </p>
            </div>
          </div>
          {onRetry && (
            <button
              onClick={onRetry}
              className="px-4 py-2 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/20 
                         rounded-full text-xs font-bold uppercase tracking-widest text-amber-600 
                         dark:text-amber-400 transition-all shrink-0"
            >
              Retry Scan
            </button>
          )}
        </div>
      )}

      {/* Unified Action-Oriented Forensic Header */}
      {!hideHeader && (
        <div className={`p-10 rounded-[2.5rem] border-2 shadow-2xl flex flex-col lg:flex-row items-center justify-between gap-10 animate-in zoom-in-95 duration-500 transition-all ${
          result.riskLevel === 'SAFE' ? 'bg-emerald-500/5 border-emerald-500/20' :
          result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-500/5 border-amber-500/20' :
          result.riskLevel === 'MALICIOUS' ? 'bg-rose-500/5 border-rose-500/20 shadow-rose-500/10' :
          'bg-zinc-500/5 border-zinc-500/20'
        }`}>
          <div className="flex flex-col md:flex-row items-center md:items-start gap-8 flex-1">
            <div className={`p-8 rounded-[2rem] shadow-2xl border-4 ${
              result.riskLevel === 'SAFE' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-600' :
              result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-500/10 border-amber-500/30 text-amber-600' :
              result.riskLevel === 'MALICIOUS' ? 'bg-rose-500/10 border-rose-500/30 text-rose-600' :
              'bg-zinc-500/10 border-zinc-500/30 text-zinc-500'
            }`}>
              {result.riskLevel === 'SAFE' ? <ShieldCheck className="w-12 h-12" /> :
               result.riskLevel === 'SUSPICIOUS' ? <AlertTriangle className="w-12 h-12" /> :
               result.riskLevel === 'MALICIOUS' ? <ShieldX className="w-12 h-12" /> :
               <Activity className="w-12 h-12" />}
            </div>
            
            <div className="space-y-4 text-center md:text-left flex-1">
              <div className="flex flex-wrap items-center justify-center md:justify-start gap-3">
                <span className={`px-4 py-1 rounded-full text-xs font-black uppercase tracking-widest border-2 ${
                  result.riskLevel === 'SAFE' ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-700 dark:text-emerald-300' :
                  result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-500/20 border-amber-500/40 text-amber-700 dark:text-amber-300' :
                  result.riskLevel === 'MALICIOUS' ? 'bg-rose-500/20 border-rose-500/40 text-rose-700 dark:text-rose-300' :
                  'bg-zinc-500/20 border-zinc-500/40 text-zinc-700 dark:text-zinc-300'
                }`}>
                  {result.riskLevel} VERDICT
                </span>
                {result.threat_intel?.is_known_malicious && (
                  <span className="flex items-center gap-2 px-3 py-1 rounded-full bg-rose-600 text-white text-[10px] font-black uppercase tracking-tighter animate-pulse shadow-lg shadow-rose-600/20">
                    <Zap className="w-3 h-3" /> INTEL HIT: {result.threat_intel.source}
                  </span>
                )}
              </div>
              
              <div>
                <h1 className="text-4xl md:text-5xl font-black tracking-tight uppercase leading-tight dark:text-white mb-2">
                  {result.verdictTitle}
                </h1>
                <p className="text-sm font-medium text-zinc-500 dark:text-zinc-400 max-w-xl line-clamp-1 opacity-80 italic">
                  {result.url}
                </p>
              </div>
              
              <div className="p-6 rounded-2xl bg-white/50 dark:bg-black/20 border border-black/5 dark:border-white/10 shadow-inner">
                <div className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] mb-2 text-zinc-400">
                   <Zap className="w-3 h-3 text-amber-500" /> Executive Recommendation
                </div>
                <p className="text-lg font-black leading-tight dark:text-zinc-100">
                  {result.recommendation || (
                    result.riskLevel === 'SAFE' ? 'Safe to proceed. No malicious patterns detected.' :
                    result.riskLevel === 'SUSPICIOUS' ? 'Caution required. Avoid interacting with forms or downloads.' :
                    result.riskLevel === 'MALICIOUS' ? 'DO NOT OPEN. This link is confirmed as an active phishing threat.' :
                    'Scanning in progress...'
                  )}
                </p>
              </div>
            </div>
          </div>

          <div className="flex flex-col items-center lg:items-end gap-6 shrink-0 pt-6 lg:pt-0 border-t lg:border-t-0 lg:border-l border-zinc-200 dark:border-white/10 lg:pl-10">
             <div className="flex items-center gap-8">
                <div className="text-right">
                   <p className="text-xs font-black uppercase tracking-widest opacity-40 mb-1">Threat Score</p>
                   <p className={`text-6xl font-black tracking-tighter ${
                     result.riskLevel === 'SAFE' ? 'text-emerald-500' :
                     result.riskLevel === 'SUSPICIOUS' ? 'text-amber-500' :
                     'text-rose-500'
                   }`}>{result.riskScore}<span className="text-xl opacity-20 ml-1">/100</span></p>
                </div>
                <div className="w-32 h-32">
                   <RiskGauge score={result.riskScore ?? 0} level={result.riskLevel} />
                </div>
             </div>
             
             <div className="w-full flex gap-3">
                {result.riskLevel === 'MALICIOUS' ? (
                  <div className="flex-1 px-8 py-5 bg-rose-600 hover:bg-rose-700 text-white rounded-2xl font-black text-sm uppercase tracking-widest text-center shadow-2xl shadow-rose-600/40 transition-all cursor-not-allowed flex items-center justify-center gap-3">
                    <ShieldX className="w-5 h-5" /> BLOCK LINK
                  </div>
                ) : (
                  <div className="flex-1 px-8 py-5 bg-emerald-600/10 dark:bg-emerald-500/10 border-2 border-emerald-500/20 text-emerald-600 dark:text-emerald-400 rounded-2xl font-black text-sm uppercase tracking-widest text-center">
                    SECURE DESTINATION
                  </div>
                )}
                {onRetry && (
                   <button 
                     onClick={onRetry}
                     className="p-5 bg-zinc-100 dark:bg-white/5 hover:bg-zinc-200 dark:hover:bg-white/10 border border-zinc-200 dark:border-white/10 rounded-2xl transition-all"
                   >
                     <RefreshCw className="w-5 h-5" />
                   </button>
                )}
             </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Agent Investigation Report */}
        {result.agentReport && (
          <div className="lg:col-span-2 glass-panel rounded-3xl p-8 dark:border-ornex-green/20 dark:bg-zinc-900/40 overflow-hidden relative">
            <div className="absolute top-0 right-0 p-4 opacity-10 pointer-events-none">
               <Bot className="w-32 h-32 text-cyber-light-accent dark:text-ornex-green" />
            </div>
            <div 
              className="flex items-center justify-between cursor-pointer group/agent"
              onClick={() => toggleSection('agentLog')}
            >
              <h3 className="text-sm font-bold text-cyber-light-heading dark:text-white flex items-center gap-2 uppercase tracking-[0.05em] border-l-[3px] border-cyber-light-accent pl-3 group-hover/agent:text-cyber-light-accent dark:group-hover/agent:text-ornex-green transition-colors">
                <span className="w-1.5 h-1.5 bg-cyber-light-accent dark:bg-ornex-green rounded-full animate-pulse"></span>
                Agent Investigation Log
              </h3>
              <div className="flex items-center gap-4">
                <div className="flex gap-2">
                  {result.agentReport.activeProbing?.reachable ? (
                     <span className="px-2 py-1 rounded-md bg-cyber-light-accent-bg dark:bg-emerald-500/10 text-cyber-light-accent-deep dark:text-ornex-green text-xs font-bold border border-cyber-light-accent/20">LIVE</span>
                  ) : (
                     <span className="px-2 py-1 rounded-md bg-zinc-500/10 text-zinc-500 text-xs font-bold border border-zinc-500/20">OFFLINE</span>
                  )}
                </div>
                <ChevronDown className={`w-5 h-5 text-zinc-400 transition-transform duration-300 ${expandedSections.has('agentLog') ? 'rotate-180' : ''}`} />
              </div>
            </div>

            <div className={`accordion-content ${expandedSections.has('agentLog') ? 'expanded' : 'collapsed'}`}>
              <div className="pt-6 pb-4 grid grid-cols-1 md:grid-cols-3 gap-6 items-start">
               {/* Active Probing Section */}
               <div className="space-y-3">
                  <InfoTip title="Active Probing" content="Real-time interaction with the URL to identify login forms and harvest behavior signatures.">
                    <div className="flex items-center gap-2 text-xs font-mono text-cyber-light-accent dark:text-ornex-green uppercase tracking-wider mb-1">
                      <Terminal className="w-4 h-4" />
                      <span>Active Probing</span>
                    </div>
                  </InfoTip>
                  <div className="bg-white dark:bg-zinc-900/80 backdrop-blur-md border border-zinc-200 dark:border-white/10 rounded-2xl p-5 pb-7 font-mono text-xs space-y-2 shadow-sm hover:shadow-md transition-all duration-300">
                     <div className="flex justify-between border-b border-cyber-light-border dark:border-white/10 pb-2 mb-2">
                        <span className="text-cyber-light-text dark:text-zinc-400">Form:</span>
                        <span className={result.agentReport.activeProbing?.loginFormFound ? "text-amber-500" : "text-zinc-400"}>
                          {result.agentReport.activeProbing?.loginFormFound ? "DETECTED" : "NONE"}
                        </span>
                     </div>
                      <div className="space-y-1">
                        <p className="text-zinc-500 dark:text-zinc-400 mb-1">Payload Trace:</p>
                        <p className="text-cyber-light-accent-code dark:text-ornex-green truncate bg-zinc-100 dark:bg-transparent px-2 py-0.5 rounded font-mono font-bold">
                          {result.agentReport?.activeProbing?.credentialsUsed || 'N/A'}
                        </p>
                      </div>
                     <div className="mt-2 pt-2 border-t border-cyber-light-border dark:border-white/10">
                        <p className="text-cyber-light-text dark:text-zinc-400 mb-1">Outcome:</p>
                        <p className={`font-bold ${result.agentReport.activeProbing?.behaviorRisk === 'HIGH' ? 'text-rose-500' : 'text-cyber-light-heading dark:text-zinc-300'}`}>
                           {result.agentReport.activeProbing?.outcome || 'Session Terminated'}
                        </p>
                     </div>
                  </div>
               </div>

               {/* Visual Forensics Section */}
               <div className="space-y-3">
                  <InfoTip title="Visual Analysis" content="Computer Vision analysis of page layout and branding to detect pixel-perfect impersonation.">
                    <div className="flex items-center gap-2 text-xs font-mono text-cyber-light-accent dark:text-ornex-green uppercase tracking-wider mb-1">
                      <Eye className="w-4 h-4" />
                      <span>Visual Forensic</span>
                    </div>
                  </InfoTip>
                  <div className="bg-white dark:bg-zinc-900/80 backdrop-blur-md border border-zinc-200 dark:border-white/10 rounded-2xl p-5 pb-7 font-mono text-xs space-y-2 shadow-sm hover:shadow-md transition-all duration-300">
                     <div className="flex justify-between border-b border-cyber-light-border dark:border-white/10 pb-2 mb-2">
                        <span className="text-cyber-light-text dark:text-zinc-400">AI Brand Match:</span>
                        <span className="text-cyber-light-heading dark:text-zinc-200">
                          {result.visual_forensics?.brand_match ? `${Math.round(result.visual_forensics.score * 100)}%` : '0%'}
                        </span>
                     </div>
                     <div className="space-y-1">
                        <p className="text-cyber-light-text dark:text-zinc-400 mb-1">Identity Guess:</p>
                        <p className="text-cyber-light-heading dark:text-zinc-200 font-bold uppercase tracking-tighter">
                          {result.visual_forensics?.brand_match || 'UNKNOWN'}
                        </p>
                     </div>
                     <div className="mt-2 pt-2 border-t border-cyber-light-border dark:border-white/10">
                        <p className="text-cyber-light-text dark:text-zinc-400 mb-1">Visual Evidence:</p>
                        <p className="text-cyber-light-heading dark:text-zinc-300">
                           {result.visual_forensics?.explanation || (
                             result.visual_forensics?.brand_match 
                               ? `Detected high-fidelity impersonation of ${result.visual_forensics.brand_match}` 
                               : "No significant visual impersonation detected."
                           )}
                        </p>
                      </div>
                  </div>
               </div>

               <div className="space-y-3">
                  <InfoTip title="Evidence Capture" content="Visual snapshot of the target page taken during active probing to detect UI redress or impersonation.">
                    <div className="flex items-center gap-2 text-xs font-mono text-cyber-light-accent dark:text-ornex-green uppercase tracking-wider mb-1">
                       <ImageIcon className="w-4 h-4" />
                       <span>Evidence Capture</span>
                    </div>
                  </InfoTip>
                   <div className="relative group/screenshot overflow-hidden rounded-xl border border-zinc-200 dark:border-white/10 bg-zinc-100 dark:bg-zinc-900/50 aspect-video cursor-zoom-in">
                    {(() => {
                      const screenshotPath = result.agentReport?.activeProbing?.screenshotPath || result.visual_forensics?.screenshot_path;
                      
                      if (screenshotPath) {
                        return (
                          <img 
                            src={`${API_BASE_URL}/${screenshotPath.replace(/^\//, '')}`} 
                            alt="Phishing Page Screenshot"
                            className="w-full h-full object-cover object-top opacity-90 group-hover/screenshot:opacity-100 transition-opacity"
                            onClick={() => setIsImageModalOpen(true)}
                            onError={(e) => {
                              (e.target as HTMLImageElement).src = `https://placehold.co/600x400/18181b/71717a?text=Evidence+Render+Failed`;
                            }}
                          />
                        );
                      }
                      
                      return (
                        <div className="w-full h-full flex flex-col items-center justify-center gap-2 bg-[repeating-linear-gradient(45deg,transparent,transparent_10px,rgba(255,255,255,0.05)_10px,rgba(255,255,255,0.05)_20px)] dark:bg-[repeating-linear-gradient(45deg,transparent,transparent_10px,rgba(255,255,255,0.02)_10px,rgba(255,255,255,0.02)_20px)] border-2 border-dashed border-zinc-300 dark:border-white/20 animate-pulse-slow">
                          <ImageIcon className="w-8 h-8 text-zinc-400 dark:text-zinc-500 opacity-50" />
                          <div className="text-center">
                            <span className="text-[11px] uppercase font-bold tracking-widest text-zinc-500 dark:text-zinc-400 block">No Screenshot Captured</span>
                            <span className="text-[9px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Selective Vision Skip or Timeout</span>
                          </div>
                        </div>
                      );
                    })()}
                    <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent opacity-0 group-hover/screenshot:opacity-100 transition-opacity flex items-end p-3 pointer-events-none">
                      <p className="text-[11px] text-white font-mono flex items-center gap-1">
                        <ExternalLink className="w-3 h-3" /> CLICK TO VIEW FULLSCREEN
                      </p>
                    </div>
                  </div>
               </div>
              </div>
            </div>
          </div>
        )}

        {/* Right Column: Technical Details Section */}
        <div className="space-y-6">
          <div className="glass-panel rounded-3xl p-8 dark:border-white/10 transition-colors">
            <div 
              className="flex items-center justify-between cursor-pointer group/tech"
              onClick={() => toggleSection('technical')}
            >
              <h3 className="text-sm font-bold text-cyber-light-heading dark:text-white flex items-center gap-2 uppercase tracking-[0.05em] border-l-[3px] border-purple-500 pl-3 group-hover/tech:text-purple-500 transition-colors">
                <span className="w-1.5 h-1.5 bg-purple-500 rounded-full"></span>
                Technical Analysis
              </h3>
              <ChevronDown className={`w-5 h-5 text-zinc-400 transition-transform duration-300 ${expandedSections.has('technical') ? 'rotate-180' : ''}`} />
            </div>

            <div className={`accordion-content ${expandedSections.has('technical') ? 'expanded' : 'collapsed'}`}>
              <div className="pt-6 space-y-5">
              {(() => {
                const cleanText = (text: string) => text || "Data unavailable for this analysis stage.";
                return (
                  <>
                    <div>
                      <InfoTip title="URL Analysis" content="Checks for typosquatting, suspicious subdomains, and long encoded tokens.">
                        <div className="flex items-center gap-2 text-xs font-mono text-cyber-light-text dark:text-zinc-400 mb-2 uppercase tracking-wider">
                          <Globe className="w-3 h-3" />
                          <span>URL Structure</span>
                        </div>
                      </InfoTip>
                      <p className="text-sm text-cyber-light-heading dark:text-zinc-100 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-md p-5 rounded-2xl border border-cyber-light-border dark:border-white/5 font-mono shadow-sm hover:shadow-md transition-all duration-300 break-words whitespace-pre-wrap">
                        {cleanText(result.technicalDetails?.urlStructure)}
                      </p>
                    </div>

                    <div>
                      <InfoTip title="Trust Signals" content="Verification against global threat feeds and historical domain age/stability.">
                        <div className="flex items-center gap-2 text-xs font-mono text-cyber-light-text dark:text-zinc-400 mb-2 uppercase tracking-wider">
                          <ShieldCheck className="w-3 h-3" />
                          <span>Domain Reputation</span>
                        </div>
                      </InfoTip>
                      <p className="text-sm text-cyber-light-heading dark:text-zinc-100 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-md p-5 rounded-2xl border border-cyber-light-border dark:border-white/5 font-mono shadow-sm hover:shadow-md transition-all duration-300 break-words whitespace-pre-wrap">
                        {cleanText(result.technicalDetails?.domainReputation)}
                      </p>
                    </div>

                    <div>
                      <InfoTip title="Hook Detection" content="Identifies linguistic pressure (Urgency, Financial) used to manipulate users.">
                        <div className="flex items-center gap-2 text-xs font-mono text-cyber-light-text dark:text-zinc-400 mb-2 uppercase tracking-wider">
                          <AlertTriangle className="w-3 h-3" />
                          <span>Social Engineering</span>
                        </div>
                      </InfoTip>
                      <p className="text-sm text-cyber-light-heading dark:text-zinc-100 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-md p-5 rounded-2xl border border-cyber-light-border dark:border-white/5 font-mono shadow-sm hover:shadow-md transition-all duration-300 break-words whitespace-pre-wrap">
                        {cleanText(result.technicalDetails?.socialEngineeringTricks)}
                      </p>
                    </div>
                  </>
                );
              })()}
              </div>
            </div>
          </div>


        </div>

        {/* Right Column: Advice & Findings */}
        <div className="space-y-6">
          <div className="glass-panel rounded-3xl p-8 dark:border-white/10 transition-colors">
            <div 
              className="flex items-center justify-between cursor-pointer group/findings"
              onClick={() => toggleSection('findings')}
            >
              <h3 className="text-sm font-bold text-cyber-light-heading dark:text-white flex items-center gap-2 uppercase tracking-[0.05em] border-l-[3px] border-blue-500 pl-3 group-hover/findings:text-blue-500 transition-colors">
                <span className="w-1.5 h-1.5 bg-blue-500 rounded-full"></span>
                Findings & Advice
              </h3>
              <ChevronDown className={`w-5 h-5 text-zinc-400 transition-transform duration-300 ${expandedSections.has('findings') ? 'rotate-180' : ''}`} />
            </div>

            <div className={`accordion-content ${expandedSections.has('findings') ? 'expanded' : 'collapsed'}`}>
              <div className="pt-6 space-y-6">
                 {/* Key Findings */}
                 <div className="rounded-2xl p-6 bg-white/50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-white/5 relative overflow-hidden">
                   <div className="absolute top-0 right-0 p-3 opacity-5 pointer-events-none">
                       <Activity className="w-24 h-24" />
                   </div>
                   <h4 className="text-xs font-bold text-cyber-light-heading dark:text-white flex items-center gap-2 mb-4 uppercase tracking-[0.05em] opacity-80">
                     Core Forensic Indicators
                   </h4>
             <ul className="space-y-4">
               {result.reasoning && result.reasoning.length > 0 ? (
                 result.reasoning.map((reason, idx) => (
                   <li key={idx} className="flex items-start gap-4 text-cyber-light-text dark:text-zinc-300 group/finding">
                     <ArrowRight className="w-4 h-4 text-cyber-light-text/50 dark:text-zinc-600 mt-1 flex-shrink-0 group-hover/finding:text-cyber-light-accent dark:group-hover/finding:text-ornex-green transition-colors" />
                     <span className="text-sm leading-relaxed">{reason}</span>
                   </li>
                 ))
               ) : (
                 <li className="text-sm text-cyber-light-text/50 italic">No reasoning data available for this record.</li>
               )}
                 </ul>
               </div>

               {/* Advice */}
                <div className="rounded-2xl p-6 border border-cyber-light-accent/30 bg-cyber-light-accent/5 dark:bg-zinc-900/40 shadow-[0_0_40px_rgba(0,200,83,0.05)] relative overflow-hidden">
                  <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none">
                     <ShieldCheck className="w-24 h-24 text-cyber-light-accent" />
                  </div>
                  <h4 className="text-xs font-bold text-cyber-light-accent-deep dark:text-ornex-green flex items-center gap-2 mb-4 uppercase tracking-[0.05em] opacity-90">
                    <ShieldCheck className="w-4 h-4" />
                    Mitigation Advice
                  </h4>
              <div className="grid grid-cols-1 gap-4">
                 {(result.mitigationAdvice && result.mitigationAdvice.length > 0) ? result.mitigationAdvice.map((advice, idx) => (
                   <div key={idx} className="flex items-start gap-3 p-4 rounded-2xl bg-white/60 dark:bg-zinc-900/60 border border-cyber-light-accent/30 backdrop-blur-md shadow-sm">
                      <div className="w-6 h-6 rounded-full bg-cyber-light-accent/10 dark:bg-ornex-green/10 flex items-center justify-center flex-shrink-0 text-cyber-light-accent dark:text-ornex-green font-bold text-xs">
                         {idx + 1}
                      </div>
                      <p className="text-sm text-cyber-light-text dark:text-zinc-300 leading-snug">
                         {advice}
                      </p>
                   </div>
                 )) : (
                    <div className="flex items-center gap-3 p-4 rounded-2xl bg-white/60 dark:bg-zinc-900/60 border border-cyber-light-accent/30 backdrop-blur-md shadow-sm">
                      <Info className="w-4 h-4 text-cyber-light-accent" />
                      <p className="text-sm text-cyber-light-text/70 italic">No specific mitigation required at this time.</p>
                    </div>
                 )}
               </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

      {/* Image Modal */}
      {isImageModalOpen && result.agentReport?.activeProbing?.screenshotPath && createPortal(
        <div 
          className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/95 backdrop-blur-sm p-4 md:p-8"
          onClick={() => setIsImageModalOpen(false)}
        >
          {/* Close Button - Truly fixed to the viewport */}
          <button 
            className="fixed top-6 right-6 z-[10000] p-3 rounded-full bg-white/10 hover:bg-white/20 text-white transition-colors backdrop-blur-md border border-white/10 shadow-xl cursor-pointer"
            onClick={(e) => { e.stopPropagation(); setIsImageModalOpen(false); }}
            title="Close Preview"
          >
            <X className="w-6 h-6" />
          </button>
          
          {/* Scrollable Content Area */}
          <div 
            className="w-full max-w-6xl max-h-full overflow-y-auto custom-scrollbar animate-in zoom-in-95 duration-300 rounded-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <img 
              src={`${API_BASE_URL}/${result.agentReport?.activeProbing?.screenshotPath.replace(/^\//, '')}`} 
              alt="Fullscreen Evidence Screenshot"
              className="w-full h-auto rounded-xl shadow-[0_0_50px_rgba(0,0,0,0.5)] border border-white/5 cursor-default"
            />
          </div>
        </div>,
        document.body
      )}
    </div>
  );
});

ResultDetails.displayName = 'ResultDetails';
