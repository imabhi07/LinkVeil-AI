import React, { memo, useState } from 'react';
import { createPortal } from 'react-dom';
import type { AnalysisResult } from '../types';
import { 
  ShieldCheck, ShieldAlert, ShieldX, Activity, Globe, AlertTriangle, 
  ExternalLink, ArrowRight, Bot, Eye, Terminal, Zap, Image as ImageIcon, Info, X, ChevronDown
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

  const getIcon = () => {
    switch (result.riskLevel) {
      case 'SAFE': return <ShieldCheck className="w-10 h-10 text-emerald-500 dark:text-ornex-green" />;
      case 'SUSPICIOUS': return <ShieldAlert className="w-10 h-10 text-amber-500" />;
      case 'MALICIOUS': return <ShieldX className="w-10 h-10 text-rose-500" />;
      default: return <Activity className="w-10 h-10 text-zinc-500" />;
    }
  };

  const getBorderColor = () => {
    switch (result.riskLevel) {
      case 'SAFE': return 'border-emerald-200 dark:border-ornex-green/40 bg-emerald-50/50 dark:bg-zinc-900/50 shadow-[0_0_50px_rgba(16,185,129,0.15)] dark:shadow-[0_0_50px_rgba(57,255,20,0.1)]';
      case 'SUSPICIOUS': return 'border-amber-500/40 bg-amber-500/10 shadow-[0_0_50px_rgba(245,158,11,0.1)]';
      case 'MALICIOUS': return 'border-rose-500/40 bg-rose-500/10 shadow-[0_0_50px_rgba(244,63,94,0.1)]';
      default: return 'border-zinc-200 dark:border-white/20 bg-zinc-50 dark:bg-white/5 shadow-xl';
    }
  };

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

      {/* Dynamic Recommendation Header */}
      {!hideHeader && result.recommendation && (
        <div className={`p-5 rounded-2xl border flex items-center gap-4 animate-in slide-in-from-top-4 duration-500 backdrop-blur-md ${
          result.riskLevel === 'SAFE' ? 'bg-[#ECFDF5] border-[#D1FAE5] text-[#065F46] dark:bg-ornex-green/20 dark:border-ornex-green/30 dark:text-ornex-green' :
          result.riskLevel === 'SUSPICIOUS' ? 'bg-[#FFFBEB] border-[#FEF3C7] text-[#92400E] dark:bg-amber-500/25 dark:border-amber-500/40 dark:text-white' :
          result.riskLevel === 'MALICIOUS' ? 'bg-[#FEF2F2] border-[#FEE2E2] text-[#991B1B] dark:bg-rose-500/25 dark:border-rose-500/40 dark:text-white' :
          'bg-zinc-50 dark:bg-zinc-900/80 border-zinc-200 dark:border-white/10 text-zinc-600 dark:text-zinc-400'
        } shadow-sm shadow-black/5`}>
          <div className={`p-2.5 rounded-xl ${
            result.riskLevel === 'SAFE' ? 'bg-white/80 dark:bg-emerald-500/20' :
            result.riskLevel === 'SUSPICIOUS' ? 'bg-white/80 dark:bg-amber-500/20' :
            result.riskLevel === 'MALICIOUS' ? 'bg-white/80 dark:bg-rose-500/20' :
            'bg-white/80 dark:bg-zinc-500/20'
          } shadow-inner`}>
            {result.riskLevel === 'SAFE' ? <ShieldCheck className="w-5 h-5" /> :
             result.riskLevel === 'SUSPICIOUS' ? <AlertTriangle className="w-5 h-5" /> :
             result.riskLevel === 'MALICIOUS' ? <ShieldX className="w-5 h-5" /> :
             <Activity className="w-5 h-5" />}
          </div>
          <div>
            <p className="text-[11px] font-mono uppercase tracking-widest mb-0.5 dark:text-white/90 font-bold">Sentinel Recommendation</p>
            <p className="text-lg font-bold tracking-tight dark:text-white">{result.recommendation}</p>
          </div>
        </div>
      )}

      {/* Header Card */}
      {!hideHeader && (
        <div className={`p-8 rounded-3xl border glass-panel flex flex-col md:flex-row items-center justify-between gap-8 transition-all ${getBorderColor()}`}>
          <div className="flex items-center gap-6">
            <div className="p-4 rounded-2xl bg-white dark:bg-black shadow-lg border border-zinc-100 dark:border-white/10 transition-colors">
              {getIcon()}
            </div>
            <div>
              <div className="flex items-center gap-3 mb-1">
                <h2 className="text-xs font-bold text-cyber-light-text dark:text-zinc-300 uppercase tracking-widest">Analysis Verdict</h2>
                {result.riskLevel === 'UNKNOWN' && (
                  <span className="px-2 py-0.5 rounded border text-slate-500 dark:text-slate-400 border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-slate-900/20 font-black text-xs uppercase tracking-[0.12em] shadow-sm flex items-center gap-1.5">
                    <Globe className="w-2.5 h-2.5 opacity-50" />
                    Unknown
                  </span>
                )}
                {result.threat_intel?.is_known_malicious && (
                  <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-500 text-xs font-bold border border-rose-500/20 uppercase tracking-tighter animate-pulse">
                    <Zap className="w-3 h-3" />
                    Intel Match: {result.threat_intel.source}
                  </span>
                )}
              </div>
              <h1 className="text-3xl md:text-4xl font-bold text-cyber-light-heading dark:text-white tracking-tight uppercase">{result.verdictTitle || 'Unknown Verdict'}</h1>
              <p className="text-cyber-light-text dark:text-zinc-200 mt-2 font-mono text-xs break-all">{result.url}</p>
            </div>
          </div>
          <div className="flex-shrink-0">
            <RiskGauge score={result.riskScore ?? 0} level={result.riskLevel || 'UNKNOWN'} />
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
                           {result.visual_forensics?.brand_match 
                              ? `Detected high-fidelity impersonation of ${result.visual_forensics.brand_match}` 
                              : "No significant visual impersonation detected."}
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
                    {result.agentReport?.activeProbing?.screenshotPath ? (
                        <img 
                          src={`${API_BASE_URL}/${result.agentReport?.activeProbing?.screenshotPath.replace(/^\//, '')}`} 
                          alt="Phishing Page Screenshot"
                          className="w-full h-full object-cover object-top opacity-90 group-hover/screenshot:opacity-100 transition-opacity"
                          onClick={() => setIsImageModalOpen(true)}
                          onError={(e) => {
                            (e.target as HTMLImageElement).src = 'https://placehold.co/600x400/f4f4f5/71717a?text=Evidence+Load+Failed';
                          }}
                        />
                    ) : (
                      <div className="w-full h-full flex flex-col items-center justify-center gap-2 bg-[repeating-linear-gradient(45deg,transparent,transparent_10px,rgba(255,255,255,0.05)_10px,rgba(255,255,255,0.05)_20px)] dark:bg-[repeating-linear-gradient(45deg,transparent,transparent_10px,rgba(255,255,255,0.02)_10px,rgba(255,255,255,0.02)_20px)] border-2 border-dashed border-zinc-300 dark:border-white/20 animate-pulse-slow">
                        <ImageIcon className="w-8 h-8 text-zinc-400 dark:text-zinc-500 opacity-50" />
                        <div className="text-center">
                          <span className="text-[11px] uppercase font-bold tracking-widest text-zinc-500 dark:text-zinc-400 block">No Screenshot Captured</span>
                          <span className="text-[9px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Target not probed or failed</span>
                        </div>
                      </div>
                    )}
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
                      <p className="text-sm text-cyber-light-heading dark:text-zinc-100 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-md p-5 rounded-2xl border border-cyber-light-border dark:border-white/5 font-mono shadow-sm hover:shadow-md transition-all duration-300 break-all">
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
                      <p className="text-sm text-cyber-light-heading dark:text-zinc-100 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-md p-5 rounded-2xl border border-cyber-light-border dark:border-white/5 font-mono shadow-sm hover:shadow-md transition-all duration-300 break-words">
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
                      <p className="text-sm text-cyber-light-heading dark:text-zinc-100 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-md p-5 rounded-2xl border border-cyber-light-border dark:border-white/5 font-mono shadow-sm hover:shadow-md transition-all duration-300 break-words">
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
