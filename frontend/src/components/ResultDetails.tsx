import React, { memo, useState } from 'react';
import { createPortal } from 'react-dom';
import type { AnalysisResult } from '../types';
import { 
  ShieldCheck, ShieldX, Activity, Globe, AlertTriangle, 
  ExternalLink, ArrowRight, Bot, Eye, Terminal, Image as ImageIcon, Info, X, ChevronDown, RefreshCw,
  ChevronLeft, ChevronRight
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
  const [activeScreenshotIndex, setActiveScreenshotIndex] = useState(0);

  // Consolidate all possible screenshot sources into a single deduplicated list
  const allScreenshots = React.useMemo(() => {
    const activeProbing = result.agentReport?.activeProbing;
    const sources = [
      ...(activeProbing?.screenshots || []),
      ...(activeProbing?.screenshotPath ? [activeProbing.screenshotPath] : []),
      ...(result.visual_forensics?.screenshot_path ? [result.visual_forensics.screenshot_path] : [])
    ].filter(Boolean) as string[];
    
    // Use Set to remove duplicates while preserving order
    return Array.from(new Set(sources));
  }, [result]);

  // Reset screenshot index when viewing a new result
  React.useEffect(() => {
    setActiveScreenshotIndex(0);
  }, [result.url]);

  // Handle keyboard navigation for modal
  React.useEffect(() => {
    if (!isImageModalOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'ArrowRight') {
        setActiveScreenshotIndex(prev => (prev < allScreenshots.length - 1 ? prev + 1 : prev));
      } else if (e.key === 'ArrowLeft') {
        setActiveScreenshotIndex(prev => (prev > 0 ? prev - 1 : prev));
      } else if (e.key === 'Escape') {
        setIsImageModalOpen(false);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isImageModalOpen, allScreenshots]);

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

      {/* Sentinel Recommendation Banner */}
      <div className={`p-5 sm:p-6 rounded-2xl sm:rounded-[2rem] border-2 flex flex-col sm:flex-row items-center sm:items-start gap-4 sm:gap-5 transition-all duration-700 shadow-[0_20px_50px_rgba(0,0,0,0.05)] dark:shadow-[0_20px_50px_rgba(0,0,0,0.1)] relative overflow-hidden group ${
        result.riskLevel === 'SAFE' ? 'bg-cyber-light-accent/5 dark:bg-[#062e19]/90 border-cyber-light-accent/30 dark:border-emerald-500/30 shadow-cyber-light-accent/5' :
        result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-50 dark:bg-[#2e1d06]/90 border-amber-500/30 dark:border-amber-500/30 shadow-amber-500/5' :
        result.riskLevel === 'MALICIOUS' ? 'bg-rose-50 dark:bg-[#2e0606]/90 border-rose-500/30 dark:border-rose-500/30 shadow-rose-500/10 active-hazard-glow' :
        'bg-zinc-50 dark:bg-zinc-950 border-zinc-200 dark:border-zinc-500/30'
      }`}>
        {/* Animated background pulse for high risk */}
        {result.riskLevel === 'MALICIOUS' && (
          <div className="absolute inset-0 bg-rose-500/5 animate-pulse" />
        )}
        <div className="absolute inset-0 bg-gradient-to-br from-white/20 via-transparent to-transparent opacity-50" />
        
        <div className={`p-3 sm:p-4 rounded-xl sm:rounded-2xl flex-shrink-0 shadow-lg ${
          result.riskLevel === 'SAFE' ? 'bg-cyber-light-accent/10 dark:bg-emerald-500/20 text-cyber-light-accent-deep dark:text-emerald-400 border border-cyber-light-accent/20' :
          result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-500/10 dark:bg-amber-500/20 text-amber-700 dark:text-amber-400 border border-amber-500/20' :
          result.riskLevel === 'MALICIOUS' ? 'bg-rose-500/10 dark:bg-rose-500/20 text-rose-700 dark:text-rose-400 border border-rose-500/20' :
          'bg-zinc-100 dark:bg-zinc-500/20 text-zinc-600 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-500/20'
        }`}>
          {result.riskLevel === 'SAFE' ? <ShieldCheck className="w-6 h-6 sm:w-7 sm:h-7" /> :
           result.riskLevel === 'SUSPICIOUS' ? <AlertTriangle className="w-6 h-6 sm:w-7 sm:h-7" /> :
           result.riskLevel === 'MALICIOUS' ? <ShieldX className="w-6 h-6 sm:w-7 sm:h-7" /> :
           <Activity className="w-6 h-6 sm:w-7 sm:h-7" />}
        </div>
        
        <div className="flex-1 relative z-10 text-center sm:text-left">
          <p className={`text-[10px] sm:text-[11px] font-bold font-tektur uppercase tracking-[0.3em] mb-1.5 sm:mb-2.5 ${
            result.riskLevel === 'SAFE' ? 'text-cyber-light-accent-deep dark:text-emerald-500/90' :
            result.riskLevel === 'SUSPICIOUS' ? 'text-amber-700 dark:text-amber-500/90' :
            result.riskLevel === 'MALICIOUS' ? 'text-rose-700 dark:text-rose-500/90' :
            'text-zinc-500'
          }`}>
            Forensic Findings & Conclusion
          </p>
          <h2 className="text-lg sm:text-xl md:text-2xl font-bold font-tektur tracking-tight text-zinc-900 dark:text-white/90 leading-tight mb-2 sm:mb-2.5">
            {result.riskLevel === 'SAFE' ? (
               result.agentReport?.activeProbing?.reachable === false 
                 ? 'SAFE TO IGNORE - TARGET OFFLINE' 
                 : 'PROCEED - VERIFIED SAFE'
             ) :
             result.riskLevel === 'SUSPICIOUS' ? 'PROCEED WITH CAUTION' :
             result.riskLevel === 'MALICIOUS' ? (
               result.agentReport?.activeProbing?.reachable === false 
                 ? 'DORMANT THREAT - DO NOT OPEN' 
                 : 'DANGEROUS - DO NOT OPEN'
             ) :
             'INCONCLUSIVE - REVIEW REQUIRED'}
          </h2>
          <p className="text-[12px] sm:text-[13.5px] font-semibold text-zinc-700 dark:text-white/60 leading-relaxed tracking-wide">
             {result.riskLevel === 'SAFE' ? 
               (result.agentReport?.activeProbing?.reachable === false 
                 ? 'This domain is currently unreachable and poses no active threat to your systems.' 
                 : 'Our forensic engines have cleared this target. No malicious intent or brand impersonation was detected.') :
              result.riskLevel === 'SUSPICIOUS' ? 'Advanced heuristics detected structural anomalies. Verify the destination and sender before proceeding.' :
              result.riskLevel === 'MALICIOUS' ? 
               (result.agentReport?.activeProbing?.reachable === false 
                 ? 'This is a confirmed malicious domain that is currently offline. Do not attempt to visit if it returns online.' 
                 : 'PhishGuard identifies this as an active phishing trap. Accessing this link will compromise your security.') :
              'Forensic signal fusion is incomplete due to engine timeouts. A manual review of technical details is recommended.'}
          </p>
        </div>
      </div>

      {/* Unified Action-Oriented Forensic Header - PREMIUM DESIGN OVERHAUL */}
      {!hideHeader && (
        <div className={`group relative p-5 sm:p-8 rounded-3xl sm:rounded-[2.5rem] border shadow-2xl overflow-hidden transition-all duration-500 hover:shadow-[0_32px_64px_-16px_rgba(0,0,0,0.15)] ${
          result.riskLevel === 'SAFE' ? 'bg-cyber-light-accent/5 dark:bg-emerald-500/10 border-cyber-light-accent/20 dark:border-emerald-500/30' :
          result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-50 dark:bg-amber-500/10 border-amber-500/30' :
          result.riskLevel === 'MALICIOUS' ? 'bg-rose-50 dark:bg-rose-500/10 border-rose-500/30' :
          'bg-zinc-50 dark:bg-zinc-500/10 border-zinc-200 dark:border-zinc-500/20'
        }`}>
          {/* Decorative background element */}
          <div className="absolute top-0 right-0 w-64 h-64 bg-current opacity-[0.05] rounded-full -mr-32 -mt-32 blur-3xl pointer-events-none" />
          
          <div className="flex flex-col lg:flex-row items-center justify-between gap-6 sm:gap-10 relative z-10">
            <div className="flex flex-col md:flex-row items-center md:items-start gap-6 sm:gap-8 flex-1 w-full">
              {/* Dynamic Icon Signature */}
              <div className="relative group/icon shrink-0">
                <div className={`absolute inset-0 blur-2xl opacity-40 group-hover/icon:opacity-60 transition-opacity duration-700 ${
                  result.riskLevel === 'SAFE' ? 'bg-emerald-500' :
                  result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-500' :
                  result.riskLevel === 'MALICIOUS' ? 'bg-rose-500' :
                  'bg-zinc-500'
                }`} />
                <div className={`w-16 h-16 sm:w-20 sm:h-20 rounded-2xl sm:rounded-3xl flex items-center justify-center border-2 backdrop-blur-xl relative z-10 transition-transform duration-500 group-hover/icon:scale-110 group-hover/icon:rotate-3 shadow-2xl ${
                  result.riskLevel === 'SAFE' ? 'bg-cyber-light-accent/10 border-cyber-light-accent/40 text-cyber-light-accent-deep dark:text-emerald-500 shadow-cyber-light-accent/10' :
                  result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-500/10 border-amber-500/40 text-amber-700 dark:text-amber-400 border-amber-500/20 shadow-amber-500/20' :
                  result.riskLevel === 'MALICIOUS' ? 'bg-rose-500/10 border-rose-500/40 text-rose-700 dark:text-rose-500 shadow-rose-500/20 active-hazard-glow' :
                  'bg-zinc-500/10 border-zinc-500/40 text-zinc-500'
                }`}>
                  {result.riskLevel === 'SAFE' ? <ShieldCheck className="w-8 h-8 sm:w-10 sm:h-10" /> :
                   result.riskLevel === 'SUSPICIOUS' ? <AlertTriangle className="w-8 h-8 sm:w-10 sm:h-10" /> :
                   result.riskLevel === 'MALICIOUS' ? <ShieldX className="w-8 h-8 sm:w-10 sm:h-10" /> :
                   <Activity className="w-8 h-8 sm:w-10 sm:h-10" />}
                </div>
              </div>
              
              <div className="space-y-3 sm:space-y-4 text-center md:text-left flex-1 min-w-0">
                <div className="flex flex-wrap items-center justify-center md:justify-start gap-2 sm:gap-3">
                  <div className="inline-flex items-center gap-2 px-3 sm:px-3.5 py-1 sm:py-1.5 rounded-full border border-current/20 bg-current/5 backdrop-blur-md">
                    <span className={`w-1.5 h-1.5 rounded-full animate-pulse ${
                      result.riskLevel === 'SAFE' ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]' :
                      result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.6)]' :
                      result.riskLevel === 'MALICIOUS' ? 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]' :
                      'bg-zinc-500'
                    }`} />
                    <span className={`text-[9px] sm:text-[10.5px] font-bold font-tektur uppercase tracking-[0.2em] sm:tracking-[0.3em] ${
                      result.riskLevel === 'SAFE' ? 'text-emerald-700 dark:text-emerald-400' :
                      result.riskLevel === 'SUSPICIOUS' ? 'text-amber-700 dark:text-amber-400' :
                      result.riskLevel === 'MALICIOUS' ? 'text-rose-700 dark:text-rose-400' :
                      'text-zinc-700 dark:text-zinc-400'
                    }`}>
                      Forensic Target Analysis
                    </span>
                  </div>

                  {/* Moved Pill to Left */}
                  <div className={`px-3 sm:px-4 py-1 sm:py-1.5 rounded-full font-bold font-tektur text-[8px] sm:text-[10px] uppercase tracking-[0.2em] sm:tracking-[0.25em] border shadow-sm ${
                    result.riskLevel === 'MALICIOUS' ? 'bg-rose-600/10 border-rose-500/30 text-rose-700 dark:text-rose-400' :
                    result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-500/10 border-amber-500/30 text-amber-700 dark:text-amber-400' :
                    'bg-cyber-light-accent/10 border-cyber-light-accent/30 text-cyber-light-accent-deep dark:text-emerald-400'
                  }`}>
                    {result.riskLevel === 'MALICIOUS' ? 'THREAT DETECTED' :
                     result.riskLevel === 'SUSPICIOUS' ? 'SUSPICIOUS TARGET' :
                     'SECURE DESTINATION'}
                  </div>
                </div>
                
                <div className="space-y-2 sm:space-y-3">
                  <h1 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl font-bold font-tektur tracking-tight uppercase leading-tight text-zinc-900 dark:text-white/90 group-hover:tracking-normal transition-all duration-700 drop-shadow-sm">
                    {result.verdictTitle}
                  </h1>
                  <div className="flex items-center justify-center md:justify-start gap-2.5 opacity-60 group-hover:opacity-100 transition-all duration-300">
                    <Globe className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-zinc-500 dark:text-zinc-400" />
                    <p className="text-[11px] sm:text-[12.5px] font-mono font-bold text-zinc-600 dark:text-zinc-300 truncate max-w-[280px] sm:max-w-xl tracking-tighter">
                      {result.url}
                    </p>
                  </div>

                  {result.functional_description && (
                    <div className="mt-4 sm:mt-6 flex gap-3 sm:gap-4 max-w-2xl mx-auto md:mx-0 group/purpose">
                      <div className="w-1 rounded-full bg-gradient-to-b from-purple-500/50 to-transparent shrink-0" />
                      <div className="flex-1 text-left">
                        <p className="text-[12px] sm:text-[14px] font-medium leading-relaxed text-zinc-600 dark:text-zinc-300 italic">
                          "{result.functional_description}"
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Score Sector */}
            <div className="flex flex-col items-center justify-center shrink-0 w-full lg:w-auto pt-6 sm:pt-8 lg:pt-0 border-t lg:border-t-0 lg:border-l border-zinc-200 dark:border-white/5 lg:pl-12 gap-6 sm:gap-8">
              <div className="relative group/gauge">
                <div className="absolute inset-0 bg-current opacity-[0.03] blur-2xl rounded-full scale-150 group-hover/gauge:opacity-[0.06] transition-opacity" />
                <div className="scale-110 sm:scale-125 origin-center transition-transform duration-700 group-hover/gauge:scale-135">
                  <RiskGauge score={result.riskScore ?? 0} level={result.riskLevel} />
                </div>
              </div>
              
              <div className="flex flex-col gap-3 w-full sm:min-w-[200px]">
                
                {onRetry && (
                  <button 
                    onClick={onRetry}
                    className="w-full py-2.5 sm:py-3 bg-zinc-200/50 dark:bg-white/5 hover:bg-zinc-200 dark:hover:bg-white/10 border border-zinc-300 dark:border-white/10 rounded-xl sm:rounded-2xl transition-all flex items-center justify-center gap-2.5 text-[9px] sm:text-[10px] font-black uppercase tracking-[0.15em] text-zinc-600 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-white"
                  >
                    <RefreshCw className="w-3.5 h-3.5 transition-transform duration-700 group-hover:rotate-180" /> RE-SCAN TARGET
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">

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
                  {result.agentReport?.activeProbing?.reachable ? (
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
                   <InfoTip title="Active Probing" content="Real-time interaction with the target to identify behavior signatures and forensic anomalies.">
                     <div className="flex items-center gap-2 text-xs font-mono text-cyber-light-accent dark:text-ornex-green uppercase tracking-wider mb-1">
                       <Terminal className="w-4 h-4" />
                       <span>Active Probing</span>
                     </div>
                   </InfoTip>
                   <div className="bg-cyber-light-bg dark:bg-zinc-900/80 backdrop-blur-md border border-zinc-200 dark:border-white/10 rounded-2xl p-5 pb-7 font-mono text-xs space-y-2 shadow-sm hover:shadow-md transition-all duration-300">
                      <div className="flex justify-between border-b border-cyber-light-border dark:border-white/10 pb-2 mb-2">
                         <span className="text-cyber-light-text dark:text-zinc-400">Trace:</span>
                         <span className="text-cyber-light-accent-code dark:text-ornex-green truncate bg-zinc-100 dark:bg-transparent px-2 py-0.5 rounded font-mono font-bold">
                           {result.agentReport?.activeProbing?.credentialsUsed || 'N/A'}
                         </span>
                      </div>
                      <div className="mt-2 pt-2 border-t border-cyber-light-border dark:border-white/10">
                         <p className="text-cyber-light-text dark:text-zinc-400 mb-1">Outcome:</p>
                         <p className={`text-[11px] leading-relaxed font-bold break-words ${result.agentReport?.activeProbing?.behaviorRisk === 'HIGH' ? 'text-rose-500' : 'text-cyber-light-heading dark:text-zinc-300'}`}>
                            {result.agentReport?.activeProbing?.outcome || 'Session Terminated'}
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
                  <div className="bg-cyber-light-bg dark:bg-zinc-900/80 backdrop-blur-md border border-zinc-200 dark:border-white/10 rounded-2xl p-5 pb-7 font-mono text-xs space-y-2 shadow-sm hover:shadow-md transition-all duration-300">
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
                               ? `Detected ${result.visual_forensics.brand_match} branding on the page.` 
                               : "No significant brand signatures detected visually."
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
                   <div className="relative group/screenshot overflow-hidden rounded-xl border border-zinc-200 dark:border-white/10 bg-zinc-100 dark:bg-zinc-900/50 aspect-video">
                    {(() => {
                      const screenshotPath = allScreenshots[activeScreenshotIndex];
                      
                      if (screenshotPath) {
                        return (
                          <>
                            <div className="relative w-full h-full group/main-img">
                              <img 
                                src={`${API_BASE_URL}/${screenshotPath.replace(/^\//, '')}`} 
                                alt={`Phishing Page Screenshot ${activeScreenshotIndex + 1}`}
                                className="w-full h-full object-cover object-top opacity-90 hover:opacity-100 transition-opacity cursor-zoom-in"
                                onClick={() => setIsImageModalOpen(true)}
                                onError={(e) => {
                                  (e.target as HTMLImageElement).src = `https://placehold.co/600x400/18181b/71717a?text=Evidence+Render+Failed`;
                                }}
                              />

                              {/* Navigation Arrows */}
                              {allScreenshots.length > 1 && (
                                <>
                                  <button 
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      if (activeScreenshotIndex > 0) setActiveScreenshotIndex(prev => prev - 1);
                                    }}
                                    disabled={activeScreenshotIndex === 0}
                                    className={`absolute left-2 top-1/2 -translate-y-1/2 p-2 rounded-full bg-black/40 hover:bg-black/80 text-white opacity-0 group-hover/main-img:opacity-100 transition-all backdrop-blur-sm border border-white/10 ${activeScreenshotIndex === 0 ? 'cursor-not-allowed opacity-0' : 'cursor-pointer'}`}
                                  >
                                    <ChevronLeft className="w-4 h-4" />
                                  </button>
                                  <button 
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      if (activeScreenshotIndex < allScreenshots.length - 1) setActiveScreenshotIndex(prev => prev + 1);
                                    }}
                                    disabled={activeScreenshotIndex === allScreenshots.length - 1}
                                    className={`absolute right-2 top-1/2 -translate-y-1/2 p-2 rounded-full bg-black/40 hover:bg-black/80 text-white opacity-0 group-hover/main-img:opacity-100 transition-all backdrop-blur-sm border border-white/10 ${activeScreenshotIndex === allScreenshots.length - 1 ? 'cursor-not-allowed opacity-0' : 'cursor-pointer'}`}
                                  >
                                    <ChevronRight className="w-4 h-4" />
                                  </button>
                                </>
                              )}
                              
                              {/* Stage Label */}
                              <div className="absolute top-3 left-3 px-3 py-1 rounded-lg bg-cyber-light-accent dark:bg-ornex-green/90 text-white dark:text-black text-[9px] font-black uppercase tracking-[0.1em] shadow-[0_0_15px_rgba(0,200,83,0.3)] dark:shadow-[0_0_15px_rgba(57,255,20,0.4)] pointer-events-none">
                                {activeScreenshotIndex === 0 ? 'Initial Load' : 
                                 activeScreenshotIndex === allScreenshots.length - 1 ? 'Final State' : 
                                 `Submission Step ${activeScreenshotIndex}`}
                              </div>
                            </div>

                            {/* Thumbnail Gallery (Stacked) */}
                            {allScreenshots.length > 1 && (
                              <div className="flex gap-2 mt-3 overflow-x-auto pb-1 scrollbar-thin scrollbar-thumb-white/10">
                                {allScreenshots.map((s, idx) => (
                                  <button
                                    key={idx}
                                    onClick={() => setActiveScreenshotIndex(idx)}
                                    className={`relative flex-shrink-0 w-20 aspect-video rounded-lg overflow-hidden border-2 transition-all ${
                                      activeScreenshotIndex === idx 
                                        ? 'border-cyber-light-accent dark:border-ornex-green ring-2 ring-cyber-light-accent/20 dark:ring-ornex-green/20' 
                                        : 'border-white/5 hover:border-white/20 opacity-60 hover:opacity-100'
                                    }`}
                                  >
                                    <img 
                                      src={`${API_BASE_URL}/${s.replace(/^\//, '')}`} 
                                      className="w-full h-full object-cover"
                                      alt={`Stage ${idx}`}
                                    />
                                    <div className="absolute inset-0 bg-black/40 flex items-center justify-center">
                                      <span className="text-[8px] font-black text-white">{idx === 0 ? 'START' : idx === allScreenshots.length - 1 ? 'END' : idx}</span>
                                    </div>
                                  </button>
                                ))}
                              </div>
                            )}
                          </>
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

        {/* Details Grids */}
        <div className="lg:col-span-2 grid grid-cols-1 lg:grid-cols-2 gap-6 items-start w-full">
          {/* Technical Analysis Section */}
          <div className="glass-panel rounded-3xl p-5 sm:p-8 dark:border-white/10 transition-colors">
            <div 
              className="flex items-center justify-between cursor-pointer group/tech"
              onClick={() => toggleSection('technical')}
            >
              <h3 className="text-xs sm:text-sm font-bold text-cyber-light-heading dark:text-white flex items-center gap-2 uppercase tracking-[0.05em] border-l-[3px] border-purple-500 pl-3 group-hover/tech:text-purple-500 transition-colors">
                <span className="w-1.5 h-1.5 bg-purple-500 rounded-full"></span>
                Technical Analysis
              </h3>
              <ChevronDown className={`w-4 h-4 sm:w-5 sm:h-5 text-zinc-400 transition-transform duration-300 ${expandedSections.has('technical') ? 'rotate-180' : ''}`} />
            </div>

            <div className={`accordion-content ${expandedSections.has('technical') ? 'expanded' : 'collapsed'}`}>
              <div className="pt-6 space-y-5">
              {(() => {
                const cleanText = (text: string) => text || "Data unavailable for this analysis stage.";
                return (
                  <>
                    <div>
                      <InfoTip title="URL Analysis" content="Checks for typosquatting, suspicious subdomains, and long encoded tokens.">
                        <div className="flex items-center gap-2 text-[10px] sm:text-xs font-mono text-cyber-light-text dark:text-zinc-400 mb-2 uppercase tracking-wider">
                          <Globe className="w-3 h-3" />
                          <span>URL Structure</span>
                        </div>
                      </InfoTip>
                      <p className="text-xs sm:text-sm text-cyber-light-heading dark:text-zinc-100 bg-cyber-light-bg/80 dark:bg-zinc-900/80 backdrop-blur-md p-4 sm:p-5 rounded-xl sm:rounded-2xl border border-cyber-light-border dark:border-white/5 font-mono shadow-sm hover:shadow-md transition-all duration-300 break-words whitespace-pre-wrap">
                        {cleanText(result.technicalDetails?.urlStructure)}
                      </p>
                    </div>

                    <div>
                      <InfoTip title="Trust Signals" content="Verification against global threat feeds and historical domain age/stability.">
                        <div className="flex items-center gap-2 text-[10px] sm:text-xs font-mono text-cyber-light-text dark:text-zinc-400 mb-2 uppercase tracking-wider">
                          <ShieldCheck className="w-3 h-3" />
                          <span>Reputation</span>
                        </div>
                      </InfoTip>
                      <p className="text-xs sm:text-sm text-cyber-light-heading dark:text-zinc-100 bg-cyber-light-bg/80 dark:bg-zinc-900/80 backdrop-blur-md p-4 sm:p-5 rounded-xl sm:rounded-2xl border border-cyber-light-border dark:border-white/5 font-mono shadow-sm hover:shadow-md transition-all duration-300 break-words whitespace-pre-wrap">
                        {cleanText(result.technicalDetails?.domainReputation)}
                      </p>
                    </div>

                    <div>
                      <InfoTip title="Hook Detection" content="Identifies linguistic pressure (Urgency, Financial) used to manipulate users.">
                        <div className="flex items-center gap-2 text-[10px] sm:text-xs font-mono text-cyber-light-text dark:text-zinc-400 mb-2 uppercase tracking-wider">
                          <AlertTriangle className="w-3 h-3" />
                          <span>Social Eng.</span>
                        </div>
                      </InfoTip>
                      <p className="text-xs sm:text-sm text-cyber-light-heading dark:text-zinc-100 bg-cyber-light-bg/80 dark:bg-zinc-900/80 backdrop-blur-md p-4 sm:p-5 rounded-xl sm:rounded-2xl border border-cyber-light-border dark:border-white/5 font-mono shadow-sm hover:shadow-md transition-all duration-300 break-words whitespace-pre-wrap">
                        {cleanText(result.technicalDetails?.socialEngineeringTricks)}
                      </p>
                    </div>
                  </>
                );
              })()}
              </div>
            </div>
          </div>

          {/* Advice & Findings Section */}
          <div className="glass-panel rounded-3xl p-5 sm:p-8 dark:border-white/10 transition-colors">
            <div 
              className="flex items-center justify-between cursor-pointer group/findings"
              onClick={() => toggleSection('findings')}
            >
              <h3 className="text-xs sm:text-sm font-bold text-cyber-light-heading dark:text-white flex items-center gap-2 uppercase tracking-[0.05em] border-l-[3px] border-blue-500 pl-3 group-hover/findings:text-blue-500 transition-colors">
                <span className="w-1.5 h-1.5 bg-blue-500 rounded-full"></span>
                Findings & Advice
              </h3>
              <ChevronDown className={`w-4 h-4 sm:w-5 sm:h-5 text-zinc-400 transition-transform duration-300 ${expandedSections.has('findings') ? 'rotate-180' : ''}`} />
            </div>

            <div className={`accordion-content ${expandedSections.has('findings') ? 'expanded' : 'collapsed'}`}>
              <div className="pt-6 space-y-6">
                 {/* Key Findings */}
                 <div className="rounded-2xl p-5 sm:p-6 bg-cyber-light-bg/50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-white/5 relative overflow-hidden">
                   <div className="absolute top-0 right-0 p-3 opacity-5 pointer-events-none">
                       <Activity className="w-16 h-16 sm:w-24 sm:h-24" />
                   </div>
                   <h4 className="text-[10px] sm:text-xs font-bold text-cyber-light-heading dark:text-white flex items-center gap-2 mb-4 uppercase tracking-[0.05em] opacity-80">
                     Core Forensic Indicators
                   </h4>
                   <ul className="space-y-3 sm:space-y-4">
                     {result.reasoning && result.reasoning.length > 0 ? (
                       result.reasoning.map((reason, idx) => (
                         <li key={idx} className="flex items-start gap-3 sm:gap-4 text-cyber-light-text dark:text-zinc-300 group/finding">
                           <ArrowRight className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-cyber-light-text/50 dark:text-zinc-600 mt-0.5 sm:mt-1 flex-shrink-0 group-hover/finding:text-cyber-light-accent dark:group-hover/finding:text-ornex-green transition-colors" />
                           <span className="text-[12px] sm:text-sm leading-relaxed">{reason}</span>
                         </li>
                       ))
                     ) : (
                       <li className="text-xs sm:text-sm text-cyber-light-text/50 italic">No reasoning data available for this record.</li>
                     )}
                   </ul>
                 </div>

                 {/* Advice */}
                  <div className="rounded-2xl p-5 sm:p-6 border border-cyber-light-accent/30 bg-cyber-light-accent/5 dark:bg-zinc-900/40 shadow-[0_0_40px_rgba(0,200,83,0.05)] relative overflow-hidden">
                    <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none">
                       <ShieldCheck className="w-16 h-16 sm:w-24 sm:h-24 text-cyber-light-accent" />
                    </div>
                    <h4 className="text-[10px] sm:text-xs font-bold text-cyber-light-accent-deep dark:text-ornex-green flex items-center gap-2 mb-4 uppercase tracking-[0.05em] opacity-90">
                      <ShieldCheck className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                      Mitigation Advice
                    </h4>
                    <div className="grid grid-cols-1 gap-3 sm:gap-4">
                       {(result.mitigationAdvice && result.mitigationAdvice.length > 0) ? result.mitigationAdvice.map((advice, idx) => (
                         <div key={idx} className="flex items-start gap-3 p-3 sm:p-4 rounded-xl sm:rounded-2xl bg-cyber-light-bg/60 dark:bg-zinc-900/60 border border-cyber-light-accent/30 backdrop-blur-md shadow-sm">
                            <div className="w-5 h-5 sm:w-6 sm:h-6 rounded-full bg-cyber-light-accent/10 dark:bg-ornex-green/10 flex items-center justify-center flex-shrink-0 text-cyber-light-accent dark:text-ornex-green font-bold text-[10px] sm:text-xs">
                               {idx + 1}
                            </div>
                            <p className="text-[12px] sm:text-sm text-cyber-light-text dark:text-zinc-300 leading-snug">
                               {advice}
                            </p>
                         </div>
                       )) : (
                          <div className="flex items-center gap-3 p-4 rounded-xl bg-cyber-light-bg/60 dark:bg-zinc-900/60 border border-cyber-light-accent/30 backdrop-blur-md shadow-sm">
                            <Info className="w-4 h-4 text-cyber-light-accent" />
                            <p className="text-xs sm:text-sm text-cyber-light-text/70 italic">No specific mitigation required.</p>
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
        {isImageModalOpen && createPortal(
          <div 
            className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/95 backdrop-blur-sm p-4 md:p-8"
            onClick={() => setIsImageModalOpen(false)}
          >
            <button 
              className="fixed top-6 right-6 z-[10000] p-3 rounded-full bg-white/10 hover:bg-white/20 text-white transition-colors backdrop-blur-md border border-white/10 shadow-xl cursor-pointer"
              onClick={(e) => { e.stopPropagation(); setIsImageModalOpen(false); }}
              title="Close Preview"
            >
              <X className="w-6 h-6" />
            </button>
            
            <div 
              className="w-full max-w-6xl max-h-full overflow-y-auto custom-scrollbar animate-in zoom-in-95 duration-300 rounded-xl"
              onClick={(e) => e.stopPropagation()}
            >
              {(() => {
                
                const screenshotPath = allScreenshots[activeScreenshotIndex];
                
                if (!screenshotPath) return null;

                return (
                  <div className="relative group/modal-img">
                    <img 
                      src={`${API_BASE_URL}/${screenshotPath.replace(/^\//, '')}`} 
                      alt="Fullscreen Evidence Screenshot"
                      className="w-full h-auto rounded-xl shadow-[0_0_50px_rgba(0,0,0,0.5)] border border-white/5 cursor-default"
                    />
                    
                    {/* Modal Navigation Arrows */}
                    {allScreenshots.length > 1 && (
                      <>
                        <button 
                          onClick={(e) => {
                            e.stopPropagation();
                            if (activeScreenshotIndex > 0) setActiveScreenshotIndex(prev => prev - 1);
                          }}
                          disabled={activeScreenshotIndex === 0}
                          className={`fixed left-2 sm:left-8 top-1/2 -translate-y-1/2 p-3 sm:p-5 rounded-full bg-white/5 hover:bg-white/20 text-white transition-all backdrop-blur-md border border-white/10 shadow-2xl group ${activeScreenshotIndex === 0 ? 'opacity-10 cursor-not-allowed' : 'opacity-100 cursor-pointer'}`}
                          title="Previous (Left Arrow)"
                        >
                          <ChevronLeft className="w-6 h-6 sm:w-8 sm:h-8 group-hover:-translate-x-1 transition-transform" />
                        </button>
                        <button 
                          onClick={(e) => {
                            e.stopPropagation();
                            if (activeScreenshotIndex < allScreenshots.length - 1) setActiveScreenshotIndex(prev => prev + 1);
                          }}
                          disabled={activeScreenshotIndex === allScreenshots.length - 1}
                          className={`fixed right-2 sm:right-8 top-1/2 -translate-y-1/2 p-3 sm:p-5 rounded-full bg-white/5 hover:bg-white/20 text-white transition-all backdrop-blur-md border border-white/10 shadow-2xl group ${activeScreenshotIndex === allScreenshots.length - 1 ? 'opacity-10 cursor-not-allowed' : 'opacity-100 cursor-pointer'}`}
                          title="Next (Right Arrow)"
                        >
                          <ChevronRight className="w-6 h-6 sm:w-8 sm:h-8 group-hover:translate-x-1 transition-transform" />
                        </button>

                        {/* Modal Pagination Info */}
                        <div className="absolute bottom-4 sm:bottom-6 left-1/2 -translate-x-1/2 px-3 sm:px-4 py-1.5 sm:py-2 rounded-full bg-black/60 backdrop-blur-md border border-white/10 text-[10px] sm:text-xs font-bold text-white/90 tracking-widest flex items-center gap-3">
                           <span className="text-ornex-green">{activeScreenshotIndex + 1}</span>
                           <span className="opacity-30">/</span>
                           <span>{allScreenshots.length}</span>
                        </div>
                      </>
                    )}

                    {/* Modal Stage Label */}
                    <div className="absolute top-6 left-6 px-4 py-1.5 rounded-xl bg-cyber-light-accent dark:bg-ornex-green text-white dark:text-black text-[11px] font-black uppercase tracking-[0.2em] shadow-[0_0_30px_rgba(0,200,83,0.3)] dark:shadow-[0_0_30px_rgba(57,255,20,0.4)] pointer-events-none">
                      {activeScreenshotIndex === 0 ? 'Initial Load' : 
                       activeScreenshotIndex === allScreenshots.length - 1 ? 'Final State' : 
                       `Submission Step ${activeScreenshotIndex}`}
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>,
          document.body
        )}
      </div>

  );
});

ResultDetails.displayName = 'ResultDetails';
