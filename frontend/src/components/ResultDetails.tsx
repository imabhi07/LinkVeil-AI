import React, { memo } from 'react';
import type { AnalysisResult } from '../types';
import { ShieldCheck, ShieldAlert, ShieldX, Activity, Globe, AlertTriangle, ExternalLink, ArrowRight, Bot, Eye, Terminal } from 'lucide-react';
import { RiskGauge } from './RiskGauge';

interface ResultDetailsProps {
  result: AnalysisResult;
}

export const ResultDetails: React.FC<ResultDetailsProps> = memo(({ result }) => {
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
      case 'SAFE': return 'border-emerald-200 dark:border-ornex-green/30 bg-emerald-50/50 dark:bg-ornex-green/5 shadow-[0_0_30px_rgba(16,185,129,0.1)] dark:shadow-[0_0_30px_rgba(57,255,20,0.05)]';
      case 'SUSPICIOUS': return 'border-amber-500/30 bg-amber-500/5 shadow-[0_0_30px_rgba(245,158,11,0.05)]';
      case 'MALICIOUS': return 'border-rose-500/30 bg-rose-500/5 shadow-[0_0_30px_rgba(244,63,94,0.05)]';
      default: return 'border-zinc-200 dark:border-white/10 bg-zinc-50 dark:bg-white/5';
    }
  };

  return (
    <div className="w-full space-y-6">
      {/* Header Card */}
      <div className={`p-8 rounded-3xl border glass-panel flex flex-col md:flex-row items-center justify-between gap-8 transition-all ${getBorderColor()}`}>
        <div className="flex items-center gap-6">
          <div className="p-4 rounded-2xl bg-white dark:bg-black shadow-lg border border-zinc-100 dark:border-white/10 transition-colors">
            {getIcon()}
          </div>
          <div>
            <h2 className="text-xs font-bold text-zinc-500 dark:text-zinc-500 uppercase tracking-widest mb-1">Analysis Verdict</h2>
            <h1 className="text-3xl md:text-4xl font-bold text-zinc-900 dark:text-white tracking-tight uppercase">{result.verdictTitle}</h1>
            <p className="text-zinc-600 dark:text-zinc-400 mt-2 font-mono text-xs break-all opacity-80">{result.url}</p>
          </div>
        </div>
        <div className="flex-shrink-0">
          <RiskGauge score={result.riskScore} level={result.riskLevel} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Agent Investigation Report */}
        {result.agentReport && (
          <div className="lg:col-span-2 glass-panel rounded-3xl p-8 border border-emerald-200 dark:border-ornex-green/20 bg-emerald-50/20 dark:bg-ornex-green/5 overflow-hidden relative">
            <div className="absolute top-0 right-0 p-4 opacity-10">
               <Bot className="w-32 h-32 text-emerald-500 dark:text-ornex-green" />
            </div>
            <h3 className="text-sm font-bold text-zinc-900 dark:text-white flex items-center gap-2 mb-6 uppercase tracking-wider">
              <span className="w-1.5 h-1.5 bg-emerald-500 dark:bg-ornex-green rounded-full animate-pulse"></span>
              Agent Investigation Log
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
               {/* Active Probing Section */}
               <div className="space-y-3">
                  <div className="flex items-center gap-2 text-xs font-mono text-emerald-700 dark:text-ornex-green uppercase tracking-wider mb-1">
                     <Terminal className="w-4 h-4" />
                     <span>Active Probing (The Trap)</span>
                  </div>
                  <div className="bg-zinc-50 dark:bg-black/40 border border-zinc-200 dark:border-white/10 rounded-xl p-4 font-mono text-xs space-y-2">
                     <div className="flex justify-between border-b border-zinc-200 dark:border-white/10 pb-2 mb-2">
                        <span className="text-zinc-500">Method:</span>
                        <span className="text-zinc-800 dark:text-zinc-200">Credential Injection</span>
                     </div>
                     <div className="space-y-1">
                        <p className="text-zinc-500 mb-1">Payload:</p>
                        <p className="text-emerald-600 dark:text-ornex-green">{result.agentReport?.activeProbing?.credentialsUsed || 'N/A'}</p>
                     </div>
                     <div className="mt-2 pt-2 border-t border-zinc-200 dark:border-white/10">
                        <p className="text-zinc-500 mb-1">Result:</p>
                        <p className={`font-bold ${result.agentReport?.activeProbing?.behaviorRisk === 'HIGH' ? 'text-rose-500' : 'text-zinc-700 dark:text-zinc-300'}`}>
                           {result.agentReport?.activeProbing?.outcome || 'Active Probing Failed'}
                        </p>
                     </div>
                  </div>
               </div>

               {/* Visual Forensics Section */}
               <div className="space-y-3">
                  <div className="flex items-center gap-2 text-xs font-mono text-emerald-700 dark:text-ornex-green uppercase tracking-wider mb-1">
                     <Eye className="w-4 h-4" />
                     <span>Visual Forensics (The Eyes)</span>
                  </div>
                  <div className="bg-zinc-50 dark:bg-black/40 border border-zinc-200 dark:border-white/10 rounded-xl p-4 font-mono text-xs space-y-2">
                     <div className="flex justify-between border-b border-zinc-200 dark:border-white/10 pb-2 mb-2">
                        <span className="text-zinc-500">Analysis:</span>
                        <span className="text-zinc-800 dark:text-zinc-200">Brand & Hosting</span>
                     </div>
                     <div className="space-y-1">
                        <p className="text-zinc-500 mb-1">Brand Detected:</p>
                        <p className="text-zinc-800 dark:text-zinc-200">{result.agentReport?.visualForensics?.brandImpersonation || 'LLM Qualitative Engine Offline'}</p>
                     </div>
                     <div className="mt-2 pt-2 border-t border-zinc-200 dark:border-white/10">
                        <p className="text-zinc-500 mb-1">Infrastructure:</p>
                        <p className="text-zinc-700 dark:text-zinc-300">
                           {result.agentReport?.visualForensics?.hostingMismatch || 'Awaiting LLM availability.'}
                        </p>
                     </div>
                  </div>
               </div>
            </div>
          </div>
        )}

        {/* Left Column: Insight & Action */}
        <div className="space-y-6">
          {/* Reasoning Section / Key Findings */}
          <div className="glass-panel rounded-3xl p-8 border border-zinc-200 dark:border-white/10 transition-colors relative overflow-hidden">
            <div className="absolute top-0 right-0 p-3 opacity-5">
                <Activity className="w-32 h-32" />
            </div>
            <h3 className="text-sm font-bold text-zinc-900 dark:text-white flex items-center gap-2 mb-6 uppercase tracking-wider">
              <span className="w-1.5 h-1.5 bg-blue-500 rounded-full"></span>
              Key Findings
            </h3>
            <ul className="space-y-4">
              {result.reasoning.map((reason, idx) => (
                <li key={idx} className="flex items-start gap-4 text-zinc-700 dark:text-zinc-300 group">
                  <ArrowRight className="w-4 h-4 text-zinc-400 dark:text-zinc-600 mt-1 flex-shrink-0 group-hover:text-emerald-500 dark:group-hover:text-ornex-green transition-colors" />
                  <span className="text-sm leading-relaxed">{reason}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* FORENSIC INSIGHTS BOX */}
          <div className="glass-panel rounded-3xl p-8 border border-zinc-200 dark:border-white/10 transition-colors relative overflow-hidden">
             <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-3">
                   <div className="flex items-center gap-2 text-xs font-mono text-emerald-600 dark:text-ornex-green mb-1 uppercase tracking-wider">
                     <Activity className="w-4 h-4" />
                     <span>Forensic Tactics</span>
                   </div>
                   <p className="text-sm text-zinc-700 dark:text-zinc-300 bg-zinc-50 dark:bg-black/40 p-4 rounded-xl border border-zinc-200 dark:border-white/5 font-mono">
                     {result.technicalDetails.forensicDeepDive || "Standard heuristic patterns observed."}
                   </p>
                </div>
                <div className="space-y-3">
                   <div className="flex items-center gap-2 text-xs font-mono text-blue-500 mb-1 uppercase tracking-wider">
                     <Eye className="w-4 h-4" />
                     <span>Visual Prediction</span>
                   </div>
                   <p className="text-sm text-zinc-700 dark:text-zinc-300 bg-zinc-50 dark:bg-black/40 p-4 rounded-xl border border-zinc-200 dark:border-white/5 font-mono">
                     {result.technicalDetails.visualPrediction || "Generic layout impersonation detected."}
                   </p>
                </div>
             </div>
          </div>

          {/* MITIGATION ADVICE SECTION (MOVED UNDER KEY FINDINGS) */}
          {result.mitigationAdvice && result.mitigationAdvice.length > 0 && (
            <div className="glass-panel rounded-3xl p-8 border border-emerald-500/30 bg-emerald-500/5 dark:bg-ornex-green/5 shadow-[0_0_40px_rgba(16,185,129,0.05)] relative overflow-hidden">
               <div className="absolute top-0 right-0 p-4 opacity-5">
                  <ShieldCheck className="w-32 h-32 text-emerald-500" />
               </div>
               <h3 className="text-sm font-bold text-emerald-800 dark:text-ornex-green flex items-center gap-2 mb-6 uppercase tracking-wider">
                 <ShieldCheck className="w-5 h-5" />
                 Sentinel Mitigation Advice
               </h3>
               <div className="grid grid-cols-1 gap-4">
                  {result.mitigationAdvice.map((advice, idx) => (
                    <div key={idx} className="flex items-start gap-3 p-4 rounded-2xl bg-white/50 dark:bg-black/40 border border-emerald-500/20 backdrop-blur-sm">
                       <div className="w-6 h-6 rounded-full bg-emerald-500/10 dark:bg-ornex-green/10 flex items-center justify-center flex-shrink-0 text-emerald-600 dark:text-ornex-green font-bold text-xs">
                          {idx + 1}
                       </div>
                       <p className="text-sm text-zinc-700 dark:text-zinc-300 leading-snug">
                          {advice}
                       </p>
                    </div>
                  ))}
               </div>
            </div>
          )}
        </div>

        {/* Right Column: Technical Details Section */}
        <div className="glass-panel rounded-3xl p-8 border border-zinc-200 dark:border-white/10 space-y-6 transition-colors h-full">
          <h3 className="text-sm font-bold text-zinc-900 dark:text-white flex items-center gap-2 uppercase tracking-wider">
            <span className="w-1.5 h-1.5 bg-purple-500 rounded-full"></span>
            Technical Analysis
          </h3>

          <div className="space-y-5">
            <div>
              <div className="flex items-center gap-2 text-xs font-mono text-zinc-500 dark:text-zinc-500 mb-2 uppercase tracking-wider">
                <Globe className="w-3 h-3" />
                <span>URL Structure</span>
              </div>
              <p className="text-sm text-zinc-700 dark:text-zinc-300 bg-zinc-50 dark:bg-black/40 p-4 rounded-xl border border-zinc-200 dark:border-white/5 font-mono">
                {result.technicalDetails.urlStructure}
              </p>
            </div>

            <div>
               <div className="flex items-center gap-2 text-xs font-mono text-zinc-500 dark:text-zinc-500 mb-2 uppercase tracking-wider">
                <ShieldCheck className="w-3 h-3" />
                <span>Domain Reputation</span>
              </div>
              <p className="text-sm text-zinc-700 dark:text-zinc-300 bg-zinc-50 dark:bg-black/40 p-4 rounded-xl border border-zinc-200 dark:border-white/5 font-mono">
                {result.technicalDetails.domainReputation}
              </p>
            </div>

            <div>
               <div className="flex items-center gap-2 text-xs font-mono text-zinc-500 dark:text-zinc-500 mb-2 uppercase tracking-wider">
                <AlertTriangle className="w-3 h-3" />
                <span>Social Engineering</span>
              </div>
              <p className="text-sm text-zinc-700 dark:text-zinc-300 bg-zinc-50 dark:bg-black/40 p-4 rounded-xl border border-zinc-200 dark:border-white/5 font-mono">
                {result.technicalDetails.socialEngineeringTricks}
              </p>
            </div>

          </div>
        </div>

        {/* Verification Sources Section - Bottom Full Width */}
        {result.webSources && result.webSources.length > 0 && (
          <div className="lg:col-span-2 glass-panel rounded-3xl p-8 border border-zinc-200 dark:border-white/10 transition-colors">
            <h3 className="text-sm font-bold text-zinc-900 dark:text-white flex items-center gap-2 mb-6 uppercase tracking-wider">
              <span className="w-1.5 h-1.5 bg-indigo-500 rounded-full"></span>
              Verification Sources
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {result.webSources.map((source, idx) => (
                <a
                  key={idx}
                  href={source.uri}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-4 p-4 rounded-xl bg-zinc-50 dark:bg-white/5 border border-zinc-200 dark:border-white/5 hover:border-emerald-500/50 dark:hover:border-ornex-green/50 hover:bg-zinc-100 dark:hover:bg-white/10 transition-all group"
                >
                  <div className="p-2.5 rounded-lg bg-white dark:bg-black text-zinc-400 group-hover:text-emerald-500 dark:group-hover:text-ornex-green transition-colors border border-zinc-100 dark:border-white/10">
                    <Globe className="w-4 h-4" />
                  </div>
                  <div className="overflow-hidden flex-1">
                    <p className="text-sm font-bold text-zinc-800 dark:text-zinc-200 truncate group-hover:text-emerald-500 dark:group-hover:text-ornex-green transition-colors" title={source.title}>{source.title}</p>
                    <p className="text-xs font-mono text-zinc-500 truncate" title={source.uri}>{source.uri}</p>
                  </div>
                  <ExternalLink className="w-4 h-4 text-zinc-300 dark:text-zinc-700 ml-auto group-hover:text-emerald-500 dark:group-hover:text-ornex-green" />
                </a>
              ))}
            </div>
          </div>
        )}

      </div>
    </div>
  );
});

ResultDetails.displayName = 'ResultDetails';
