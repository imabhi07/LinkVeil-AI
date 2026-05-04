import React, { memo } from 'react';
import type { HistoryItem, RiskLevel } from '../types';
import { Clock, Trash2, ArrowUpRight, X, Mail, Globe } from 'lucide-react';

interface HistorySidebarProps {
  history: HistoryItem[];
  mode: 'url' | 'email';
  onSelect: (item: HistoryItem) => void;
  onClear: () => void;
  onDelete: (id: string) => void;
}

export const HistorySidebar: React.FC<HistorySidebarProps> = memo(({ history, mode, onSelect, onClear, onDelete }) => {
    const getLevelColor = (level: RiskLevel | string) => {
      const normalized = (level || 'UNKNOWN').toString().toUpperCase();
      switch (normalized) {
        case 'SAFE':
        case 'LOW': 
          return 'text-[#166534] dark:text-ornex-green border-[#BBF7D0] dark:border-ornex-green/30 bg-[#DCFCE7] dark:bg-ornex-green/10';
        case 'SUSPICIOUS':
        case 'MEDIUM':
          return 'text-[#92400E] dark:text-amber-500 border-[#FEF3C7] dark:border-amber-500/30 bg-[#FFFBEB] dark:bg-amber-500/10';
        case 'MALICIOUS':
        case 'HIGH':
          return 'text-[#991B1B] dark:text-rose-500 border-[#FECACA] dark:border-rose-500/30 bg-[#FEE2E2] dark:bg-rose-500/10';
        case 'UNKNOWN':
          return 'text-slate-500 dark:text-slate-400 border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-slate-900/20 font-black uppercase tracking-[0.12em] shadow-sm';
        default: return 'text-zinc-600 dark:text-zinc-400 border-zinc-200 dark:border-white/10 bg-zinc-50 dark:bg-white/5 font-bold uppercase tracking-wider';
      }
  };

  return (
    <div className="glass-panel w-full h-full max-h-[600px] rounded-3xl dark:border-white/10 flex flex-col overflow-hidden transition-colors">
      <div className="p-5 border-b border-cyber-light-border dark:border-white/10 flex justify-between items-center bg-white/50 dark:bg-white/5 shrink-0">
        <h3 className="text-cyber-light-heading dark:text-white font-bold text-sm uppercase tracking-wider flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyber-light-text" />
          Recent Scans
        </h3>
        {history.length > 0 && (
          <button
            onClick={onClear}
            className="text-xs uppercase font-bold text-cyber-light-text hover:text-rose-500 transition-colors flex items-center gap-1.5 px-2 py-1 rounded hover:bg-rose-500/10"
          >
            <Trash2 className="w-3 h-3" />
            Clear Log
          </button>
        )}
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-2 custom-scrollbar">
        {history.length === 0 ? (
          <div className="text-center py-12 text-cyber-light-text/70 dark:text-zinc-600 text-sm font-mono border-2 border-dashed border-cyber-light-border dark:border-white/5 rounded-xl mx-2">
            NO {mode.toUpperCase()} DATA LOGGED
          </div>
        ) : (
          history.map((item) => {
            const isEmail = item.type === 'email';
            const riskLevel = isEmail ? (item.result?.email_risk_level?.toUpperCase() || 'UNKNOWN') : item.riskLevel;
            const title = isEmail 
              ? (item.result?.parsed_email?.subject || 'Untitled Email Analysis')
              : item.verdictTitle;
            const subtitle = isEmail
              ? (item.result?.parsed_email?.from_email || 'Unknown Sender')
              : item.url;

            return (
              <div
                key={item.id}
                onClick={() => onSelect(item)}
                className="p-5 rounded-2xl bg-white/80 dark:bg-zinc-900/40 border border-zinc-100 dark:border-white/10 hover:border-[#00C853]/50 dark:hover:border-ornex-green/50 hover:bg-white dark:hover:bg-black/60 cursor-pointer transition-all active:scale-[0.98] group shadow-sm hover:shadow-xl hover:-translate-y-1"
              >
                <div className="flex justify-between items-center mb-2">
                  <div className="flex items-center gap-2">
                    {isEmail ? <Mail className="w-3 h-3 text-zinc-400" /> : <Globe className="w-3 h-3 text-zinc-400" />}
                    <span className={`text-xs font-bold px-2 py-0.5 rounded border ${getLevelColor(riskLevel)}`}>
                      {riskLevel}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-zinc-500 dark:text-zinc-600 font-medium">
                      {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onDelete(item.id);
                      }}
                      className="p-1 rounded-md text-cyber-light-text hover:text-rose-500 hover:bg-rose-500/10 transition-colors opacity-0 group-hover:opacity-100"
                      title="Delete Scan"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <p className="text-xs font-mono text-zinc-500 dark:text-zinc-400 truncate w-3/4 opacity-80 mb-0.5" title={subtitle}>
                      {subtitle}
                  </p>
                  <ArrowUpRight className="w-3 h-3 text-cyber-light-text/40 dark:text-zinc-700 group-hover:text-cyber-light-accent dark:group-hover:text-ornex-green transition-colors" />
                </div>
                <p className="text-sm font-bold text-cyber-light-heading dark:text-zinc-200 truncate">
                  {title}
                </p>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
});

HistorySidebar.displayName = 'HistorySidebar';
