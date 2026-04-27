import React, { memo } from 'react';
import type { ScanHistoryItem, RiskLevel } from '../types';
import { Clock, Trash2, ArrowUpRight, X } from 'lucide-react';

interface HistorySidebarProps {
  history: ScanHistoryItem[];
  onSelect: (item: ScanHistoryItem) => void;
  onClear: () => void;
  onDelete: (id: string) => void;
}

export const HistorySidebar: React.FC<HistorySidebarProps> = memo(({ history, onSelect, onClear, onDelete }) => {
    const getLevelColor = (level: RiskLevel) => {
      switch (level) {
        case 'SAFE': return 'text-cyber-light-accent-deep dark:text-ornex-green border-cyber-light-accent/30 dark:border-ornex-green/30 bg-cyber-light-accent-bg dark:bg-ornex-green/10';
        case 'SUSPICIOUS': return 'text-amber-600 dark:text-amber-500 border-amber-500/30 bg-amber-500/10';
        case 'MALICIOUS': return 'text-rose-600 dark:text-rose-500 border-rose-500/30 bg-rose-500/10';
        default: return 'text-cyber-light-text border-cyber-light-border bg-black/5';
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
            className="text-[10px] uppercase font-bold text-cyber-light-text hover:text-rose-500 transition-colors flex items-center gap-1.5 px-2 py-1 rounded hover:bg-rose-500/10"
          >
            <Trash2 className="w-3 h-3" />
            Clear Log
          </button>
        )}
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-2 custom-scrollbar">
        {history.length === 0 ? (
          <div className="text-center py-12 text-cyber-light-text/70 dark:text-zinc-600 text-sm font-mono border-2 border-dashed border-cyber-light-border dark:border-white/5 rounded-xl mx-2">
            NO DATA LOGGED
          </div>
        ) : (
          history.map((item) => (
            <div
              key={item.id}
              onClick={() => onSelect(item)}
              className="p-4 rounded-xl bg-white/40 dark:bg-black/20 border border-cyber-light-border dark:border-white/5 hover:border-cyber-light-accent/30 dark:hover:border-ornex-green/30 hover:bg-white/80 dark:hover:bg-white/10 cursor-pointer transition-all active:scale-[0.98] group"
            >
              <div className="flex justify-between items-center mb-2">
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getLevelColor(item.riskLevel)}`}>
                  {item.riskLevel}
                </span>
                <div className="flex items-center gap-3">
                  <span className="text-[10px] font-mono text-cyber-light-text dark:text-zinc-600">
                    {new Date(item.timestamp).toLocaleTimeString()}
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
                <p className="text-xs font-mono text-cyber-light-text dark:text-zinc-400 truncate w-3/4 opacity-70 mb-0.5" title={item.url}>
                    {item.url}
                </p>
                <ArrowUpRight className="w-3 h-3 text-cyber-light-text/40 dark:text-zinc-700 group-hover:text-cyber-light-accent dark:group-hover:text-ornex-green transition-colors" />
              </div>
              <p className="text-sm font-bold text-cyber-light-heading dark:text-zinc-200 truncate">
                {item.verdictTitle}
              </p>
            </div>
          ))
        )}
      </div>
    </div>
  );
});

HistorySidebar.displayName = 'HistorySidebar';
