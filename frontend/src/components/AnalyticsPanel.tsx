import { useEffect, useState, useMemo, useCallback } from 'react';
import { 
  BarChart3, TrendingUp, ShieldAlert, ShieldCheck, Activity, 
  Globe, X, RefreshCw, AlertTriangle 
} from 'lucide-react';

interface ScanListItem {
  url: string;
  risk_level: string;
  risk_score: number;
  brand_name: string | null;
  timestamp: string;
}

interface AnalyticsData {
  total_scans: number;
  risk_distribution: Record<string, number>;
  daily_volume: { date: string, count: number }[];
  top_brands: { brand: string, count: number }[];
  top_impersonated_brands: { brand: string, category: string, share: string }[];
  last_updated: string;
  filter_days: number;
}

function ScanListPopover({ scans, loading, filterLabel, color, onClose }: {
  scans: ScanListItem[];
  loading: boolean;
  filterLabel: string;
  color: string;
  onClose: () => void;
}) {
  // Close on Escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  return (
    <div className="scan-popover absolute top-full left-0 right-0 mt-2 z-[110] animate-in slide-in-from-top-2 duration-200">
      {/* Arrow pointer */}
      <div className="absolute -top-2 left-1/2 -translate-x-1/2 w-4 h-4 
                      bg-white dark:bg-zinc-800 border-l border-t border-zinc-200 dark:border-white/10 rotate-45" />
      
      {/* Bubble body */}
      <div className="bg-white dark:bg-zinc-800/95 backdrop-blur-xl border border-zinc-200 dark:border-white/10 
                      rounded-2xl shadow-2xl overflow-hidden max-h-80">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-100 dark:border-white/5 bg-zinc-50 dark:bg-black/20">
          <span className={`text-xs font-bold uppercase tracking-wider ${color}`}>
            {filterLabel} — {scans.length} results
          </span>
          <button onClick={onClose} className="text-zinc-400 dark:text-zinc-500 hover:text-zinc-900 dark:hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        
        {/* Scan list */}
        <div className="overflow-y-auto max-h-64 divide-y divide-white/5 custom-scrollbar">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <div className="w-6 h-6 border-2 border-emerald-500/20 
                              border-t-emerald-500 rounded-full animate-spin" />
            </div>
          ) : scans.length === 0 ? (
            <div className="py-8 text-center text-zinc-500 text-xs">
              No scans in this category
            </div>
          ) : (
            scans.map((scan, i) => (
              <div key={i} className="px-4 py-3 flex items-center justify-between 
                                      hover:bg-white/[0.02] transition-colors group/item">
                <div className="flex items-center gap-3 min-w-0">
                  {/* Risk dot */}
                  <div className={`w-2 h-2 rounded-full shrink-0 ${
                    scan.risk_level === 'High' || scan.risk_level === 'Malicious'
                      ? 'bg-rose-500 shadow-[0_0_6px_rgba(244,63,94,0.5)]' 
                      : 'bg-cyber-light-accent-deep dark:bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.5)]'
                  }`} />
                  <div className="min-w-0">
                    <div className="text-xs text-zinc-900 dark:text-white truncate max-w-[250px] group-hover/item:text-emerald-600 dark:group-hover/item:text-emerald-400 transition-colors">
                      {scan.url}
                    </div>
                    <div className="text-[9px] text-zinc-500 flex items-center gap-1.5 mt-0.5">
                      <span className="font-bold">Score: {Math.round(scan.risk_score)}</span>
                      {scan.brand_name && (
                        <>
                          <span className="text-zinc-700">•</span>
                          <span className="italic text-zinc-400">{scan.brand_name}</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
                <span className="text-[9px] text-zinc-600 font-mono shrink-0 ml-3">
                  {new Date(scan.timestamp).toLocaleDateString(undefined, {
                    month: 'short', day: 'numeric'
                  })}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

export function AnalyticsPanel({ onClose }: { onClose: () => void }) {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [days, setDays] = useState(7);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // New state for drill-down
  const [activeFilter, setActiveFilter] = useState<string | null>(null);
  const [scanList, setScanList] = useState<ScanListItem[]>([]);
  const [scanListLoading, setScanListLoading] = useState(false);

  const fetchAnalytics = useCallback(async (isSilent = false) => {
    if (!data) setLoading(true);
    setIsRefreshing(true);
    setError(false);
    
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
      const response = await fetch(`${API_BASE_URL}/api/v1/analytics/?days=${days}`);
      if (response.ok) {
        const json = await response.json();
        setData(json);
      } else {
        setError(true);
      }
    } catch (err) {
      console.error("Failed to fetch analytics:", err);
      setError(true);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, [days]);

  useEffect(() => {
    fetchAnalytics();
    const interval = setInterval(() => {
      fetchAnalytics(true);
    }, 30000);
    return () => clearInterval(interval);
  }, [fetchAnalytics]);

  // Handle click outside to dismiss popover
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest('.stat-card') && !target.closest('.scan-popover')) {
        setActiveFilter(null);
      }
    };
    
    if (activeFilter) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [activeFilter]);

  const handleCardClick = async (filterKey: string) => {
    if (activeFilter === filterKey) {
      setActiveFilter(null);
      return;
    }
    
    setActiveFilter(filterKey);
    setScanListLoading(true);
    
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
      const res = await fetch(`${API_BASE_URL}/api/v1/analytics/scans?filter=${filterKey}&days=${days}`);
      if (res.ok) {
        setScanList(await res.json());
      }
    } catch (err) {
      console.error("Failed to fetch scan list:", err);
    } finally {
      setScanListLoading(false);
    }
  };

  const stats = useMemo(() => {
    if (!data) return [];
    
    const dist: Record<string, number> = {};
    Object.entries(data.risk_distribution).forEach(([k, v]) => {
      dist[k.toLowerCase()] = v;
    });

    return [
      { 
        label: 'Total Scans', 
        value: data.total_scans, 
        icon: Activity, 
        color: 'text-zinc-400',
        filterKey: 'all'
      },
      { 
        label: 'Malicious', 
        value: (dist['high'] || 0) + (dist['malicious'] || 0) + (dist['medium'] || 0) + (dist['unknown'] || 0), 
        icon: ShieldAlert, 
        color: 'text-rose-500',
        filterKey: 'malicious'
      },
      { 
        label: 'Safe', 
        value: (dist['low'] || 0) + (dist['safe'] || 0), 
        icon: ShieldCheck, 
        color: 'text-cyber-light-accent-deep dark:text-emerald-500',
        filterKey: 'safe'
      },
    ];
  }, [data]);

  if (loading && !data) {
    return (
      <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm">
        <div className="w-12 h-12 border-4 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm">
        <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-white/10 rounded-3xl p-8 text-center max-w-sm animate-in zoom-in duration-300 shadow-2xl">
          <AlertTriangle className="w-12 h-12 text-amber-500 mx-auto mb-4" />
          <h3 className="text-xl font-bold text-zinc-900 dark:text-white mb-2">Analytics Offline</h3>
          <p className="text-zinc-500 dark:text-zinc-400 text-sm mb-6">Could not establish connection to the intelligence server.</p>
          <div className="flex gap-3">
            <button 
              onClick={() => fetchAnalytics()}
              className="flex-1 px-4 py-2 bg-emerald-500 text-black rounded-xl text-sm font-bold hover:bg-emerald-400 transition-colors"
            >
              Retry Connection
            </button>
            <button 
              onClick={onClose}
              className="px-4 py-2 bg-white/5 text-white rounded-xl text-sm font-medium hover:bg-white/10 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 md:p-8 bg-black/60 backdrop-blur-sm animate-in fade-in duration-300">
      <div className="relative w-full max-w-6xl max-h-[95vh] overflow-hidden bg-cyber-light-bg dark:bg-zinc-900/90 border border-cyber-light-border dark:border-white/10 rounded-3xl shadow-2xl backdrop-blur-xl flex flex-col">
        
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-cyber-light-border dark:border-white/5 bg-white/50 dark:bg-white/5">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-emerald-500/20 rounded-xl relative">
              <BarChart3 className="w-6 h-6 text-emerald-400" />
              {isRefreshing && (
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-emerald-500 rounded-full animate-ping" />
              )}
            </div>
            <div>
              <h2 className="text-xl font-bold text-cyber-light-heading dark:text-white tracking-tight">Forensic Intelligence Dashboard</h2>
              <p className="text-xs text-cyber-light-text dark:text-zinc-400 font-mono uppercase tracking-widest">Real-time Threat Monitoring</p>
            </div>
          </div>

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-1 bg-black/5 dark:bg-black/40 rounded-xl p-1 border border-cyber-light-border dark:border-white/5">
              {[7, 30, 0].map(d => (
                <button
                  key={d}
                  onClick={() => {
                    setDays(d);
                    setActiveFilter(null); // Close popover when timeframe changes
                  }}
                  className={`px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${
                    days === d 
                      ? 'bg-emerald-500 text-black shadow-lg shadow-emerald-500/20' 
                      : 'text-cyber-light-text hover:text-white hover:bg-black/10 dark:hover:bg-white/5'
                  }`}
                >
                  {d === 0 ? 'ALL TIME' : `${d}D`}
                </button>
              ))}
            </div>

            <button 
              onClick={onClose}
              className="p-2 hover:bg-zinc-200 dark:hover:bg-white/10 rounded-full transition-colors text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white"
            >
              <X className="w-6 h-6" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 md:p-8 space-y-8 custom-scrollbar relative">
          
          {/* Stats Grid */}
          <div className="grid grid-cols-3 gap-4 relative z-[106]">
            {stats.map((stat, i) => (
              <div key={i} className="relative">
                  <div 
                    onClick={() => handleCardClick(stat.filterKey)}
                    className={`stat-card p-5 border rounded-2xl cursor-pointer transition-all duration-300 relative overflow-hidden group
                      ${activeFilter === stat.filterKey 
                        ? 'bg-emerald-500/10 border-emerald-500/40 ring-1 ring-emerald-500/20' 
                        : 'bg-white/40 dark:bg-white/5 border-cyber-light-border dark:border-white/5 hover:border-cyber-light-accent hover:bg-white/60 dark:hover:border-white/10 dark:hover:bg-white/[0.07]'}`}
                  >
                    {/* Subtle active indicator at top */}
                    {activeFilter === stat.filterKey && (
                      <div className="absolute top-0 left-0 right-0 h-1 bg-emerald-500 animate-in slide-in-from-top-1" />
                    )}
                    
                    <stat.icon className={`w-5 h-5 ${stat.color} mb-4 group-hover:scale-110 transition-transform`} />
                    <div className="text-3xl font-bold text-cyber-light-accent-data dark:text-white mb-1 tracking-tight">{stat.value}</div>
                    <div className="text-[10px] text-cyber-light-text font-bold uppercase tracking-widest flex items-center justify-between">
                      {stat.label}
                      {activeFilter === stat.filterKey && <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />}
                    </div>
                  </div>

                {/* Popover anchored to this specific card */}
                {activeFilter === stat.filterKey && (
                  <ScanListPopover 
                    scans={scanList}
                    loading={scanListLoading}
                    filterLabel={stat.label}
                    color={stat.color}
                    onClose={() => setActiveFilter(null)}
                  />
                )}
              </div>
            ))}
          </div>

          {/* Scan Volume Chart */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-cyber-light-heading dark:text-zinc-300 flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-emerald-500 dark:text-emerald-400" />
                Scan Activity Distribution
              </h3>
              <span className="text-[10px] text-cyber-light-text/70 dark:text-zinc-500 font-mono italic">
                Showing last {data.daily_volume.length} days
              </span>
            </div>
            <div className="h-64 bg-white/40 dark:bg-black/20 rounded-3xl p-6 pb-10 border border-cyber-light-border dark:border-white/5 flex items-end gap-2 relative overflow-visible">
              <div className="absolute inset-0 bg-gradient-to-t from-emerald-500/5 to-transparent pointer-events-none rounded-3xl" />
              {data.daily_volume.map((v, i) => {
                const max = Math.max(...data.daily_volume.map(d => d.count), 1);
                const height = (v.count / max) * 100;
                return (
                  <div key={i} className="flex-1 flex flex-col items-center group relative" style={{ height: '100%' }}>
                    <div className="w-full flex-1 flex flex-col justify-end items-center relative">
                      <span className="text-[10px] text-cyber-light-accent-deep dark:text-emerald-400 font-mono font-bold mb-1 z-10">
                        {v.count > 0 ? v.count : ''}
                      </span>
                      <div 
                        className="w-[70%] bg-gradient-to-t from-emerald-500/30 to-emerald-400/15 dark:from-emerald-500/50 dark:to-emerald-400/25 group-hover:from-emerald-500/50 group-hover:to-emerald-400/30 dark:group-hover:from-emerald-500/70 dark:group-hover:to-emerald-400/40 border-t-2 border-emerald-400 rounded-t-lg transition-all duration-500 ease-out relative"
                        style={{ height: `${Math.max(height, 4)}%`, minHeight: '4px' }}
                      >
                        <div className="absolute -top-8 left-1/2 -translate-x-1/2 bg-zinc-800 dark:bg-zinc-800 text-white text-[9px] py-1 px-2 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none border border-white/10 whitespace-nowrap z-50 shadow-xl">
                          {new Date(v.date + 'T00:00:00').toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} — {v.count} scans
                        </div>
                      </div>
                    </div>
                    <span className="text-[9px] text-cyber-light-text font-mono font-bold uppercase mt-2 absolute -bottom-6">
                      {new Date(v.date + 'T00:00:00').toLocaleDateString(undefined, { weekday: 'short' })}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Top Impersonated Brands */}
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-cyber-light-heading dark:text-zinc-300 flex items-center gap-2">
              <Globe className="w-4 h-4 text-emerald-500 dark:text-emerald-400" />
              Top Impersonated Brands
              <span className="text-[9px] text-cyber-light-text dark:text-zinc-600 font-mono ml-2 bg-white dark:bg-white/5 px-2 py-0.5 rounded-lg">GLOBAL INTEL</span>
            </h3>
            <div className="grid md:grid-cols-2 gap-2">
              {data.top_impersonated_brands.slice(0, 10).map((b, i) => (
                <div key={i} className="relative group overflow-hidden p-3 bg-white/40 dark:bg-white/5 rounded-2xl border border-cyber-light-border dark:border-white/5 hover:bg-white/60 dark:hover:bg-white/[0.08] transition-all">
                  <div 
                    className="absolute inset-0 bg-emerald-500/5 transition-all duration-1000 ease-out origin-left"
                    style={{ width: b.share }}
                  />
                  <div className="relative flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-xl bg-white dark:bg-zinc-900 border border-cyber-light-border dark:border-white/5 flex items-center justify-center text-xs font-black text-emerald-600 dark:text-emerald-400 shadow-sm">
                        {i + 1}
                      </div>
                      <div className="flex flex-col">
                        <span className="text-sm font-bold text-cyber-light-heading dark:text-white tracking-tight">{b.brand}</span>
                        <span className="text-[9px] text-cyber-light-text font-mono uppercase tracking-wider">{b.category}</span>
                      </div>
                    </div>
                    <div className="text-xs font-mono font-bold text-cyber-light-accent-data dark:text-emerald-400/80 bg-cyber-light-accent-bg dark:bg-emerald-500/10 px-2 py-1 rounded-lg">
                      {b.share}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 bg-white/40 dark:bg-black/40 border-t border-cyber-light-border dark:border-white/5 flex flex-col md:flex-row items-center justify-between gap-4 px-8">
          <div className="flex items-center gap-2">
             <RefreshCw className={`w-3 h-3 text-emerald-500/50 ${isRefreshing ? 'animate-spin' : ''}`} />
             <p className="text-[9px] text-cyber-light-text font-mono uppercase tracking-[0.2em]">
               Last Intel Sync: {new Date(data.last_updated).toLocaleTimeString()}
             </p>
          </div>
          <p className="text-[9px] text-cyber-light-text font-mono uppercase tracking-[0.2em]">
            LinkVeil-AI Forensic Engine v2.1.0 • Protected by Multimodal Neural Vision
          </p>
        </div>
      </div>
    </div>
  );
}
