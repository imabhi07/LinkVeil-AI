import { useEffect, useState, useMemo, useCallback, useRef } from 'react';
import { InfoTip } from './InfoTip';
import { 
  BarChart3, TrendingUp, ShieldAlert, ShieldCheck, Activity, 
  Globe, X, RefreshCw, AlertTriangle, Fingerprint, Layers, Microscope,
  CreditCard, User, Terminal,
  Zap, Gift, Search
} from 'lucide-react';

interface ScanListItem {
  url: string;
  risk_level: string;
  risk_score: number;
  brand_name: string | null;
  timestamp: string;
}

const SectionTooltip = ({ text }: { text: string }) => (
  <InfoTip title="Insight" content={text} className="inline-flex ml-1.5" />
);

const InfoTooltip = ({ text, children, className = "inline-flex items-center" }: { text: string, children: React.ReactNode, className?: string }) => {
  const index = text.indexOf('|');
  const [title, content] = index !== -1 ? [text.slice(0, index), text.slice(index + 1)] : ['', text];
  return (
    <InfoTip title={title.trim() || 'Protocols'} content={content.trim()} className={className}>
      {children}
    </InfoTip>
  );
};

interface AnalyticsData {
  url: {
    total_scans: number;
    risk_distribution: Record<string, number>;
    daily_volume: { date: string, count: number }[];
    top_brands: { brand: string, count: number }[];
    top_malicious_tlds: { tld: string; count: number; malicious_pct: number }[];
  };
  email: {
    total_scans: number;
    risk_distribution: Record<string, number>;
    daily_volume: { date: string, count: number }[];
    attack_vectors: { category: string; count: number; percentage: number }[];
    auth_posture: {
      spf: { pass: number; fail: number; none: number };
      dkim: { pass: number; fail: number; none: number };
      dmarc: { pass: number; fail: number; none: number };
    };
    obfuscation_heatmap: { technique: string; count: number }[];
    confidence_trend: { date: string; avg_quality: number; high: number; medium: number; low: number }[];
  };
  combined: {
    total_scans: number;
    last_updated: string;
    filter_days: number;
  };
  top_impersonated_brands: { brand: string, category: string, share: string }[];
  last_updated: string;
  filter_days: number;
}

// Scan list item for the expanded card view
interface ScanListInlineProps {
  scans: ScanListItem[];
  loading: boolean;
  error?: string | null;
  color: string;
  riskLevelColor: string;
  onReview?: (scan: ScanListItem) => void;
}

function ScanListInline({ scans, loading, error, riskLevelColor, color, onReview }: ScanListInlineProps) {
  // Use a local state to keep the previous scans during the collapse animation
  const [displayScans, setDisplayScans] = useState<ScanListItem[]>(scans);
  
  useEffect(() => {
    if (scans.length > 0) {
      setDisplayScans(scans);
    } else if (!loading && !error) {
      // Small delay before clearing display scans to allow collapse animation to finish
      const timer = setTimeout(() => setDisplayScans([]), 600);
      return () => clearTimeout(timer);
    } else if (error) {
      setDisplayScans([]);
    }
  }, [scans, loading, error]);

  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'all' | 'high' | 'safe'>('all');

  const filteredScans = displayScans.filter(scan => {
    const matchesSearch = scan.url.toLowerCase().includes(searchQuery.toLowerCase());
    const isHigh = scan.risk_level.toLowerCase() === 'high' || scan.risk_level.toLowerCase() === 'malicious';
    const matchesSeverity = severityFilter === 'all' || 
      (severityFilter === 'high' && isHigh) ||
      (severityFilter === 'safe' && !isHigh);
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="mt-6 pt-6 border-t border-zinc-200 dark:border-white/5 overflow-hidden transition-all duration-700">
      <div className="flex flex-col gap-4 mb-4 px-1">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
             <div className={`w-1.5 h-1.5 rounded-full ${riskLevelColor} animate-pulse shadow-[0_0_6px_rgba(16,185,129,0.3)]`} />
              <h4 className={`text-xs font-black uppercase tracking-[0.2em] ${color}`}>
                Forensic Log
              </h4>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-zinc-500 dark:text-zinc-600 font-mono uppercase tracking-tighter opacity-50">Pulse</span>
            <div className={`w-1 h-1 rounded-full ${loading ? 'bg-cyber-light-accent dark:bg-ornex-green animate-pulse' : 'bg-cyber-light-accent/50 dark:bg-ornex-green/50'}`} />
          </div>
        </div>

        {/* Search & Severity Filter */}
        <div className="flex items-center gap-2">
          <div className="relative flex-1 group">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500 group-focus-within:text-cyber-light-accent dark:group-focus-within:text-ornex-green transition-colors" />
            <input 
              type="text" 
              placeholder="Filter Intel..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-black/10 dark:bg-black/40 border border-zinc-200/50 dark:border-white/5 rounded-xl pl-9 pr-3 py-1.5 text-xs text-zinc-900 dark:text-zinc-300 focus:outline-none focus:border-cyber-light-accent/30 dark:focus:border-ornex-green/30 transition-all font-mono"
            />
          </div>
          <select 
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as any)}
            className="bg-black/10 dark:bg-black/40 border border-zinc-200/50 dark:border-white/5 rounded-xl px-2 py-1.5 text-[10px] font-black uppercase tracking-wider text-zinc-600 dark:text-zinc-500 focus:outline-none cursor-pointer hover:border-cyber-light-accent/30 dark:hover:border-ornex-green/30"
          >
            <option value="all">ALL</option>
            <option value="high">RISK</option>
            <option value="safe">SAFE</option>
          </select>
        </div>
      </div>
      
      <div className="space-y-2 max-h-[280px] overflow-y-auto overflow-x-hidden custom-scrollbar pr-2">
        {loading && scans.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 gap-3">
            <RefreshCw className="w-6 h-6 text-cyber-light-accent/20 dark:text-ornex-green/20 animate-spin" />
            <span className="text-[10px] text-zinc-600 font-mono animate-pulse uppercase tracking-[0.2em]">Syncing...</span>
          </div>
        ) : error ? (
          <div className="flex flex-col items-center justify-center py-10 px-4 text-center gap-3">
            <div className="w-8 h-8 rounded-full bg-rose-500/10 flex items-center justify-center">
              <AlertTriangle className="w-4 h-4 text-rose-500" />
            </div>
            <p className="text-[10px] text-rose-600 dark:text-rose-400 font-medium uppercase tracking-wider max-w-[200px]">
              {error}
            </p>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="py-12 text-center">
            <p className="text-xs text-zinc-600 uppercase tracking-widest font-black">No matching records</p>
          </div>
        ) : (
          filteredScans.map((scan, i) => {
            const riskLower = (scan.risk_level || "").toLowerCase();
            const isHigh = riskLower === 'high' || riskLower === 'malicious';
            const isMedium = riskLower === 'medium' || riskLower === 'suspicious';
            const statusColor = isHigh ? 'text-rose-600 dark:text-rose-500' : isMedium ? 'text-amber-600 dark:text-amber-500' : 'text-cyber-light-accent dark:text-ornex-green';
            const statusBg = isHigh ? 'bg-rose-500/10 border-rose-500/20' : isMedium ? 'bg-amber-500/10 border-amber-500/20' : 'bg-cyber-light-accent/10 border-cyber-light-accent/20 dark:bg-ornex-green/10 dark:border-ornex-green/20';

            return (
              <div key={i} className="group/item relative p-3 bg-zinc-100/50 dark:bg-black/30 border border-zinc-200/50 dark:border-white/5 rounded-xl flex items-center justify-between hover:bg-white dark:hover:bg-white/[0.03] hover:border-ornex-green/20 transition-all duration-200">
                <div className="min-w-0 flex-1 pr-3">
                  <div className="text-xs text-zinc-800 dark:text-zinc-300 truncate font-mono group-hover/item:text-cyber-light-accent dark:group-hover/item:text-ornex-green transition-colors tracking-tight">
                    {scan.url}
                  </div>
                  <div className="flex items-center gap-3 mt-1.5">
                    <div className={`flex items-center gap-1.5 px-2 py-0.5 ${statusBg} border rounded-md`}>
                      <div className={`w-1 h-1 rounded-full ${isHigh ? 'bg-rose-500 animate-pulse' : isMedium ? 'bg-amber-500' : 'bg-cyber-light-accent dark:bg-ornex-green'}`} />
                      <span className={`text-[10px] font-black uppercase tracking-widest ${statusColor}`}>
                        {scan.risk_level}
                      </span>
                    </div>
                    <span className="text-[10px] text-zinc-400 font-mono">
                      {new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                </div>
                
                <div className="flex items-center gap-3">
                  <button 
                    onClick={() => onReview && onReview(scan)}
                    className="px-3 py-1.5 bg-cyber-light-accent/5 dark:bg-ornex-green/5 hover:bg-cyber-light-accent/20 dark:hover:bg-ornex-green/20 border border-cyber-light-accent/10 dark:border-ornex-green/10 hover:border-cyber-light-accent/30 dark:hover:border-ornex-green/30 rounded-lg text-[10px] font-black text-cyber-light-accent dark:text-ornex-green uppercase tracking-widest transition-all opacity-0 group-hover/item:opacity-100 translate-x-2 group-hover/item:translate-x-0 cursor-pointer"
                  >
                    Review
                  </button>
                  <div className={`w-1 h-6 rounded-full opacity-30 group-hover/item:opacity-80 transition-all ${
                    isHigh ? 'bg-rose-500' : isMedium ? 'bg-amber-500' : 'bg-cyber-light-accent dark:bg-ornex-green'
                  }`} />
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

export function AnalyticsPanel({ onClose, onReview, clientId, isInitializing, initError, onReinitSession }: { onClose: () => void; onReview?: (scan: ScanListItem) => void; clientId: string; isInitializing?: boolean; initError?: string | null; onReinitSession?: () => Promise<any> }) {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [days, setDays] = useState(7);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState<'url' | 'email'>('url');

  // New state for drill-down
  const [activeFilter, setActiveFilter] = useState<string | null>(null);
  const [scanList, setScanList] = useState<ScanListItem[]>([]);
  const [scanListLoading, setScanListLoading] = useState(false);
  const [scanListError, setScanListError] = useState<string | null>(null);
  const hasDataRef = useRef(false);

  // Sync ref with data state to avoid stale closures in useCallback
  useEffect(() => {
    hasDataRef.current = !!data;
  }, [data]);

  const fetchAnalytics = useCallback(async (isSilent = false, isRetry = false) => {
    if (!hasDataRef.current && !isSilent) setLoading(true);
    if (!isSilent) setIsRefreshing(true);
    setError(false);
    
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
      const response = await fetch(`${API_BASE_URL}/api/v1/analytics/?days=${days}`, {
        headers: {
          'X-Client-ID': clientId
        },
        credentials: 'include'
      });
      if (response.ok) {
        const json = await response.json();
        setData(json);
        hasDataRef.current = true;
      } else {
        if (response.status === 401 && !isRetry) {
          if (onReinitSession) await onReinitSession();
          // After refreshing, try one more time and await it so finally block doesn't run prematurely
          return await fetchAnalytics(isSilent, true);
        }
        if (!isSilent) setError(true);
      }
    } catch (err) {
      console.error("Failed to fetch analytics:", err);
      if (!isSilent) setError(true);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, [days, clientId, onReinitSession]);

  useEffect(() => {
    if (!isInitializing && !initError && clientId) {
      fetchAnalytics();
    }
  }, [fetchAnalytics, isInitializing, initError, clientId]);

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

  const handleCardClick = async (filterKey: string, isRetry = false) => {
    if (activeFilter === filterKey) {
      setActiveFilter(null);
      return;
    }
    
    setActiveFilter(filterKey);
    setScanListLoading(true);
    
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
      const endpoint = activeTab === 'url' ? 'scans' : 'email-scans';
      const res = await fetch(`${API_BASE_URL}/api/v1/analytics/${endpoint}?filter=${filterKey}&days=${days}`, {
        headers: {
          'X-Client-ID': clientId
        },
        credentials: 'include'
      });
      if (res.ok) {
        const rawList = await res.json();
        // Transform email list to match ScanListItem interface if needed
        const list = activeTab === 'url' ? rawList : rawList.map((s: any) => ({
          url: s.sender_domain || s.scan_id, 
          risk_level: s.verdict_label.toLowerCase(),
          risk_score: s.final_risk_score,
          brand_name: null,
          timestamp: s.timestamp
        }));
        setScanList(list);
        setScanListError(null);
      } else if (res.status === 401 && !isRetry) {
        if (onReinitSession) await onReinitSession();
        return await handleCardClick(filterKey, true);
      } else {
        const errorText = await res.text();
        setScanListError(`Error ${res.status}: ${errorText || 'Failed to fetch forensic logs'}`);
        setScanList([]);
      }
    } catch (err) {
      console.error("Failed to fetch scan list:", err);
      setScanListError("Network error: Unable to connect to forensic service");
      setScanList([]);
    } finally {
      setScanListLoading(false);
    }
  };

  const stats = useMemo(() => {
    if (!data) return [];
    
    const currentData = activeTab === 'url' ? data.url : data.email;
    const dist: Record<string, number> = {};
    Object.entries(currentData.risk_distribution).forEach(([k, v]) => {
      dist[k.toLowerCase()] = v;
    });

    return [
      { 
        label: `Total ${activeTab.toUpperCase()} Scans`, 
        value: currentData.total_scans, 
        icon: Activity, 
        color: 'text-zinc-400',
        filterKey: 'all'
      },
      { 
        label: 'Malicious', 
        value: (dist['high'] || 0) + (dist['malicious'] || 0), 
        icon: ShieldAlert, 
        color: 'text-rose-500',
        filterKey: 'malicious'
      },
      { 
        label: 'Suspicious', 
        value: (dist['medium'] || 0) + (dist['suspicious'] || 0), 
        icon: AlertTriangle, 
        color: 'text-amber-500',
        filterKey: 'suspicious'
      },
      { 
        label: 'Safe', 
        value: (dist['low'] || 0) + (dist['safe'] || 0), 
        icon: ShieldCheck, 
        color: 'text-cyber-light-accent-deep dark:text-ornex-green',
        filterKey: 'safe'
      },
    ];
  }, [data, activeTab]);

  if (isInitializing || (loading && !data)) {
    return (
      <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-md">
        <div className="flex flex-col items-center gap-6 animate-pulse">
          <div className="w-16 h-16 border-4 border-cyber-light-accent/20 dark:border-ornex-green/20 border-t-cyber-light-accent dark:border-t-ornex-green rounded-full animate-spin"></div>
          <div className="text-center space-y-2">
            <h3 className="text-xl font-black text-white uppercase tracking-[0.2em]">Forensic Link Active</h3>
            <p className="text-zinc-500 font-mono text-xs uppercase tracking-widest">Establishing secure intel tunnel...</p>
          </div>
        </div>
      </div>
    );
  }

  if (initError || error || !data) {
    return (
      <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-md">
        <div className="bg-white dark:bg-black border border-zinc-200 dark:border-ornex-green/20 rounded-3xl p-8 text-center max-w-sm animate-in zoom-in duration-300 shadow-2xl">
          <AlertTriangle className="w-12 h-12 text-amber-500 mx-auto mb-4" />
          <h3 className="text-xl font-bold text-zinc-900 dark:text-white mb-2 tracking-tight">Forensic Link {initError ? 'Initialization Error' : 'Offline'}</h3>
          <p className="text-zinc-500 dark:text-zinc-400 text-sm mb-6">
            {initError || "Could not establish connection to the intelligence server."}
          </p>
          <div className="flex flex-col gap-3">
            <button 
              onClick={() => {
                if (initError) {
                  // This should ideally trigger the parent's initSession, 
                  // but we'll let it try to fetch if clientId magically appeared
                  fetchAnalytics();
                } else {
                  fetchAnalytics();
                }
              }}
              className="w-full px-4 py-2.5 bg-cyber-light-accent dark:bg-ornex-green text-white dark:text-black rounded-xl text-xs font-black uppercase tracking-widest hover:scale-105 transition-all shadow-lg"
            >
              {initError ? 'Retry Session Link' : 'Retry Data Sync'}
            </button>
            <button 
              onClick={onClose}
              className="w-full px-4 py-2.5 bg-zinc-100 dark:bg-white/5 text-zinc-500 dark:text-white rounded-xl text-xs font-bold uppercase tracking-widest hover:bg-zinc-200 dark:hover:bg-white/10 transition-all"
            >
              Close Intelligence Console
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 md:p-8 bg-black/80 backdrop-blur-md animate-in fade-in duration-300">
      <div className="relative w-full max-w-6xl max-h-[95vh] overflow-hidden bg-cyber-light-bg dark:bg-ornex-panel border border-cyber-light-border dark:border-white/10 rounded-3xl shadow-[0_0_80px_rgba(0,0,0,0.8)] flex flex-col">
        {/* Background Depth Glows */}
        <div className="absolute top-0 left-1/4 w-1/2 h-64 bg-ornex-green/5 blur-[120px] pointer-events-none" />
        <div className="absolute bottom-0 right-1/4 w-1/2 h-64 bg-ornex-green/3 blur-[120px] pointer-events-none" />
        
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between p-4 md:p-6 border-b border-cyber-light-border dark:border-white/5 bg-cyber-light-bg/50 dark:bg-ornex-panel/50 backdrop-blur-xl gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 md:p-2.5 bg-cyber-light-accent/10 dark:bg-ornex-green/20 rounded-xl relative">
              <BarChart3 className="w-5 h-5 md:w-6 md:h-6 text-cyber-light-accent dark:text-ornex-green" />
              {isRefreshing && (
                <div className="absolute -top-1 -right-1 w-2.5 h-2.5 md:w-3 md:h-3 bg-ornex-green rounded-full animate-ping" />
              )}
            </div>
            <div className="min-w-0">
              <h2 className="text-lg md:text-xl font-bold text-cyber-light-heading dark:text-white tracking-tight truncate">Forensic Intelligence</h2>
              <p className="text-[9px] md:text-[11px] text-cyber-light-text dark:text-ornex-green font-mono uppercase tracking-[0.2em] opacity-80 truncate">Real-time Threat Monitoring</p>
            </div>
          </div>

          <div className="flex items-center justify-between sm:justify-end gap-3 md:gap-6">
            <div className="flex items-center gap-1 bg-black/5 dark:bg-ornex-panel rounded-xl p-1 border border-cyber-light-border dark:border-white/5">
              {[7, 30, 0].map(d => (
                <button
                  key={d}
                  onClick={() => {
                    setDays(d);
                    setActiveFilter(null);
                  }}
                  className={`px-3 md:px-4 py-1 md:py-1.5 rounded-lg text-[10px] md:text-xs font-black transition-all tracking-widest ${
                    days === d 
                    ? 'bg-gradient-to-r from-cyber-light-accent to-cyber-light-accent-deep dark:from-[#00C853] dark:to-ornex-green text-white dark:text-black shadow-lg shadow-cyber-light-accent/30 dark:shadow-ornex-green/20' 
                      : 'text-cyber-light-text/70 dark:text-zinc-500 hover:text-cyber-light-heading dark:hover:text-white hover:bg-black/10 dark:hover:bg-white/5'
                  }`}
                >
                  {d === 0 ? 'ALL' : `${d}D`}
                </button>
              ))}
            </div>
            
            <button 
              onClick={() => fetchAnalytics()}
              disabled={isRefreshing}
              className={`group/refresh p-2 rounded-xl border transition-all duration-300 flex items-center justify-center
                ${isRefreshing 
                  ? 'bg-cyber-light-accent/10 dark:bg-ornex-green/10 border-cyber-light-accent/30 dark:border-ornex-green/30 text-cyber-light-accent dark:text-ornex-green' 
                  : 'bg-black/5 dark:bg-white/5 border-cyber-light-border dark:border-white/5 text-zinc-500 hover:text-cyber-light-accent dark:hover:text-ornex-green hover:border-cyber-light-accent/30 dark:hover:border-ornex-green/30 hover:bg-cyber-light-accent/5 dark:hover:bg-ornex-green/5'}`}
              title="Refresh Forensic Data"
            >
              <RefreshCw className={`w-4 h-4 md:w-5 md:h-5 ${isRefreshing ? 'animate-spin' : 'group-hover/refresh:rotate-180 transition-transform duration-500'}`} />
            </button>

            <button 
              onClick={onClose}
              className="p-2 hover:bg-zinc-200 dark:hover:bg-white/10 rounded-full transition-colors text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white"
            >
              <X className="w-5 h-5 md:w-6 md:h-6" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto overscroll-contain p-6 md:p-8 space-y-8 custom-scrollbar relative">
          
          {/* Tab Switcher */}
          <div className="flex items-center gap-2 md:gap-4 border-b border-zinc-200 dark:border-white/5 pb-4 overflow-x-auto no-scrollbar">
            <button
              onClick={() => {
                setActiveTab('url');
                setActiveFilter(null);
              }}
              className={`flex items-center gap-2 px-4 md:px-6 py-2 md:py-2.5 rounded-xl md:rounded-2xl text-xs md:text-sm font-bold transition-all relative whitespace-nowrap ${
                activeTab === 'url'
                  ? 'text-cyber-light-accent-deep dark:text-ornex-green bg-cyber-light-accent/15 dark:bg-ornex-green/10 border border-cyber-light-accent/30 dark:border-ornex-green/20 shadow-sm'
                  : 'text-zinc-500 hover:text-cyber-light-heading dark:hover:text-white hover:bg-zinc-100 dark:hover:bg-white/5 border border-transparent'
              }`}
            >
              <Globe className={`w-3.5 h-3.5 md:w-4 md:h-4 ${activeTab === 'url' ? 'animate-pulse' : ''}`} />
              URL Intelligence
              {activeTab === 'url' && (
                <div className="absolute -bottom-4 left-1/2 -translate-x-1/2 w-10 md:w-12 h-1 bg-cyber-light-accent dark:bg-ornex-green rounded-full shadow-[0_0_10px_rgba(16,185,129,0.3)]" />
              )}
              <span className={`ml-1.5 px-2 py-0.5 rounded-lg text-[9px] md:text-[11px] font-mono font-bold transition-colors ${
                activeTab === 'url' 
                  ? 'bg-cyber-light-accent/20 text-cyber-light-accent-deep dark:bg-ornex-green/20 dark:text-ornex-green' 
                  : 'bg-zinc-200/80 text-zinc-500 dark:bg-black/40 dark:text-zinc-500'
              }`}>
                {data.url.total_scans}
              </span>
            </button>
            <button
              onClick={() => {
                setActiveTab('email');
                setActiveFilter(null);
              }}
              className={`flex items-center gap-2 px-4 md:px-6 py-2 md:py-2.5 rounded-xl md:rounded-2xl text-xs md:text-sm font-bold transition-all relative whitespace-nowrap ${
                activeTab === 'email'
                  ? 'text-cyber-light-accent-deep dark:text-ornex-green bg-cyber-light-accent/15 dark:bg-ornex-green/10 border border-cyber-light-accent/30 dark:border-ornex-green/20 shadow-sm'
                  : 'text-zinc-500 hover:text-cyber-light-heading dark:hover:text-white hover:bg-zinc-100 dark:hover:bg-white/5 border border-transparent'
              }`}
            >
              <ShieldAlert className={`w-3.5 h-3.5 md:w-4 md:h-4 ${activeTab === 'email' ? 'animate-pulse' : ''}`} />
              Email Intelligence
              {activeTab === 'email' && (
                <div className="absolute -bottom-4 left-1/2 -translate-x-1/2 w-10 md:w-12 h-1 bg-cyber-light-accent dark:bg-ornex-green rounded-full shadow-[0_0_10px_rgba(16,185,129,0.3)]" />
              )}
              <span className={`ml-1.5 px-2 py-0.5 rounded-lg text-[9px] md:text-[11px] font-mono font-bold transition-colors ${
                activeTab === 'email' 
                  ? 'bg-cyber-light-accent/20 text-cyber-light-accent-deep dark:bg-ornex-green/20 dark:text-ornex-green' 
                  : 'bg-zinc-200/80 text-zinc-500 dark:bg-black/40 dark:text-zinc-500'
              }`}>
                {data.email.total_scans}
              </span>
            </button>
          </div>
          
          {/* Stats Flex Accordion */}
          <div className="flex flex-col md:flex-row items-start gap-3 md:gap-4 relative z-[106] min-h-[140px]">
            {stats.map((stat, i) => {
              const isActive = activeFilter === stat.filterKey;
              const riskColor = stat.color.replace('text-', 'bg-');
              
              return (
                <div 
                  key={i} 
                  className={`transition-all duration-700 ease-[cubic-bezier(0.2,0,0,1)] ${isActive ? 'md:flex-[4] h-auto' : 'flex-1'} min-w-0 group`}
                >
                  <div 
                    onClick={() => handleCardClick(stat.filterKey)}
                    className={`relative p-4 md:p-6 border rounded-2xl md:rounded-3xl cursor-pointer transition-all duration-700 ease-[cubic-bezier(0.2,0,0,1)] overflow-hidden flex flex-col h-full
                      ${isActive 
                        ? 'bg-cyber-light-bg dark:bg-ornex-panel border-cyber-light-accent/40 dark:border-ornex-green/40 shadow-[0_25px_60px_rgba(0,0,0,0.9),0_0_20px_rgba(0,255,65,0.15)] md:scale-[1.02]' 
                        : 'bg-zinc-100/60 dark:bg-zinc-900/50 border-zinc-200/50 dark:border-white/10 hover:bg-zinc-100/80 dark:hover:bg-zinc-900/80 shadow-xl hover:shadow-cyber-light-accent/10 dark:hover:shadow-ornex-green/10 md:hover:-translate-y-2'}`}
                  >
                    {/* Background Glow Effect */}
                    <div className={`absolute -top-20 -right-20 w-40 h-40 rounded-full blur-[80px] transition-opacity duration-700 ${isActive ? 'opacity-10' : 'opacity-0'} ${riskColor}`} />
                    
                    <div className={`flex flex-col h-full ${!isActive ? 'justify-center items-center text-center' : ''}`}>
                      <div className={`flex items-center justify-between ${isActive ? 'mb-6' : 'mb-3'}`}>
                        <div className={`p-2.5 rounded-xl ${isActive ? 'bg-zinc-50 dark:bg-white/5 border border-zinc-200 dark:border-white/10' : ''}`}>
                          <stat.icon className={`w-5 h-5 ${stat.color} transition-all duration-500 ${!isActive ? 'group-hover:scale-110' : ''}`} />
                        </div>
                        {isActive && (
                          <div className="flex items-center gap-1.5 px-2 py-0.5 bg-cyber-light-accent/10 dark:bg-ornex-green/10 rounded-full border border-cyber-light-accent/20 dark:border-ornex-green/20">
                             <span className="text-[11px] font-black text-cyber-light-accent dark:text-ornex-green uppercase tracking-widest animate-pulse">Live</span>
                             <div className="w-1 h-1 rounded-full bg-cyber-light-accent dark:bg-ornex-green" />
                          </div>
                        )}
                      </div>

                      <div className="relative">
                        <div className={`font-black text-cyber-light-accent-data dark:text-white tracking-tighter transition-all duration-500 leading-none
                          ${isActive ? 'text-4xl md:text-5xl mb-2' : 'text-xl md:text-2xl mb-1'}`}>
                          {stat.value}
                        </div>
                        <div className={`font-bold uppercase tracking-[0.2em] transition-all duration-500
                          ${isActive ? 'text-[10px] md:text-xs text-cyber-light-accent/70 dark:text-ornex-green/70' : 'text-[9px] md:text-xs text-zinc-500'}`}>
                          {stat.label}
                        </div>
                      </div>

                      {/* Smooth height-transitioned content */}
                      <div className={`grid transition-all duration-700 ease-[cubic-bezier(0.2,0,0,1)] ${isActive ? 'grid-rows-[1fr] opacity-100 mt-4 translate-y-0' : 'grid-rows-[0fr] opacity-0 mt-0 -translate-y-2'}`}>
                        <div className="overflow-hidden">
                          <ScanListInline 
                            scans={isActive ? scanList : []}
                            loading={isActive ? scanListLoading : false}
                            error={isActive ? scanListError : null}
                            color={stat.color}
                            riskLevelColor={riskColor}
                            onReview={onReview}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Tab-Specific Content */}
          <div className="animate-in fade-in slide-in-from-bottom-4 duration-700">
            {activeTab === 'url' ? (
              <div className="space-y-8">
                {/* Scan Volume Chart (URL) */}
                <div className="space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <h3 className="text-sm font-bold text-cyber-light-heading dark:text-zinc-300 flex items-center gap-2">
                      <TrendingUp className="w-4 h-4 text-cyber-light-accent dark:text-ornex-green" />
                      Activity Distribution
                      <SectionTooltip text="Daily volume of analyzed items over the selected time window." />
                    </h3>
                    <span className="text-[10px] md:text-xs text-cyber-light-text/70 dark:text-zinc-500 font-mono italic">
                      Last {activeTab === 'url' ? data.url.daily_volume.length : data.email.daily_volume.length} days
                    </span>
                  </div>
                  <div className="h-[140px] bg-zinc-100/40 dark:bg-zinc-900/40 rounded-3xl p-6 pb-10 border border-cyber-light-border dark:border-white/10 flex flex-col relative overflow-visible shadow-inner">
                    <div className="absolute inset-0 bg-gradient-to-t from-cyber-light-accent/5 dark:from-ornex-green/5 to-transparent pointer-events-none rounded-3xl" />
                    
                    {/* Grid Lines */}
                    <div className="absolute inset-0 p-6 pb-10 flex flex-col justify-between pointer-events-none opacity-20">
                      {[1, 2, 3].map(i => (
                        <div key={i} className="w-full h-px border-t border-dashed border-cyber-light-accent/20 dark:border-ornex-green/30" />
                      ))}
                    </div>

                    <div className="flex-1 flex items-end gap-2 relative z-10">
                      {data.url.daily_volume.length > 0 ? (
                        data.url.daily_volume.map((v, i) => {
                          const max = Math.max(...data.url.daily_volume.map(d => d.count), 1);
                          const height = (v.count / max) * 100;
                          return (
                            <div key={i} className="flex-1 flex flex-col items-center group relative h-full justify-end">
                              <div className="w-full flex flex-col justify-end items-center relative h-full">
                                <span className="text-[10px] text-cyber-light-accent-deep dark:text-ornex-green font-mono font-bold mb-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                  {v.count}
                                </span>
                                <div 
                                  className="w-[70%] bg-gradient-to-t from-cyber-light-accent/40 to-cyber-light-accent/20 dark:from-ornex-green/50 dark:to-ornex-green/25 group-hover:from-cyber-light-accent/60 group-hover:to-cyber-light-accent/40 dark:group-hover:from-ornex-green/70 dark:group-hover:to-ornex-green/40 border-t-2 border-cyber-light-accent dark:border-ornex-green rounded-t-lg transition-all duration-500 ease-out relative shadow-[0_-4px_12px_rgba(0,200,83,0.1)] overflow-hidden"
                                  style={{ height: v.count > 0 ? `${Math.max(height, 8)}%` : '2px', opacity: v.count > 0 ? 1 : 0.2 }}
                                >
                                  {/* Scanline effect */}
                                  <div className="absolute inset-0 bg-[linear-gradient(0deg,transparent_24%,rgba(255,255,255,0.05)_25%,rgba(255,255,255,0.05)_26%,transparent_27%,transparent_74%,rgba(255,255,255,0.05)_75%,rgba(255,255,255,0.05)_76%,transparent_77%)] bg-[length:100%_4px] opacity-20" />
                                  
                                  <div className="absolute -top-12 left-1/2 -translate-x-1/2 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white text-[9px] py-1 px-2 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none border border-zinc-200 dark:border-white/10 whitespace-nowrap z-50 shadow-xl">
                                    {new Date(v.date.replace(/-/g, '/')).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} - {v.count} scans
                                  </div>
                                </div>
                              </div>
                              <span className="text-[9px] text-cyber-light-text font-mono font-bold uppercase mt-2 absolute -bottom-6">
                                {new Date(v.date.replace(/-/g, '/')).toLocaleDateString(undefined, { weekday: 'short' })}
                              </span>
                            </div>
                          );
                        })
                      ) : (
                        <div className="flex-1 flex items-center justify-center text-zinc-500 font-mono text-[10px] uppercase tracking-widest italic opacity-50">
                          Insufficient data for volume analysis
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Infrastructure Risk: Top Malicious TLDs */}
                <div className="space-y-4">
                  <h3 className="text-sm font-bold text-cyber-light-heading dark:text-zinc-300 flex items-center gap-2">
                    <Layers className="w-4 h-4 text-amber-500" />
                    Infrastructure Risk
                    <SectionTooltip text="Top-level domains associated with malicious infrastructure." />
                  </h3>
                  <div className="bg-zinc-100/40 dark:bg-zinc-900/40 rounded-3xl p-5 md:p-6 border border-cyber-light-border dark:border-white/10 shadow-inner">
                    <div className="grid grid-cols-1 xs:grid-cols-2 md:grid-cols-4 gap-3 md:gap-4 items-start">
                      {data.url.top_malicious_tlds.length > 0 ? (
                        data.url.top_malicious_tlds.map((t, i) => {
                          const isHighRisk = t.malicious_pct > 70;
                          return (
                            <div key={i} className={`group relative p-3.5 md:p-4 bg-zinc-100/50 dark:bg-black/20 rounded-xl md:rounded-2xl border ${isHighRisk ? 'border-rose-500/30 bg-rose-500/5' : 'border-zinc-200 dark:border-white/5'} transition-all hover:translate-y-[-2px] hover:shadow-lg overflow-hidden`}>
                              <div className="flex items-center gap-3 mb-2 md:mb-3">
                                <div className={`p-1.5 md:p-2 rounded-lg md:rounded-xl ${isHighRisk ? 'bg-rose-500/10 text-rose-500' : 'bg-amber-500/10 text-amber-500'}`}>
                                  <Globe className="w-3.5 h-3.5 md:w-4 md:h-4" />
                                </div>
                                <div className="flex flex-col min-w-0">
                                  <span className="text-sm md:text-base font-black text-zinc-900 dark:text-white leading-tight truncate">{t.tld}</span>
                                  <span className="text-[8px] md:text-[9px] font-mono uppercase text-zinc-500 tracking-widest">{t.count} Scans</span>
                                </div>
                              </div>

                              <div className="space-y-1.5">
                                <div className="flex justify-between items-end">
                                  <span className={`text-[11px] font-bold uppercase tracking-tighter ${isHighRisk ? 'text-rose-500' : 'text-amber-500'}`}>
                                    {isHighRisk ? 'High Threat Density' : 'Infrastucture Risk'}
                                  </span>
                                  <span className="text-xs font-mono font-black text-zinc-900 dark:text-white">{t.malicious_pct}%</span>
                                </div>
                                <div className="h-2 w-full bg-zinc-200 dark:bg-white/5 rounded-full overflow-hidden shadow-inner">
                                  <div 
                                    className={`h-full bg-gradient-to-r ${isHighRisk ? 'from-rose-600 to-rose-400' : 'from-amber-600 to-amber-400'} rounded-full transition-all duration-1000 ease-out shadow-[0_0_8px_rgba(244,63,94,0.3)]`} 
                                    style={{ width: `${t.malicious_pct}%` }} 
                                  />
                                </div>
                              </div>
                            </div>
                          );
                        })
                      ) : (
                        <div className="col-span-full py-8 text-center text-zinc-500 font-mono text-[10px] uppercase tracking-widest italic">
                          No malicious TLD patterns detected in current window
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="space-y-8">
                {/* Scan Volume Chart (Email) */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-cyber-light-heading dark:text-zinc-300 flex items-center gap-2">
                      <TrendingUp className="w-4 h-4 text-cyber-light-accent dark:text-ornex-green" />
                      Email Forensic Activity Distribution
                      <SectionTooltip text="Volume of deep-scan email forensic analyses processed. Peak activity often correlates with active phishing campaigns." />
                    </h3>
                    <span className="text-xs text-cyber-light-text/70 dark:text-zinc-500 font-mono italic">
                      Showing last {data.email.daily_volume.length} days
                    </span>
                  </div>
                  <div className="h-[140px] bg-zinc-100/40 dark:bg-zinc-900/40 rounded-3xl p-6 pb-10 border border-cyber-light-border dark:border-white/10 flex flex-col relative overflow-visible shadow-inner">
                    <div className="absolute inset-0 bg-gradient-to-t from-cyber-light-accent/5 dark:from-ornex-green/5 to-transparent pointer-events-none rounded-3xl" />
                    
                    {/* Grid Lines */}
                    <div className="absolute inset-0 p-6 pb-10 flex flex-col justify-between pointer-events-none opacity-20">
                      {[1, 2, 3].map(i => (
                        <div key={i} className="w-full h-px border-t border-dashed border-cyber-light-accent/20 dark:border-ornex-green/30" />
                      ))}
                    </div>

                    <div className="flex-1 flex items-end gap-2 relative z-10">
                      {data.email.daily_volume.length > 0 ? (
                        data.email.daily_volume.map((v, i) => {
                          const max = Math.max(...data.email.daily_volume.map(d => d.count), 1);
                          const height = (v.count / max) * 100;
                          return (
                            <div key={i} className="flex-1 flex flex-col items-center group relative h-full justify-end">
                              <div className="w-full flex flex-col justify-end items-center relative h-full">
                                <span className="text-[10px] text-cyber-light-accent-deep dark:text-ornex-green font-mono font-bold mb-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                  {v.count}
                                </span>
                                <div 
                                  className="w-[70%] bg-gradient-to-t from-cyber-light-accent/40 to-cyber-light-accent/20 dark:from-ornex-green/50 dark:to-ornex-green/25 group-hover:from-cyber-light-accent/60 group-hover:to-cyber-light-accent/40 dark:group-hover:from-ornex-green/70 dark:group-hover:to-ornex-green/40 border-t-2 border-cyber-light-accent dark:border-ornex-green rounded-t-lg transition-all duration-500 ease-out relative shadow-[0_-4px_12px_rgba(0,200,83,0.1)] overflow-hidden"
                                  style={{ height: v.count > 0 ? `${Math.max(height, 8)}%` : '2px', opacity: v.count > 0 ? 1 : 0.2 }}
                                >
                                  {/* Scanline effect */}
                                  <div className="absolute inset-0 bg-[linear-gradient(0deg,transparent_24%,rgba(255,255,255,0.05)_25%,rgba(255,255,255,0.05)_26%,transparent_27%,transparent_74%,rgba(255,255,255,0.05)_75%,rgba(255,255,255,0.05)_76%,transparent_77%)] bg-[length:100%_4px] opacity-20" />
                                  
                                  <div className="absolute -top-12 left-1/2 -translate-x-1/2 bg-cyber-light-bg dark:bg-zinc-800 text-zinc-900 dark:text-white text-[9px] py-1 px-2 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none border border-zinc-200 dark:border-white/10 whitespace-nowrap z-50 shadow-xl">
                                    {new Date(v.date.replace(/-/g, '/')).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} - {v.count} forensic logs
                                  </div>
                                </div>
                              </div>
                              <span className="text-[9px] text-cyber-light-text font-mono font-bold uppercase mt-2 absolute -bottom-6">
                                {new Date(v.date.replace(/-/g, '/')).toLocaleDateString(undefined, { weekday: 'short' })}
                              </span>
                            </div>
                          );
                        })
                      ) : (
                        <div className="flex-1 flex items-center justify-center text-zinc-500 font-mono text-[10px] uppercase tracking-widest italic opacity-50">
                          Insufficient data for volume analysis
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Email Intelligence View */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
                  {/* How They Attacked */}
                  <div className="space-y-4 flex flex-col h-full">
                    <h3 className="text-sm font-bold text-cyber-light-heading dark:text-zinc-300 flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-rose-500" />
                      How They Attacked
                      <SectionTooltip text="Categorizes the 'psychological angle' or technical weakness exploited in the detected phishing attempts." />
                      <span className="text-[11px] text-rose-600 dark:text-rose-400/80 font-mono ml-2 bg-rose-500/5 px-2 py-0.5 rounded-lg border border-rose-500/10 uppercase">Primary Method</span>
                    </h3>
                    <div className="bg-zinc-100/40 dark:bg-zinc-900/40 rounded-[2.5rem] p-6 sm:p-8 border border-cyber-light-border dark:border-white/10 shadow-2xl flex flex-col flex-1 h-full min-h-[340px] relative overflow-visible group/card">
                      {/* Decorative Background Elements Wrapper */}
                      <div className="absolute inset-0 overflow-hidden pointer-events-none rounded-[2.5rem] z-0">
                        <div className="absolute -top-24 -right-24 w-64 h-64 bg-rose-500/10 rounded-full blur-[80px] group-hover/card:bg-rose-500/20 transition-colors duration-1000" />
                        <div className="absolute -bottom-24 -left-24 w-64 h-64 bg-purple-500/5 rounded-full blur-[80px] group-hover/card:bg-purple-500/10 transition-colors duration-1000" />
                      </div>
                      <div className="relative z-10 h-full flex flex-col">
                      {data.email.attack_vectors.length > 0 ? (
                        <div className="flex-1 flex flex-col sm:flex-row items-center justify-center gap-6 md:gap-8 w-full py-1">
                          {/* Advanced Donut Chart */}
                          <div className="relative w-20 h-20 md:w-24 md:h-24 shrink-0 group/chart">
                            {/* Background Secondary Ring for context (Other Methods) */}
                            <div className="absolute inset-[-10%] rounded-full border-[6px] border-zinc-100 dark:border-white/[0.03] pointer-events-none" />
                            <div className="absolute inset-[-10%] rounded-full border-[6px] border-transparent border-t-purple-500/20 border-r-blue-500/20 pointer-events-none animate-[spin_8s_linear_infinite]" />
                            
                            <div 
                              className="absolute inset-0 rounded-full shadow-[0_0_20px_rgba(244,63,94,0.15)] dark:shadow-none z-10" 
                              style={{ 
                                background: `conic-gradient(
                                  #f43f5e 0% ${data.email.attack_vectors[0]?.percentage || 0}%, 
                                  #f59e0b ${data.email.attack_vectors[0]?.percentage || 0}% ${(data.email.attack_vectors[0]?.percentage || 0) + (data.email.attack_vectors[1]?.percentage || 0)}%, 
                                  #a855f7 ${(data.email.attack_vectors[0]?.percentage || 0) + (data.email.attack_vectors[1]?.percentage || 0)}% ${(data.email.attack_vectors[0]?.percentage || 0) + (data.email.attack_vectors[1]?.percentage || 0) + (data.email.attack_vectors[2]?.percentage || 0)}%,
                                  #3b82f6 ${(data.email.attack_vectors[0]?.percentage || 0) + (data.email.attack_vectors[1]?.percentage || 0) + (data.email.attack_vectors[2]?.percentage || 0)}% 100%
                                )` 
                              }} 
                            />
                            {/* Inner Glass Ring */}
                            <div className="absolute inset-[15%] bg-cyber-light-bg/90 dark:bg-zinc-950/90 backdrop-blur-md rounded-full border border-white/20 dark:border-white/5 flex items-center justify-center flex-col shadow-inner overflow-hidden">
                              <div className="absolute inset-0 bg-gradient-to-br from-white/50 to-transparent dark:from-white/5 opacity-50" />
                              <span className="relative text-lg md:text-2xl font-black text-zinc-900 dark:text-white leading-none">
                                {data.email.attack_vectors[0]?.percentage || 0}%
                              </span>
                              <span className="relative text-[8px] md:text-[10px] font-mono uppercase text-zinc-400 mt-0.5 tracking-tighter">Major</span>
                            </div>
                          </div>

                          {/* Data-Rich List */}
                          <div className="flex-1 space-y-3 w-full">
                            {data.email.attack_vectors.map((av, i) => {
                              const colors = [
                                { bg: 'bg-rose-500', text: 'text-rose-600 dark:text-rose-500', border: 'border-rose-500/10', bar: 'bg-rose-500/10' },
                                { bg: 'bg-amber-500', text: 'text-amber-700 dark:text-amber-500', border: 'border-amber-500/10', bar: 'bg-amber-500/10' },
                                { bg: 'bg-purple-500', text: 'text-purple-600 dark:text-purple-500', border: 'border-purple-500/10', bar: 'bg-purple-500/10' },
                                { bg: 'bg-blue-500', text: 'text-blue-600 dark:text-blue-500', border: 'border-blue-500/10', bar: 'bg-blue-500/10' }
                              ][i] || { bg: 'bg-zinc-500', text: 'text-zinc-700 dark:text-zinc-500', border: 'border-zinc-500/10', bar: 'bg-zinc-500/10' };

                              const getIcon = (cat: string) => {
                                const low = cat.toLowerCase();
                                if (low.includes('financial') || low.includes('payment')) return <CreditCard className="w-3.5 h-3.5" />;
                                if (low.includes('identity') || low.includes('credential')) return <User className="w-3.5 h-3.5" />;
                                if (low.includes('urgent') || low.includes('fear')) return <Zap className="w-3.5 h-3.5" />;
                                if (low.includes('reward') || low.includes('winning')) return <Gift className="w-3.5 h-3.5" />;
                                if (low.includes('technical') || low.includes('it')) return <Terminal className="w-3.5 h-3.5" />;
                                return <AlertTriangle className="w-3.5 h-3.5" />;
                              };

                              return (
                                <div key={i} className="group/item relative">
                                  <div className="flex items-center justify-between text-sm mb-1.5 relative z-10">
                                    <div className="flex items-center gap-3 min-w-0">
                                      <div className={`p-1.5 md:p-2 rounded-lg md:rounded-xl ${colors.bar} ${colors.text} border ${colors.border} transition-transform group-hover/item:scale-110 shadow-sm`}>
                                        {getIcon(av.category)}
                                      </div>
                                      <div className="flex flex-col">
                                        <span className={`text-[11px] md:text-[12px] ${colors.text} font-black truncate leading-tight tracking-tight uppercase`}>{av.category}</span>
                                        <span className="text-[9px] md:text-[11px] text-zinc-700 dark:text-zinc-300 font-bold mt-1 uppercase tracking-[0.05em]">{av.count} detected</span>
                                      </div>
                                    </div>
                                    <div className="flex flex-col items-end shrink-0 ml-4">
                                      <span className={`font-mono font-black ${colors.text} text-sm md:text-xl leading-none`}>{av.percentage}%</span>
                                      <span className="text-[7px] md:text-[8px] text-zinc-400 uppercase font-bold mt-1 tracking-tighter">Impact</span>
                                    </div>
                                  </div>
                                  {/* Progress Bar Container */}
                                  <div className="h-1.5 md:h-2 w-full bg-zinc-100 dark:bg-white/5 rounded-full overflow-hidden shadow-inner border border-black/[0.02] dark:border-white/[0.02]">
                                    <div 
                                      className={`h-full ${colors.bg} rounded-full transition-all duration-1000 ease-out delay-300 shadow-[0_0_12px_rgba(0,0,0,0.1)]`}
                                      style={{ width: `${av.percentage}%` }}
                                    />
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      ) : (
                        <div className="flex-1 flex items-center justify-center text-zinc-500 font-mono text-[10px] uppercase tracking-widest italic">
                          Insufficient email data for vector analysis
                        </div>
                      )}
                      {/* User-Friendly Insight */}
                     </div>
                    </div>
                  </div>

                  {/* Forensic Confidence Trend */}
                  <div className="space-y-4 flex flex-col h-full">
                    <h3 className="text-sm font-bold text-cyber-light-heading dark:text-zinc-300 flex items-center gap-2">
                      <Microscope className="w-4 h-4 text-purple-500" />
                      How Sure is the AI?
                      <SectionTooltip text="The Forensic Certainty Index (FCI) measures the conclusiveness of evidence. A low average often indicates a high volume of safe traffic diluting the peak malicious certainty." />
                      <span className="text-[11px] text-purple-600 dark:text-purple-400/80 font-mono ml-2 bg-purple-500/5 px-2 py-0.5 rounded-lg border border-purple-500/10 uppercase">FCI Analytics</span>
                    </h3>
                    <div className="bg-zinc-100/40 dark:bg-zinc-900/40 rounded-[2.5rem] p-6 sm:p-8 border border-cyber-light-border dark:border-white/10 shadow-2xl min-h-[340px] relative flex flex-col flex-1 h-full group/card overflow-visible">
                      {/* Decorative Background Elements Wrapper */}
                      <div className="absolute inset-0 overflow-hidden pointer-events-none rounded-[2.5rem] z-0">
                        <div className="absolute -top-24 -right-24 w-64 h-64 bg-purple-500/10 rounded-full blur-[80px] group-hover/card:bg-purple-500/20 transition-colors duration-1000" />
                        <div className="absolute -bottom-24 -left-24 w-64 h-64 bg-ornex-green/5 rounded-full blur-[80px] group-hover/card:bg-ornex-green/10 transition-colors duration-1000" />
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-12 gap-8 relative z-10 h-full flex-1">
                        {/* Left: Large Circular Gauge */}
                        <div className="md:col-span-5 flex flex-col items-center justify-center p-4 bg-zinc-900/5 dark:bg-black/20 rounded-[2rem] border border-black/5 dark:border-white/5 relative group/gauge">
                           {/* Glow Ring */}
                           <div className="absolute inset-0 rounded-[2rem] bg-purple-500/0 group-hover/gauge:bg-purple-500/5 transition-all duration-700" />
                           
                           {/* Main Value */}
                           <div className="relative w-32 h-32 md:w-40 md:h-40 flex items-center justify-center">
                              <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 100 100">
                                 <circle
                                    cx="50" cy="50" r="40"
                                    className="stroke-zinc-200 dark:stroke-zinc-800 fill-none"
                                    strokeWidth="8"
                                 />
                                 {(() => {
                                   const rawPeak = Math.max(...data.email.confidence_trend.map(t => t.avg_quality));
                                   // Cap at 99% for forensic realism
                                   const peak = Math.min(0.99, rawPeak);
                                   const circumference = 2 * Math.PI * 40;
                                   const offset = circumference - (circumference * peak);
                                   return (
                                     <circle
                                        cx="50" cy="50" r="40"
                                        className="stroke-purple-500 fill-none transition-all duration-1000 ease-out"
                                        strokeWidth="8"
                                        strokeDasharray={circumference}
                                        strokeDashoffset={offset}
                                        strokeLinecap="round"
                                        style={{ filter: 'drop-shadow(0 0 8px rgba(168,85,247,0.4))' }}
                                     />
                                   );
                                 })()}
                              </svg>
                              <div className="absolute inset-0 flex flex-col items-center justify-center">
                                  <span className="text-3xl md:text-4xl font-black text-zinc-900 dark:text-white tabular-nums">
                                     {Math.round(Math.min(0.99, Math.max(...data.email.confidence_trend.map(t => t.avg_quality))) * 100)}%
                                  </span>
                                  <div className="flex flex-col items-center mt-1">
                                    <span className="text-[7px] md:text-[8px] font-bold text-zinc-500 dark:text-zinc-400 uppercase tracking-[0.2em] leading-tight">CONCLUSIVE</span>
                                    <span className="text-[7px] md:text-[8px] font-bold text-zinc-500 dark:text-zinc-400 uppercase tracking-[0.2em] leading-tight">EVIDENCE</span>
                                  </div>
                              </div>
                           </div>

                           <div className="mt-4 text-center">
                              {(() => {
                                 const avg = data.email.confidence_trend.reduce((acc, t) => acc + t.avg_quality, 0) / (data.email.confidence_trend.length || 1);
                                 const verdict = avg > 0.7 ? { label: "DECISIVE", color: "text-purple-500", desc: "High-fidelity evidence across all vectors" } : 
                                               avg > 0.4 ? { label: "SUBSTANTIVE", color: "text-amber-500", desc: "Consistent patterns with minor variances" } : 
                                               { label: "PRELIMINARY", color: "text-zinc-500", desc: "Limited evidence; requires deeper probing" };
                                 return (
                                   <>
                                     <div className={`text-[13px] font-black ${verdict.color} tracking-[0.25em] mb-1.5 drop-shadow-sm`}>{verdict.label} EVIDENCE</div>
                                     <div className="text-[9px] text-zinc-400 font-medium px-4 leading-tight">{verdict.desc}</div>
                                   </>
                                 );
                              })()}
                           </div>
                        </div>

                        {/* Right: Insights & Stats */}
                        <div className="md:col-span-7 flex flex-col justify-between space-y-4">
                           <div className="space-y-3">
                              <div className="flex items-center justify-start border-b border-black/5 dark:border-white/5 pb-3">
                                 <div className="flex flex-col">
                                    <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Total Intelligence</span>
                                    <span className="text-xl font-black text-zinc-900 dark:text-white tabular-nums">{data.email.total_scans} Scans</span>
                                 </div>
                              </div>

                              <div className="space-y-3">
                                 <h4 className="text-[10px] font-black text-zinc-500 uppercase tracking-[0.15em]">Certainty Timeline</h4>
                                 <div className="h-16 flex items-end gap-2 px-1 relative group/timeline">
                                    {/* Grid Lines */}
                                    <div className="absolute inset-0 flex flex-col justify-between pointer-events-none opacity-10 py-1">
                                      {[1, 2, 3].map(i => (
                                        <div key={i} className="w-full h-px border-t border-dashed border-zinc-400" />
                                      ))}
                                    </div>

                                    {/* Timeline Base Line */}
                                    <div className="absolute bottom-0 left-0 right-0 h-px bg-zinc-200 dark:bg-white/10" />
                                    
                                    {data.email.confidence_trend.map((t, i) => {
                                      const scaledVal = Math.min(100, Math.max(0, t.avg_quality * 100));
                                      const isLast = i === data.email.confidence_trend.length - 1;
                                      return (
                                        <div key={i} className="flex-1 h-full flex flex-col justify-end items-center group/dot relative">
                                          <InfoTooltip 
                                            text={`SESSION: ${new Date(t.date.replace(/-/g, '/')).toLocaleDateString()} | QUALITY: ${Math.round(scaledVal)}%`}
                                            className="h-full w-full flex justify-center text-[10px]"
                                          >
                                            <div 
                                               className={`w-3.5 rounded-t-md transition-all duration-500 absolute left-1/2 -translate-x-1/2 group-hover/dot:w-4
                                                  ${isLast 
                                                    ? 'bg-gradient-to-t from-purple-600 via-purple-500 to-purple-400 shadow-[0_0_20px_rgba(168,85,247,0.4)]' 
                                                    : 'bg-gradient-to-t from-zinc-500/50 via-zinc-400/40 to-zinc-300/30 group-hover/dot:from-purple-500/50 group-hover/dot:to-purple-400/50'}`}
                                               style={{ height: `${Math.max(scaledVal, isLast ? 25 : 12)}%`, bottom: 0 }}
                                            >
                                               {isLast && (
                                                 <div className="absolute inset-0 bg-white/20 rounded-full animate-pulse blur-[1px]" />
                                               )}
                                               <div className="absolute top-0 left-0 right-0 h-1 bg-white/10 rounded-full opacity-0 group-hover/dot:opacity-100 transition-opacity" />
                                            </div>
                                            <span className="absolute -bottom-6 left-1/2 -translate-x-1/2 text-[8px] font-mono font-bold text-zinc-400 dark:text-zinc-500 uppercase tracking-tighter transition-all">
                                              {new Date(t.date.replace(/-/g, '/')).toLocaleDateString(undefined, { weekday: 'short' })}
                                            </span>
                                          </InfoTooltip>
                                        </div>
                                      );
                                    })}
                                 </div>
                              </div>
                           </div>

                           {/* Analysis Footer */}
                           <div className="bg-purple-500/5 dark:bg-white/5 p-4 rounded-2xl border border-purple-500/10 dark:border-white/10">
                              <p className="text-[10px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
                                 The <strong>Forensic Certainty Index (FCI)</strong> correlates signals across linguistic intent, technical infrastructure, and reputation intelligence. A <strong>Conclusive</strong> rating indicates a high-fidelity match with confirmed adversarial patterns.
                              </p>
                           </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
                  {/* Authentication Posture */}
                  <div className="space-y-4 flex flex-col">
                    <h3 className="text-sm font-bold text-cyber-light-heading dark:text-zinc-300 flex items-center gap-2">
                      <Fingerprint className="w-4 h-4 text-cyber-light-accent-deep dark:text-ornex-green" />
                      Is the Sender Real?
                      <SectionTooltip text="Checks the sender's identity against global security standards (SPF, DKIM, DMARC) to detect spoofing." />
                      <span className="text-[11px] text-cyber-light-accent-deep/80 dark:text-ornex-green/60 font-mono ml-2 bg-cyber-light-accent/5 dark:bg-ornex-green/5 px-2 py-0.5 rounded-lg border border-cyber-light-accent/20 dark:border-ornex-green/10 uppercase">Identity Check</span>
                    </h3>
                    <div className="bg-zinc-100/40 dark:bg-zinc-900/40 rounded-3xl p-5 border border-cyber-light-border dark:border-white/10 shadow-inner flex flex-col justify-between flex-1 h-full min-h-[200px]">
                      <div className="space-y-3">
                        {['spf', 'dkim', 'dmarc'].map((type) => {
                          const stats = data.email.auth_posture[type as keyof typeof data.email.auth_posture];
                          const total = stats.pass + stats.fail + stats.none || 1;
                          const passPct = (stats.pass / total) * 100;
                          const failPct = (stats.fail / total) * 100;
                          const nonePct = (stats.none / total) * 100;

                          const tooltips = {
                            spf: "Sender Policy Framework | Validates authorized mail servers for a domain.",
                            dkim: "DomainKeys Identified Mail | Cryptographic signature to prevent email tampering.",
                            dmarc: "DMARC Policy | Orchestrates SPF/DKIM to provide a unified authentication verdict."
                          };

                          return (
                            <div key={type} className="group cursor-default">
                              <div className="flex items-center justify-between mb-2 relative z-10">
                                <div className="flex items-center gap-3">
                                  <div className={`w-1 h-6 md:h-8 rounded-full ${passPct > 80 ? 'bg-cyber-light-accent-deep dark:bg-ornex-green shadow-[0_0_8px_rgba(5,150,105,0.2)] dark:shadow-[0_0_8px_rgba(0,255,65,0.4)]' : passPct > 50 ? 'bg-amber-500' : 'bg-rose-500'}`} />
                                  <div className="flex flex-col">
                                    <div className="flex items-center gap-1.5">
                                      <InfoTooltip text={tooltips[type as keyof typeof tooltips]}>
                                        <span className="text-[11px] md:text-[12px] font-bold uppercase tracking-wider text-zinc-900 dark:text-zinc-100 hover:text-cyber-light-accent-deep dark:hover:text-ornex-green transition-colors cursor-help border-b border-dotted border-zinc-500/30">
                                          {type} Protocol
                                        </span>
                                      </InfoTooltip>
                                    </div>
                                    <span className="text-[10px] md:text-[11px] text-zinc-500 font-medium uppercase tracking-tight">Security Check</span>
                                  </div>
                                </div>
                                <div className="flex flex-col items-end">
                                  <span className={`text-xs md:text-[12px] font-mono font-black ${passPct > 80 ? 'text-cyber-light-accent-deep dark:text-ornex-green' : 'text-amber-500'} leading-none`}>
                                    {Math.round(passPct)}%
                                  </span>
                                  <span className="text-[8px] md:text-[10px] text-zinc-400 uppercase font-bold mt-1 tracking-tighter italic opacity-50">Score</span>
                                </div>
                              </div>
                              
                              <div className="relative h-2 md:h-2.5 w-full bg-zinc-200 dark:bg-black/20 rounded-full overflow-hidden flex gap-[2px] shadow-inner border border-black/[0.05] dark:border-white/[0.02]">
                                <div 
                                  className="h-full bg-cyber-light-accent dark:bg-ornex-green transition-all duration-1000 ease-out shadow-[0_0_12px_rgba(16,185,129,0.2)] dark:shadow-[0_0_12px_rgba(0,255,65,0.3)] rounded-l-full" 
                                  style={{ width: `${passPct}%` }} 
                                />
                                <div 
                                  className="h-full bg-rose-500 transition-all duration-1000 ease-out shadow-[0_0_12px_rgba(244,63,94,0.3)]" 
                                  style={{ width: `${failPct}%` }} 
                                />
                                <div 
                                  className="h-full bg-zinc-400 dark:bg-white/10 transition-all duration-1000 ease-out rounded-r-full" 
                                  style={{ width: `${nonePct}%` }} 
                                />
                              </div>
                            </div>
                          );
                        })}
                      </div>

                      <div className="flex flex-col sm:flex-row items-center justify-between mt-3 pt-3 border-t border-cyber-light-border dark:border-white/5 gap-3">
                        <div className="flex flex-wrap items-center justify-center gap-3 md:gap-4">
                          <div className="flex items-center gap-2">
                            <div className="w-2 md:w-2.5 h-2 md:h-2.5 rounded-full bg-cyber-light-accent-deep dark:bg-ornex-green shadow-[0_0_8px_rgba(5,150,105,0.3)] dark:shadow-[0_0_8px_rgba(0,255,65,0.5)]" />
                            <span className="text-[9px] md:text-[11px] font-bold uppercase text-zinc-500 dark:text-zinc-400 tracking-tight">Pass</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <div className="w-2 md:w-2.5 h-2 md:h-2.5 rounded-full bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.3)]" />
                            <span className="text-[9px] md:text-[11px] font-bold uppercase text-zinc-500 dark:text-zinc-400 tracking-tight">Fail</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <div className="w-2 md:w-2.5 h-2 md:h-2.5 rounded-full bg-zinc-400 shadow-[0_0_8px_rgba(161,161,170,0.2)]" />
                            <span className="text-[9px] md:text-[11px] font-bold uppercase text-zinc-500 dark:text-zinc-400 tracking-tight">None</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-1.5 text-cyber-light-accent-deep/80 dark:text-ornex-green/60 hover:text-cyber-light-accent-deep dark:hover:text-ornex-green transition-colors cursor-default group/verified">
                          <ShieldCheck className="w-3 md:w-3.5 h-3 md:h-3.5 transition-transform group-hover/verified:scale-110" />
                          <span className="text-[8px] md:text-[9px] font-black uppercase tracking-widest font-mono">Forensic Pipeline</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Hiding Techniques */}
                  <div className="space-y-4">
                    <h3 className="text-sm font-bold text-cyber-light-heading dark:text-zinc-300 flex items-center gap-2">
                      <Activity className="w-4 h-4 text-cyan-500" />
                      Hiding Techniques
                      <SectionTooltip text="Identifies clever tricks attackers use to hide malicious links or text from security scanners." />
                      <span className="text-[11px] text-cyan-600 dark:text-cyan-400/80 font-mono ml-2 bg-cyan-500/5 px-2 py-0.5 rounded-lg border border-cyan-500/10 uppercase">Detected Tricks</span>
                    </h3>
                    <div className="bg-zinc-100/40 dark:bg-zinc-900/40 rounded-3xl p-5 border border-cyber-light-border dark:border-white/10 shadow-inner min-h-[200px] flex flex-col relative overflow-hidden group/heatmap">
                      {/* Grid Backdrop */}
                      <div className="absolute inset-0 opacity-[0.02] dark:opacity-[0.05] pointer-events-none" style={{ backgroundImage: 'linear-gradient(currentColor 1px, transparent 1px), linear-gradient(to right, currentColor 1px, transparent 1px)', backgroundSize: '24px 24px' }} />
                      
                      {data.email.obfuscation_heatmap.length > 0 ? (
                        <div className="flex-1 flex flex-col gap-4 relative z-10">
                          {data.email.obfuscation_heatmap.map((h, i) => {
                            const maxCount = Math.max(...data.email.obfuscation_heatmap.map(x => x.count)) || 1;
                            const intensity = h.count / maxCount;
                            
                            return (
                              <div key={i} className="space-y-2">
                                <div className="flex items-center justify-between px-1">
                                  <div className="flex items-center gap-2">
                                    <div className={`w-1.5 h-3 rounded-full ${intensity > 0.7 ? 'bg-cyan-400' : intensity > 0.3 ? 'bg-cyan-600' : 'bg-cyan-900'}`} />
                                    <span className="text-[11px] font-bold text-zinc-900 dark:text-zinc-100 uppercase tracking-tight">{h.technique}</span>
                                  </div>
                                  <span className="text-[11px] font-mono font-black text-cyan-600 dark:text-cyan-400">INTENSITY: {Math.round(intensity * 100)}%</span>
                                </div>
                                
                                <div className="flex gap-1 h-4">
                                  {[...Array(12)].map((_, j) => {
                                    const threshold = (j + 1) / 12;
                                    const isActive = intensity >= threshold;
                                    return (
                                      <div 
                                        key={j} 
                                        className={`flex-1 rounded-sm transition-all duration-700
                                          ${isActive 
                                            ? 'bg-cyan-500/80 shadow-[0_0_12px_rgba(6,182,212,0.4)] border-t border-white/20' 
                                            : 'bg-zinc-500/10 dark:bg-white/5 border border-transparent'}
                                          ${j === 0 ? 'rounded-l-lg' : ''} ${j === 11 ? 'rounded-r-lg' : ''}`}
                                        style={{ opacity: isActive ? 0.3 + (j / 12) * 0.7 : 1 }}
                                      />
                                    );
                                  })}
                                </div>
                              </div>
                            );
                          })}

                          {/* Thermal Scale Legend */}
                          <div className="mt-auto pt-4 flex items-center justify-between border-t border-white/5 opacity-60">
                            <div className="flex items-center gap-4">
                              <div className="flex items-center gap-1.5">
                                <div className="w-2 h-2 rounded-sm bg-cyan-900" />
                                <span className="text-[10px] font-bold uppercase text-zinc-500">Low Threat</span>
                              </div>
                              <div className="flex items-center gap-1.5">
                                <div className="w-2 h-2 rounded-sm bg-cyan-600" />
                                <span className="text-[10px] font-bold uppercase text-zinc-500">Moderate</span>
                              </div>
                              <div className="flex items-center gap-1.5">
                                <div className="w-2 h-2 rounded-sm bg-cyan-400 shadow-[0_0_5px_rgba(34,211,238,0.5)]" />
                                <span className="text-[10px] font-bold uppercase text-zinc-500">Critical</span>
                              </div>
                            </div>
                          </div>
                          {/* User-Friendly Insight */}
                        </div>
                      ) : (
                        <div className="flex-1 flex items-center justify-center text-zinc-500 font-mono text-[10px] uppercase tracking-widest italic opacity-50 relative z-10">
                          No active evasion tactics identified
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>


          {/* Top Impersonated Brands */}
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-cyber-light-heading dark:text-zinc-300 flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyber-light-accent-deep dark:text-ornex-green" />
              Top Impersonated Brands
              <SectionTooltip text="Global threat intelligence data showing the most common brands exploited in recent phishing campaigns." />
              <span className="text-[11px] text-cyber-light-accent-deep dark:text-ornex-green/60 font-mono ml-2 bg-cyber-light-accent/5 dark:bg-ornex-green/5 px-2 py-0.5 rounded-lg border border-cyber-light-accent/20 dark:border-ornex-green/10">GLOBAL INTEL</span>
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 md:gap-4 items-start">
              {data.top_impersonated_brands.length > 0 ? (
                data.top_impersonated_brands.slice(0, 8).map((b, i) => (
                  <div key={i} className="relative group overflow-hidden p-3.5 md:p-4 bg-zinc-100/40 dark:bg-white/[0.03] rounded-xl md:rounded-2xl border border-cyber-light-border dark:border-white/5 hover:bg-zinc-200/60 dark:hover:bg-white/[0.08] hover:border-cyber-light-accent/30 dark:hover:border-ornex-green/20 transition-all shadow-sm hover:shadow-md">
                    <div 
                      className="absolute inset-0 bg-cyber-light-accent/5 dark:bg-ornex-green/[0.05] border-r-2 border-cyber-light-accent/20 dark:border-ornex-green/20 transition-all duration-1000 ease-out origin-left"
                      style={{ width: b.share.includes('%') ? b.share : `${b.share}%` }}
                    />
                    <div className="relative flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5 md:gap-3 min-w-0">
                        <div className="w-7 h-7 md:w-8 md:h-8 rounded-lg md:rounded-xl bg-cyber-light-bg dark:bg-zinc-900 border border-cyber-light-border dark:border-white/5 flex items-center justify-center text-[10px] md:text-xs font-black text-cyber-light-accent-deep dark:text-ornex-green shadow-sm shrink-0">
                          {i + 1}
                        </div>
                        <div className="flex flex-col min-w-0">
                          <span className="text-xs md:text-sm font-bold text-cyber-light-heading dark:text-white tracking-tight truncate">{b.brand}</span>
                          <span className="text-[8px] md:text-[10px] text-cyber-light-text font-mono uppercase tracking-wider truncate">{b.category}</span>
                        </div>
                      </div>
                      <div className="text-[10px] md:text-xs font-mono font-black text-cyber-light-accent-deep dark:text-ornex-green bg-cyber-light-accent/10 dark:bg-ornex-green/10 px-1.5 md:px-2 py-0.5 md:py-1 rounded-lg border border-cyber-light-accent/20 dark:border-ornex-green/10 shrink-0">
                        {b.share}
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="col-span-full py-12 bg-white/20 dark:bg-white/5 rounded-3xl border border-dashed border-zinc-300 dark:border-white/10 flex items-center justify-center text-zinc-500 font-mono text-[10px] uppercase tracking-widest italic">
                  Global threat intelligence stream pending
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Footer - Final Polish */}
        <div className="p-5 sm:p-6 md:p-8 bg-cyber-light-bg/50 dark:bg-black/20 border-t border-cyber-light-border dark:border-white/5">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-6 sm:gap-4">
            <div className="flex flex-col sm:flex-row items-center gap-2 sm:gap-6">
              <div className="flex items-center gap-2.5 px-3 py-1.5 rounded-full bg-cyber-light-bg dark:bg-white/5 border border-zinc-200 dark:border-white/10 shadow-sm transition-all hover:border-cyber-light-accent/40 dark:hover:border-ornex-green/30">
                 <RefreshCw className={`w-3 h-3 text-cyber-light-accent-deep dark:text-ornex-green ${isRefreshing ? 'animate-spin' : ''}`} />
                 <p className="text-[9px] md:text-xs text-cyber-light-text dark:text-zinc-400 font-mono font-bold uppercase tracking-widest">
                   Last Intel Sync: <span className="text-cyber-light-accent-deep dark:text-ornex-green">{new Date(data.last_updated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                 </p>
              </div>
              
              <div className="hidden sm:flex items-center gap-1.5 opacity-40">
                <div className="w-1 h-1 rounded-full bg-zinc-400" />
                <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-tighter">Status: Nominal</span>
              </div>
            </div>

            <div className="flex flex-col items-center sm:items-end gap-1.5">
              <p className="text-[10px] md:text-xs text-cyber-light-text dark:text-zinc-400 font-mono font-black uppercase tracking-[0.15em] opacity-80">
                LinkVeil-AI Forensic Engine <span className="text-cyber-light-accent-deep dark:text-ornex-green">v2.1.0</span>
              </p>
              <div className="flex items-center gap-2 opacity-40 hover:opacity-100 transition-opacity cursor-default">
                <span className="text-[8px] md:text-[9px] text-cyber-light-text font-mono uppercase tracking-[0.3em]">Quantum-Secure Pipeline • vVision Enabled</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
