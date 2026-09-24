import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';
import { api } from '../api/client';
import type {
  RunResponse,
  DashboardViewModel,
  SessionEvidence,
  FindingRow,
} from '../api/types';

interface InvestigationContextType {
  runs: RunResponse[];
  activeRunId: string | null;
  activeRun: RunResponse | null;
  dashboard: DashboardViewModel | null;
  sessions: SessionEvidence[];
  selectedSession: SessionEvidence | null;
  selectedStreamKey: string | null;
  selectedFinding: FindingRow | null;
  selectedEventFrame: number | null;
  activeView: 'home' | 'workbench';
  activeTab: 'overview' | 'timeline' | 'evidence' | 'certs';
  isLoading: boolean;
  error: string | null;
  filterProtocol: string | null;
  filterSeverity: string | null;
  searchQuery: string;
  showCommandPalette: boolean;
  showShortcuts: boolean;
  selectRun: (runId: string) => Promise<void>;
  selectSession: (streamKey: string | null) => void;
  selectFinding: (finding: FindingRow | null) => void;
  selectEventFrame: (frame: number | null) => void;
  setActiveView: (view: 'home' | 'workbench') => void;
  setActiveTab: (tab: 'overview' | 'timeline' | 'evidence' | 'certs') => void;
  setShowCommandPalette: (show: boolean) => void;
  setShowShortcuts: (show: boolean) => void;
  setFilterProtocol: (proto: string | null) => void;
  setFilterSeverity: (sev: string | null) => void;
  setSearchQuery: (query: string) => void;
  refreshRuns: () => Promise<RunResponse[]>;
  uploadCapture: (file: File, options?: { ai?: boolean; formula?: string }) => Promise<RunResponse>;
}

const InvestigationContext = createContext<InvestigationContextType | null>(null);

export const InvestigationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // URL query params support for deep linking & refresh
  const urlParams = useMemo(() => new URLSearchParams(window.location.search), []);
  const initialView = (urlParams.get('view') as 'home' | 'workbench') || 'home';
  const initialTab = (urlParams.get('tab') as 'overview' | 'timeline' | 'evidence' | 'certs') || 'overview';
  const initialRunId = urlParams.get('run_id') || null;
  const initialStreamKey = urlParams.get('session') || null;
  const initialFindingId = urlParams.get('finding') || null;
  const initialFrame = urlParams.get('frame') ? parseInt(urlParams.get('frame')!, 10) : null;
  const initialModal = urlParams.get('modal');

  const [runs, setRuns] = useState<RunResponse[]>([]);
  const [activeRunId, setActiveRunId] = useState<string | null>(initialRunId);
  const [dashboard, setDashboard] = useState<DashboardViewModel | null>(null);
  const [sessions, setSessions] = useState<SessionEvidence[]>([]);
  const [selectedStreamKey, setSelectedStreamKey] = useState<string | null>(initialStreamKey);
  const [selectedFinding, setSelectedFinding] = useState<FindingRow | null>(null);
  const [selectedEventFrame, setSelectedEventFrame] = useState<number | null>(initialFrame);
  const [activeView, setActiveView] = useState<'home' | 'workbench'>(initialView);
  const [activeTab, setActiveTab] = useState<'overview' | 'timeline' | 'evidence' | 'certs'>(initialTab);
  const [showCommandPalette, setShowCommandPalette] = useState<boolean>(initialModal === 'command');
  const [showShortcuts, setShowShortcuts] = useState<boolean>(initialModal === 'shortcuts');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Sync state to URL without reloading
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (activeView) params.set('view', activeView);
    if (activeTab) params.set('tab', activeTab);
    if (activeRunId) params.set('run_id', activeRunId);
    if (selectedStreamKey) {
      params.set('session', selectedStreamKey);
    } else {
      params.delete('session');
    }
    if (selectedFinding?.title) {
      params.set('finding', encodeURIComponent(selectedFinding.title));
    } else {
      params.delete('finding');
    }
    if (selectedEventFrame !== null) {
      params.set('frame', selectedEventFrame.toString());
    } else {
      params.delete('frame');
    }
    const newRelativePathQuery = window.location.pathname + '?' + params.toString();
    window.history.replaceState(null, '', newRelativePathQuery);
  }, [activeView, activeTab, activeRunId, selectedStreamKey, selectedFinding, selectedEventFrame]);

  // Global Keyboard Shortcuts (1-4, Cmd+K, ?, Esc)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      const isInput = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable);

      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setShowCommandPalette((prev) => !prev);
        return;
      }

      if (e.key === 'Escape') {
        setShowCommandPalette(false);
        setShowShortcuts(false);
        setSelectedFinding(null);
        setSelectedEventFrame(null);
        return;
      }

      if (isInput) return;

      if (e.key === '?') {
        e.preventDefault();
        setShowShortcuts((prev) => !prev);
      } else if (e.key === '1') {
        setActiveView('workbench');
        setActiveTab('overview');
      } else if (e.key === '2') {
        setActiveView('workbench');
        setActiveTab('timeline');
      } else if (e.key === '3') {
        setActiveView('workbench');
        setActiveTab('evidence');
      } else if (e.key === '4') {
        setActiveView('workbench');
        setActiveTab('certs');
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Filters
  const [filterProtocol, setFilterProtocol] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');

  const activeRun = useMemo(() => {
    const found = runs.find((r) => r.run_id === activeRunId);
    if (found) return found;
    if (dashboard && activeRunId) {
      return {
        run_id: activeRunId,
        capture_id: dashboard.identity?.capture_id || '',
        state: 'COMPLETED',
        created_at: dashboard.identity?.generated_at || new Date().toISOString(),
        source_filename: 'investigation.pcap',
        duration_ms: null,
        ai_enabled: dashboard.identity?.ai_enabled || false,
      } as RunResponse;
    }
    return null;
  }, [runs, activeRunId, dashboard]);

  const selectedSession = useMemo(() => {
    if (!selectedStreamKey || !sessions.length) return sessions[0] || null;
    return sessions.find((s) => s.stream_key === selectedStreamKey) || sessions[0] || null;
  }, [sessions, selectedStreamKey]);

  const refreshRuns = useCallback(async () => {
    try {
      const resp = await api.getAnalyses({ limit: 50 });
      setRuns(resp.items);
      return resp.items;
    } catch (err: any) {
      console.error('Failed to load runs:', err);
      setError(err.message || 'Failed to load analyses');
      return [];
    }
  }, []);

  const selectRun = useCallback(async (runId: string) => {
    setActiveRunId(runId);
    setIsLoading(true);
    setError(null);
    setSelectedFinding(null);
    setSelectedEventFrame(null);

    try {
      const [dashData, sessData] = await Promise.all([
        api.getDashboard(runId),
        api.getSessions(runId).catch((e) => {
          console.warn('Sessions endpoint warning:', e);
          return { run_id: runId, capture_id: '', total: 0, items: [] };
        }),
      ]);

      setDashboard(dashData);
      const items = sessData.items || [];
      setSessions(items);

      // Handle stream key selection (honor deep link or keep valid selection)
      if (items.length > 0) {
        const matchingStream = initialStreamKey && items.find((s) => s.stream_key === initialStreamKey);
        setSelectedStreamKey(matchingStream ? matchingStream.stream_key : items[0].stream_key);
      } else {
        setSelectedStreamKey(null);
      }

      // Handle initial finding deep link if present
      if (initialFindingId && dashData.findings && dashData.findings.length > 0) {
        const decoded = decodeURIComponent(initialFindingId).toLowerCase();
        const matchingFinding = dashData.findings.find(
          (f) =>
            f.title.toLowerCase().includes(decoded) ||
            (f.source_rule_ids && f.source_rule_ids.some((r) => r.toLowerCase().includes(decoded)))
        );
        if (matchingFinding) {
          setSelectedFinding(matchingFinding);
        }
      } else if (initialFrame !== null) {
        setSelectedEventFrame(initialFrame);
      }
    } catch (err: any) {
      console.error('Failed to fetch analysis details:', err);
      setError(err.message || 'Failed to fetch analysis data');
    } finally {
      setIsLoading(false);
    }
  }, [initialStreamKey, initialFindingId, initialFrame]);

  // Initial load
  useEffect(() => {
    if (initialRunId) {
      selectRun(initialRunId);
    }
    refreshRuns().then((loadedRuns) => {
      if (!initialRunId && loadedRuns && loadedRuns.length > 0) {
        const completedRuns = loadedRuns.filter((r) => r.state === 'COMPLETED');
        const candidatePool = completedRuns.length > 0 ? completedRuns : loadedRuns;
        selectRun(candidatePool[0].run_id);
      }
    });
  }, [refreshRuns, selectRun, initialRunId]);

  const selectSession = useCallback((streamKey: string | null) => {
    setSelectedStreamKey(streamKey);
    setSelectedEventFrame(null);
  }, []);

  const selectFinding = useCallback((finding: FindingRow | null) => {
    setSelectedFinding(finding);
    if (finding) {
      setSelectedEventFrame(null);
      if (finding.affected_stream_keys.length > 0) {
        if (!selectedStreamKey || !finding.affected_stream_keys.includes(selectedStreamKey)) {
          setSelectedStreamKey(finding.affected_stream_keys[0]);
        }
      }
    }
  }, [selectedStreamKey]);

  const selectEventFrame = useCallback((frame: number | null) => {
    setSelectedEventFrame(frame);
    if (frame !== null) {
      setSelectedFinding(null);
    }
  }, []);

  const uploadCapture = useCallback(
    async (file: File, options?: { ai?: boolean; formula?: string }): Promise<RunResponse> => {
      setIsLoading(true);
      setError(null);
      try {
        const run = await api.uploadCapture(file, options);
        await refreshRuns();
        await selectRun(run.run_id);
        setActiveView('workbench');
        return run;
      } catch (err: any) {
        console.error('Upload failed:', err);
        setError(err.message || 'Capture analysis failed');
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [refreshRuns, selectRun]
  );

  return (
    <InvestigationContext.Provider
      value={{
        runs,
        activeRunId,
        activeRun,
        dashboard,
        sessions,
        selectedSession,
        selectedStreamKey,
        selectedFinding,
        selectedEventFrame,
        activeView,
        activeTab,
        isLoading,
        error,
        filterProtocol,
        filterSeverity,
        searchQuery,
        showCommandPalette,
        showShortcuts,
        selectRun,
        selectSession,
        selectFinding,
        selectEventFrame,
        setActiveView,
        setActiveTab,
        setShowCommandPalette,
        setShowShortcuts,
        setFilterProtocol,
        setFilterSeverity,
        setSearchQuery,
        refreshRuns,
        uploadCapture,
      }}
    >
      {children}
    </InvestigationContext.Provider>
  );
};

export const useInvestigation = () => {
  const context = useContext(InvestigationContext);
  if (!context) {
    throw new Error('useInvestigation must be used within an InvestigationProvider');
  }
  return context;
};
