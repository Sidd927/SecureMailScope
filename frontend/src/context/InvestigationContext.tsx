import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';
import { api } from '../api/client';
import { FIXTURES, type FixtureKey } from '../fixtures';

/**
 * Verification Mode: Set to true to disable all fixture fallbacks.
 * In this mode, any failure to reach the real backend immediately surfaces an error,
 * strictly preventing fixture data from ever entering the state.
 */
export const DISABLE_FIXTURE_FALLBACK = true;

import type {
  RunResponse,
  DashboardViewModel,
  SessionEvidence,
  FindingRow,
  AssessmentResponse,
  ReportItem,
  ProtocolEvent,
  ReportDocument,
} from '../api/types';

export const DEFAULT_FALLBACK_RUNS: RunResponse[] = [
  {
    run_id: '58d5f74ba5024c83ad6e62dae6dd06b6',
    state: 'COMPLETED',
    capture_id: 'ce5377348e22ad92c33d705e31388944bad8224534d478c38b57a75d3ba4a501',
    assessment_id: '645090e0bc44ba9d',
    ai_enabled: false,
    formula_id: 'F2-group-damped',
    created_at: '2026-09-24T10:18:22Z',
    started_at: '2026-09-24T10:18:22.010Z',
    completed_at: '2026-09-24T10:18:22.148Z',
    duration_ms: 138,
    ingest_status: 'PARSED',
    error_code: null,
    error_message: null,
    source_filename: 'backup_weak_certificate.pcap',
    backend_version: '0.1.0',
    replayed: false,
    stages: [{ stage: 'dissection', ms: 80 }, { stage: 'rules', ms: 58 }],
    overall_posture: 'CRITICAL',
    score_value: 44.0,
  },
  {
    run_id: '871ea0c739b246098ff481c887afcc0f',
    state: 'COMPLETED',
    capture_id: '97b2b61aa870b74861c606e604f3ecf6f77d8818241817bd22beb814f3dcbe83',
    assessment_id: 'ass-871ea0c739b2',
    ai_enabled: false,
    formula_id: 'F2-group-damped',
    created_at: '2026-09-24T10:18:22Z',
    started_at: '2026-09-24T10:18:22.020Z',
    completed_at: '2026-09-24T10:18:22.340Z',
    duration_ms: 141,
    ingest_status: 'PARSED',
    error_code: null,
    error_message: null,
    source_filename: 'deepdive_cross_session_control_endpoint.pcap',
    backend_version: '0.1.0',
    replayed: false,
    stages: [{ stage: 'dissection', ms: 82 }, { stage: 'rules', ms: 59 }],
    overall_posture: 'CRITICAL',
    score_value: 22.15,
  },
  {
    run_id: '9aaefe1d93f046faac255dfe67c86c18',
    state: 'COMPLETED',
    capture_id: 'd257ec482cd486432e510f8ddb9cf9e46747c237e743036c977b67b76cc51f65',
    assessment_id: 'ass-9aaefe1d93f0',
    ai_enabled: false,
    formula_id: 'F2-group-damped',
    created_at: '2026-09-24T10:18:22Z',
    started_at: '2026-09-24T10:18:22.012Z',
    completed_at: '2026-09-24T10:18:22.148Z',
    duration_ms: 136,
    ingest_status: 'PARSED',
    error_code: null,
    error_message: null,
    source_filename: 'scene_b_certificate_honesty.pcap',
    backend_version: '0.1.0',
    replayed: false,
    stages: [{ stage: 'dissection', ms: 70 }, { stage: 'rules', ms: 66 }],
    overall_posture: 'STRONG',
    score_value: 100.0,
  },
];

export type ForensicTab =
  | 'overview'
  | 'provenance'
  | 'journey'
  | 'evidence'
  | 'certs'
  | 'cross_session'
  | 'report';

export type SectionErrors = Partial<Record<'sessions' | 'assessment' | 'reports', string>>;

interface InvestigationContextType {
  runs: RunResponse[];
  /** False until the first run-list request settles; until then `runs` holds fixture placeholders. */
  runsLoaded: boolean;
  activeRunId: string | null;
  activeRun: RunResponse | null;
  dashboard: DashboardViewModel | null;
  assessment: AssessmentResponse | null;
  reports: ReportItem[];
  sessions: SessionEvidence[];
  selectedSession: SessionEvidence | null;
  selectedStreamKey: string | null;
  selectedFinding: FindingRow | null;
  selectedEventFrame: number | null;
  selectedEvent: ProtocolEvent | null;
  dossierOpen: boolean;
  activeView: 'home' | 'workbench';
  activeTab: ForensicTab;
  isLoading: boolean;
  error: string | null;
  isUsingFixtures: boolean;
  sectionErrors: SectionErrors;
  reportDoc: ReportDocument | null;
  reportStatus: 'idle' | 'loading' | 'ready' | 'error';
  reportError: string | null;
  loadReport: () => Promise<void>;
  filterProtocol: string | null;
  filterSeverity: string | null;
  searchQuery: string;
  showCommandPalette: boolean;
  showShortcuts: boolean;
  selectRun: (runId: string) => Promise<void>;
  selectSession: (streamKey: string | null) => void;
  selectFinding: (finding: FindingRow | null) => void;
  selectEventFrame: (frame: number | null) => void;
  selectEvent: (event: ProtocolEvent | null) => void;
  setDossierOpen: (open: boolean) => void;
  setActiveView: (view: 'home' | 'workbench') => void;
  setActiveTab: (tab: ForensicTab) => void;
  setShowCommandPalette: (show: boolean) => void;
  setShowShortcuts: (show: boolean) => void;
  setFilterProtocol: (proto: string | null) => void;
  setFilterSeverity: (sev: string | null) => void;
  setSearchQuery: (query: string) => void;
  refreshRuns: () => Promise<RunResponse[]>;
  uploadCapture: (file: File, options?: { ai?: boolean; formula?: string }) => Promise<RunResponse>;

  // Contextual Pivoting Actions
  pivotToJourney: (frame?: number, streamKey?: string) => void;
  pivotToEvidence: (streamKey?: string) => void;
  pivotToCerts: (certIndex?: number) => void;
  pivotToFinding: (finding: FindingRow) => void;
  pivotToProvenance: (findingTitle?: string) => void;
  pivotToCrossSession: (streamKey?: string) => void;
  pivotToReport: () => void;
}

const InvestigationContext = createContext<InvestigationContextType | null>(null);

function normalizeTab(tabParam: string | null): ForensicTab {
  if (!tabParam) return 'overview';
  if (tabParam === 'timeline') return 'journey';
  if (['overview', 'provenance', 'journey', 'evidence', 'certs', 'cross_session', 'report'].includes(tabParam)) {
    return tabParam as ForensicTab;
  }
  return 'overview';
}

export const InvestigationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const urlParams = useMemo(() => new URLSearchParams(window.location.search), []);
  const initialView = (urlParams.get('view') as 'home' | 'workbench') || 'home';
  const initialTab = normalizeTab(urlParams.get('tab'));
  const initialRunId = urlParams.get('run_id') || null;
  const initialStreamKey = urlParams.get('session') || null;
  const initialFindingId = urlParams.get('finding') || null;
  const initialFrame = urlParams.get('frame') ? parseInt(urlParams.get('frame')!, 10) : null;
  const initialModal = urlParams.get('modal');

  const [runs, setRuns] = useState<RunResponse[]>(DISABLE_FIXTURE_FALLBACK ? [] : DEFAULT_FALLBACK_RUNS);
  const [activeRunId, setActiveRunId] = useState<string | null>(initialRunId || (DISABLE_FIXTURE_FALLBACK ? null : DEFAULT_FALLBACK_RUNS[0].run_id));
  const [dashboard, setDashboard] = useState<DashboardViewModel | null>(null);
  const [assessment, setAssessment] = useState<AssessmentResponse | null>(null);
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [sessions, setSessions] = useState<SessionEvidence[]>([]);
  const [selectedStreamKey, setSelectedStreamKey] = useState<string | null>(initialStreamKey);
  const [selectedFinding, setSelectedFinding] = useState<FindingRow | null>(null);
  const [selectedEventFrame, setSelectedEventFrame] = useState<number | null>(initialFrame);
  const [selectedEvent, setSelectedEvent] = useState<ProtocolEvent | null>(null);
  const [dossierOpen, setDossierOpen] = useState<boolean>(false);
  const [activeView, setActiveView] = useState<'home' | 'workbench'>(initialView);
  const [activeTab, setActiveTab] = useState<ForensicTab>(initialTab);
  const [showCommandPalette, setShowCommandPalette] = useState<boolean>(initialModal === 'command');
  const [showShortcuts, setShowShortcuts] = useState<boolean>(initialModal === 'shortcuts');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [runsFromFixtures, setRunsFromFixtures] = useState<boolean>(false);
  const [runsLoaded, setRunsLoaded] = useState<boolean>(false);
  const [runDetail, setRunDetail] = useState<RunResponse | null>(null);
  const [investigationFromFixtures, setInvestigationFromFixtures] = useState<boolean>(false);
  const isUsingFixtures = runsFromFixtures || investigationFromFixtures;
  const [sectionErrors, setSectionErrors] = useState<SectionErrors>({});
  const [reportDoc, setReportDoc] = useState<ReportDocument | null>(null);
  const [reportStatus, setReportStatus] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [reportError, setReportError] = useState<string | null>(null);

  // Filters
  const [filterProtocol, setFilterProtocol] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Sync state to URL without full refresh
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
      params.set('finding', selectedFinding.title);
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

  // Global Keyboard Shortcuts
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
        setDossierOpen(false);
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
        setActiveTab('evidence');
      } else if (e.key === '3') {
        setActiveView('workbench');
        setActiveTab('journey');
      } else if (e.key === '4') {
        setActiveView('workbench');
        setActiveTab('certs');
      } else if (e.key === '5') {
        setActiveView('workbench');
        setActiveTab('cross_session');
      } else if (e.key === '6') {
        setActiveView('workbench');
        setActiveTab('provenance');
      } else if (e.key === '7') {
        setActiveView('workbench');
        setActiveTab('report');
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const activeRun = useMemo(() => {
    if (!activeRunId) return null;
    const found = runs.find((r) => r.run_id === activeRunId);
    if (found) return found;
    if (!DISABLE_FIXTURE_FALLBACK) {
      const fix = Object.values(FIXTURES).find((f) => f.run.run_id === activeRunId);
      if (fix) return fix.run as unknown as RunResponse;
    }
    // Runs outside the 50-item list come from GET /analyses/{id}; nothing is synthesised.
    if (runDetail?.run_id === activeRunId) return runDetail;
    return null;
  }, [runs, activeRunId, runDetail]);

  const selectedSession = useMemo(() => {
    if (!selectedStreamKey || !sessions.length) return sessions[0] || null;
    return sessions.find((s) => s.stream_key === selectedStreamKey) || sessions[0] || null;
  }, [sessions, selectedStreamKey]);

  const refreshRuns = useCallback(async () => {
    try {
      const resp = await api.getAnalyses({ limit: 50 });
      if (resp && resp.items && resp.items.length > 0) {
        setRuns(resp.items);
        setRunsFromFixtures(false);
        setRunsLoaded(true);
        return resp.items;
      }
      if (DISABLE_FIXTURE_FALLBACK) {
        setRuns([]);
        setRunsFromFixtures(false);
        setRunsLoaded(true);
        return [];
      }
      setRuns(DEFAULT_FALLBACK_RUNS);
      setRunsFromFixtures(true);
      setRunsLoaded(true);
      return DEFAULT_FALLBACK_RUNS;
    } catch (err: any) {
      console.warn('Backend unavailable, using authentic offline PCAP fixtures:', err);
      if (DISABLE_FIXTURE_FALLBACK) {
        setRuns([]);
        setRunsFromFixtures(false);
        setRunsLoaded(true);
        throw err;
      }
      setRuns(DEFAULT_FALLBACK_RUNS);
      setRunsFromFixtures(true);
      setRunsLoaded(true);
      return DEFAULT_FALLBACK_RUNS;
    }
  }, []);

  const selectRun = useCallback(async (runId: string) => {
    setActiveRunId(runId);
    setReportDoc(null);
    setReportStatus('idle');
    setReportError(null);
    setIsLoading(true);
    setError(null);
    setSelectedFinding(null);
    setSelectedEventFrame(null);
    setSelectedEvent(null);
    setDossierOpen(false);

    try {
      const failures: SectionErrors = {};
      const [dashData, runData, sessData, assessData, repsData] = await Promise.all([
        api.getDashboard(runId),
        api.getAnalysis(runId).catch(() => null),
        api.getSessions(runId).catch((e) => {
          failures.sessions = e?.message || 'Sessions request failed';
          return { run_id: runId, capture_id: '', total: 0, items: [] };
        }),
        api.getAssessment(runId).catch((e) => {
          failures.assessment = e?.message || 'Assessment request failed';
          return null;
        }),
        api.getReports(runId).catch((e) => {
          failures.reports = e?.message || 'Reports request failed';
          return { run_id: runId, items: [] };
        }),
      ]);
      setSectionErrors(failures);
      setRunDetail(runData);

      setDashboard(dashData);
      setInvestigationFromFixtures(false);
      setAssessment(assessData);
      setReports(repsData?.items || []);
      const items = sessData.items || [];
      setSessions(items);

      if (items.length > 0) {
        const matchingStream = initialStreamKey && items.find((s) => s.stream_key === initialStreamKey);
        setSelectedStreamKey(matchingStream ? matchingStream.stream_key : items[0].stream_key);
      } else {
        setSelectedStreamKey(null);
      }

      if (initialFindingId && dashData.findings && dashData.findings.length > 0) {
        const decoded = initialFindingId.toLowerCase();
        const matchingFinding = dashData.findings.find(
          (f) =>
            f.title.toLowerCase().includes(decoded) ||
            (f.source_rule_ids && f.source_rule_ids.some((r) => r.toLowerCase().includes(decoded)))
        );
        if (matchingFinding) {
          setSelectedFinding(matchingFinding);
          setDossierOpen(true);
        }
      } else if (initialFrame !== null) {
        setSelectedEventFrame(initialFrame);
        setDossierOpen(true);
      }
    } catch (err: any) {
      console.warn('Failed to fetch from backend, checking authentic fixtures for runId:', runId, err);
      if (DISABLE_FIXTURE_FALLBACK) {
        setDashboard(null);
        setInvestigationFromFixtures(false);
        setError(`REAL-BACKEND FAIL: Backend request failed for runId "${runId}". Fixture fallback is strictly disabled. Error: ${err?.message || err}`);
        return;
      }
      // Find matching fixture
      const fixtureKey = (Object.keys(FIXTURES) as FixtureKey[]).find(
        (k) => FIXTURES[k].run.run_id === runId || FIXTURES[k].run.source_filename === runId || runId.includes(k)
      ) || (runId.includes('control') ? 'deepdive_cross_session_control_endpoint' : runId.includes('honesty') ? 'scene_b_certificate_honesty' : runId.includes('weak') ? 'backup_weak_certificate' : null);

      if (fixtureKey && FIXTURES[fixtureKey]) {
        const fix = FIXTURES[fixtureKey];
        setDashboard(fix.dashboard);
        setInvestigationFromFixtures(true);
        setSectionErrors({});
        setAssessment(fix.assessment);
        const fixSessions = fix.sessions?.items || [];
        setSessions(fixSessions);
        if (fixSessions.length > 0) {
          setSelectedStreamKey(fixSessions[0].stream_key);
        }
        if (initialFindingId && fix.dashboard?.findings && fix.dashboard.findings.length > 0) {
          const decoded = initialFindingId.toLowerCase();
          const match = fix.dashboard.findings.find(
            (f: any) => f.title.toLowerCase().includes(decoded) || (f.issue_class && f.issue_class.toLowerCase().includes(decoded))
          );
          if (match) {
            setSelectedFinding(match);
            setDossierOpen(true);
          }
        } else if (initialFrame !== null) {
          setSelectedEventFrame(initialFrame);
          setDossierOpen(true);
        }
        setError(null);
      } else {
        setDashboard(null);
        setInvestigationFromFixtures(false);
        setError(`Unable to resolve investigation session for runId: "${runId}". (HTTP 502 Bad Gateway)`);
      }
    } finally {
      setIsLoading(false);
    }
  }, [initialStreamKey, initialFindingId, initialFrame]);

  // Initial load
  useEffect(() => {
    const targetRun = initialRunId || (DISABLE_FIXTURE_FALLBACK ? null : DEFAULT_FALLBACK_RUNS[0].run_id);
    if (targetRun) {
      selectRun(targetRun);
    }
    refreshRuns();
  }, [refreshRuns, selectRun, initialRunId]);

  const selectSession = useCallback((streamKey: string | null) => {
    setSelectedStreamKey(streamKey);
    setSelectedEventFrame(null);
    setSelectedEvent(null);
  }, []);

  const loadReport = useCallback(async () => {
    if (!activeRunId || investigationFromFixtures) return;
    setReportStatus('loading');
    setReportError(null);
    try {
      setReportDoc(await api.getReportJson(activeRunId));
      setReportStatus('ready');
    } catch (err: any) {
      setReportError(err?.message || 'Report request failed');
      setReportStatus('error');
    }
  }, [activeRunId, investigationFromFixtures]);

  const selectFinding = useCallback((finding: FindingRow | null) => {
    setSelectedFinding(finding);
    if (finding) {
      setSelectedEventFrame(null);
      setSelectedEvent(null);
      setDossierOpen(true);
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
      setDossierOpen(true);
    }
  }, []);

  const selectEvent = useCallback((event: ProtocolEvent | null) => {
    setSelectedEvent(event);
    if (event) {
      setSelectedEventFrame(event.frame);
      setDossierOpen(true);
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
        // The caller reports the failure; the global error belongs to the loaded run.
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [refreshRuns, selectRun]
  );

  // Contextual Pivoting Actions
  const pivotToJourney = useCallback((frame?: number, streamKey?: string) => {
    setActiveView('workbench');
    setActiveTab('journey');
    if (streamKey) setSelectedStreamKey(streamKey);
    if (frame !== undefined) setSelectedEventFrame(frame);
  }, []);

  const pivotToEvidence = useCallback((streamKey?: string) => {
    setActiveView('workbench');
    setActiveTab('evidence');
    if (streamKey) setSelectedStreamKey(streamKey);
  }, []);

  const pivotToCerts = useCallback((_certIndex?: number) => {
    setActiveView('workbench');
    setActiveTab('certs');
  }, []);

  const pivotToFinding = useCallback((finding: FindingRow) => {
    setActiveView('workbench');
    selectFinding(finding);
  }, [selectFinding]);

  const pivotToProvenance = useCallback((findingTitle?: string) => {
    setActiveView('workbench');
    setActiveTab('provenance');
    if (findingTitle && dashboard?.findings) {
      const match = dashboard.findings.find((f) => f.title === findingTitle);
      if (match) setSelectedFinding(match);
    }
  }, [dashboard]);

  const pivotToCrossSession = useCallback((streamKey?: string) => {
    setActiveView('workbench');
    setActiveTab('cross_session');
    if (streamKey) setSelectedStreamKey(streamKey);
  }, []);

  const pivotToReport = useCallback(() => {
    setActiveView('workbench');
    setActiveTab('report');
  }, []);

  return (
    <InvestigationContext.Provider
      value={{
        runs,
        runsLoaded,
        activeRunId,
        activeRun,
        dashboard,
        assessment,
        reports,
        sessions,
        selectedSession,
        selectedStreamKey,
        selectedFinding,
        selectedEventFrame,
        selectedEvent,
        dossierOpen,
        activeView,
        activeTab,
        isLoading,
        error,
        isUsingFixtures,
        sectionErrors,
        reportDoc,
        reportStatus,
        reportError,
        loadReport,
        filterProtocol,
        filterSeverity,
        searchQuery,
        showCommandPalette,
        showShortcuts,
        selectRun,
        selectSession,
        selectFinding,
        selectEventFrame,
        selectEvent,
        setDossierOpen,
        setActiveView,
        setActiveTab,
        setShowCommandPalette,
        setShowShortcuts,
        setFilterProtocol,
        setFilterSeverity,
        setSearchQuery,
        refreshRuns,
        uploadCapture,
        pivotToJourney,
        pivotToEvidence,
        pivotToCerts,
        pivotToFinding,
        pivotToProvenance,
        pivotToCrossSession,
        pivotToReport,
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
