import React, { useState, useMemo } from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import { ProtocolTimeline } from './timeline/ProtocolTimeline';
import { EvidenceMatrix } from './evidence/EvidenceMatrix';
import { CertificateForensics } from './evidence/CertificateForensics';
import { ContextualInspector } from './inspector/ContextualInspector';
import { InvestigationOverview } from './overview/InvestigationOverview';
import { SeverityBadge } from '../common/SeverityBadge';
import { ForensicHash } from '../common/ForensicHash';
import {
  GitCommit,
  Layers,
  Award,
  Search,
  ShieldAlert,
  Compass,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import { formatEndpoint, formatProtocol } from '../../utils/formatters';

export const WorkbenchView: React.FC = () => {
  const {
    activeRunId,
    activeRun,
    dashboard,
    sessions,
    selectedSession,
    selectSession,
    selectFinding,
    activeTab,
    setActiveTab,
    setActiveView,
    selectRun,
    isLoading,
    error,
  } = useInvestigation();

  // Search & Filter state for stream reel
  const [streamFilter, setStreamFilter] = useState('');
  const [selectedProto, setSelectedProto] = useState<string | null>(null);

  const handleOpenScoreModal = () => {
    const params = new URLSearchParams(window.location.search);
    params.set('modal', 'score');
    window.history.replaceState(null, '', window.location.pathname + '?' + params.toString());
    window.dispatchEvent(new PopStateEvent('popstate'));
  };

  // Filtered streams for horizontal reel
  const filteredSessions = useMemo(() => {
    return sessions.filter((s) => {
      if (selectedProto && s.protocol.toLowerCase() !== selectedProto.toLowerCase()) {
        return false;
      }
      if (!streamFilter.trim()) return true;
      const q = streamFilter.toLowerCase();
      const clientStr = s.client ? `${s.client.ip}:${s.client.port}` : '';
      const serverStr = s.server ? `${s.server.ip}:${s.server.port}` : '';
      return (
        s.stream_key.toLowerCase().includes(q) ||
        clientStr.toLowerCase().includes(q) ||
        serverStr.toLowerCase().includes(q) ||
        s.protocol.toLowerCase().includes(q)
      );
    });
  }, [sessions, selectedProto, streamFilter]);

  // Unique protocols available
  const availableProtos = useMemo(() => {
    const set = new Set<string>();
    for (const s of sessions) {
      if (s.protocol) set.add(s.protocol.toUpperCase());
    }
    return Array.from(set);
  }, [sessions]);

  // Findings for currently selected stream
  const currentSessionFindings = useMemo(() => {
    if (!selectedSession || !dashboard?.findings) return [];
    return dashboard.findings.filter((f) =>
      f.affected_stream_keys.includes(selectedSession.stream_key)
    );
  }, [selectedSession, dashboard]);

  if (isLoading) {
    return (
      <div
        style={{
          flex: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: 'var(--color-page)',
          color: 'var(--color-ink-muted)',
          fontSize: 'var(--text-sm)',
          fontFamily: 'var(--font-mono)',
        }}
      >
        Dissecting network frames & verifying cryptographic state machine…
      </div>
    );
  }

  if (error && !dashboard) {
    return (
      <div
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: 'var(--color-page)',
          padding: '40px',
          textAlign: 'center',
        }}
      >
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '5px 12px',
            borderRadius: 'var(--radius-xs)',
            backgroundColor: 'var(--color-sev-critical-bg)',
            border: '1px solid var(--color-sev-critical-border)',
            color: 'var(--color-sev-critical)',
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            fontWeight: 800,
            textTransform: 'uppercase',
            letterSpacing: '0.08em',
            marginBottom: '16px',
          }}
        >
          <AlertTriangle size={14} />
          ANALYSIS UNAVAILABLE
        </div>
        <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 800, color: 'var(--color-ink)', marginBottom: '8px' }}>
          Forensic Engine Could Not Complete Request
        </h2>
        <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-ink-muted)', maxWidth: '480px', marginBottom: '20px', lineHeight: 1.5 }}>
          The backend service is either starting up or encountering transient connection limits. All prior artifacts remain safe in the forensic ledger.
        </p>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          {activeRunId && (
            <button
              type="button"
              onClick={() => selectRun(activeRunId)}
              className="btn btn-primary"
              style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              <RefreshCw size={13} />
              Retry Analysis Retrieval
            </button>
          )}
          <button
            type="button"
            onClick={() => setActiveView('home')}
            className="btn btn-secondary"
          >
            Return to Launchpad
          </button>
        </div>
        <details style={{ marginTop: '24px', textAlign: 'left', maxWidth: '480px' }}>
          <summary style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--color-ink-muted)', cursor: 'pointer' }}>
            Technical Diagnostic Information (Expand)
          </summary>
          <pre style={{ marginTop: '8px', padding: '10px', backgroundColor: 'var(--color-panel)', borderRadius: 'var(--radius-sm)', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--color-ink-secondary)', overflowX: 'auto', border: '1px solid var(--color-border)' }}>
            {error}
          </pre>
        </details>
      </div>
    );
  }

  if (!activeRun) {
    return (
      <div
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: 'var(--color-page)',
          padding: '40px',
        }}
      >
        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 800, color: 'var(--color-ink)' }}>
          No Active Investigation Case File Selected
        </div>
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--color-ink-muted)', marginTop: '8px' }}>
          Select an investigation from the Launchpad or ingest a new PCAP capture file.
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: 'var(--color-page)',
        minHeight: 0,
        overflow: 'hidden',
      }}
    >
      {/* ============================================================ */}
      {/* 1. TOP CASE FILE DOSSIER BAR */}
      {/* ============================================================ */}
      <div
        style={{
          backgroundColor: 'var(--color-surface)',
          borderBottom: '1px solid var(--color-border)',
          padding: '10px 24px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
          boxShadow: 'var(--shadow-subtle)',
          flexShrink: 0,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <div>
            <div
              style={{
                fontSize: '10px',
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                color: 'var(--color-ink-muted)',
                fontWeight: 700,
              }}
            >
              ACTIVE FORENSIC CASE FILE
            </div>
            <h1
              style={{
                fontSize: 'var(--text-base)',
                fontWeight: 800,
                color: 'var(--color-ink)',
                lineHeight: 1.2,
                marginTop: '1px',
              }}
            >
              {activeRun.source_filename}
            </h1>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <ForensicHash value={activeRun.capture_id} length={12} label="SHA-256" />
            {activeRun.duration_ms && (
              <span
                style={{
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--color-ink-muted)',
                  backgroundColor: 'var(--color-panel)',
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-xs)',
                  border: '1px solid var(--color-border)',
                }}
              >
                {activeRun.duration_ms}ms parse
              </span>
            )}
          </div>
        </div>

        {/* View Switcher Tabs & Global Coverage */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          {dashboard?.coverage && (
            <div
              style={{
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                color: 'var(--color-ink-secondary)',
              }}
            >
              Coverage: <strong style={{ color: 'var(--color-ink)' }}>{dashboard.coverage.percent_text}</strong>
            </div>
          )}

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              backgroundColor: 'var(--color-panel)',
              padding: '3px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--color-border)',
            }}
          >
            <button
              type="button"
              onClick={() => setActiveTab('overview')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                padding: '4px 10px',
                fontSize: 'var(--text-xs)',
                fontWeight: activeTab === 'overview' ? 800 : 600,
                color: activeTab === 'overview' ? 'var(--color-accent)' : 'var(--color-ink-muted)',
                backgroundColor: activeTab === 'overview' ? 'var(--color-surface)' : 'transparent',
                borderRadius: 'var(--radius-xs)',
                boxShadow: activeTab === 'overview' ? 'var(--shadow-subtle)' : 'none',
                transition: 'all var(--transition-fast)',
              }}
            >
              <Compass size={13} />
              <span>1. Overview</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('timeline')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                padding: '4px 10px',
                fontSize: 'var(--text-xs)',
                fontWeight: activeTab === 'timeline' ? 800 : 600,
                color: activeTab === 'timeline' ? 'var(--color-accent)' : 'var(--color-ink-muted)',
                backgroundColor: activeTab === 'timeline' ? 'var(--color-surface)' : 'transparent',
                borderRadius: 'var(--radius-xs)',
                boxShadow: activeTab === 'timeline' ? 'var(--shadow-subtle)' : 'none',
                transition: 'all var(--transition-fast)',
              }}
            >
              <GitCommit size={13} />
              <span>2. Protocol Journey</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('evidence')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                padding: '4px 10px',
                fontSize: 'var(--text-xs)',
                fontWeight: activeTab === 'evidence' ? 800 : 600,
                color: activeTab === 'evidence' ? 'var(--color-accent)' : 'var(--color-ink-muted)',
                backgroundColor: activeTab === 'evidence' ? 'var(--color-surface)' : 'transparent',
                borderRadius: 'var(--radius-xs)',
                boxShadow: activeTab === 'evidence' ? 'var(--shadow-subtle)' : 'none',
                transition: 'all var(--transition-fast)',
              }}
            >
              <Layers size={13} />
              <span>3. Evidence Ledger</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('certs')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                padding: '4px 10px',
                fontSize: 'var(--text-xs)',
                fontWeight: activeTab === 'certs' ? 800 : 600,
                color: activeTab === 'certs' ? 'var(--color-accent)' : 'var(--color-ink-muted)',
                backgroundColor: activeTab === 'certs' ? 'var(--color-surface)' : 'transparent',
                borderRadius: 'var(--radius-xs)',
                boxShadow: activeTab === 'certs' ? 'var(--shadow-subtle)' : 'none',
                transition: 'all var(--transition-fast)',
              }}
            >
              <Award size={13} />
              <span>4. X.509 Certs ({selectedSession?.certificates?.length ?? 0})</span>
            </button>
          </div>
        </div>
      </div>

      {/* ============================================================ */}
      {/* 2. HORIZONTAL STREAM NAVIGATION REEL (For Stream Tabs) */}
      {/* ============================================================ */}
      {activeTab !== 'overview' && (
        <div
          style={{
            backgroundColor: 'var(--color-panel)',
            borderBottom: '1px solid var(--color-border)',
            padding: '8px 24px',
            display: 'flex',
            alignItems: 'center',
            gap: '14px',
            flexShrink: 0,
            overflowX: 'auto',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                letterSpacing: '0.06em',
                fontWeight: 800,
                color: 'var(--color-ink-muted)',
              }}
            >
              DISSECTED STREAMS ({filteredSessions.length}/{sessions.length}):
            </span>

            {/* Quick Protocol Filter Chips */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <button
                type="button"
                onClick={() => setSelectedProto(null)}
                style={{
                  fontSize: '10px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: selectedProto === null ? 800 : 600,
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-xs)',
                  backgroundColor: selectedProto === null ? 'var(--color-ink)' : 'var(--color-surface)',
                  color: selectedProto === null ? '#ffffff' : 'var(--color-ink-muted)',
                  border: '1px solid var(--color-border)',
                }}
              >
                ALL
              </button>
              {availableProtos.map((pr) => (
                <button
                  key={pr}
                  type="button"
                  onClick={() => setSelectedProto(selectedProto === pr ? null : pr)}
                  style={{
                    fontSize: '10px',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: selectedProto === pr ? 800 : 600,
                    padding: '2px 6px',
                    borderRadius: 'var(--radius-xs)',
                    backgroundColor: selectedProto === pr ? 'var(--color-accent)' : 'var(--color-surface)',
                    color: selectedProto === pr ? '#ffffff' : 'var(--color-ink-muted)',
                    border: '1px solid var(--color-border)',
                  }}
                >
                  {pr}
                </button>
              ))}

              {/* Quick Stream Search */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  backgroundColor: 'var(--color-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-xs)',
                  padding: '2px 8px',
                  marginLeft: '8px',
                }}
              >
                <Search size={11} style={{ color: 'var(--color-ink-muted)' }} />
                <input
                  type="text"
                  placeholder="Search stream or IP…"
                  value={streamFilter}
                  onChange={(e) => setStreamFilter(e.target.value)}
                  style={{
                    border: 'none',
                    background: 'none',
                    outline: 'none',
                    fontSize: '10px',
                    fontFamily: 'var(--font-mono)',
                    width: '130px',
                    color: 'var(--color-ink)',
                  }}
                />
              </div>
            </div>
          </div>

          {/* Horizontal Stream Cards Reel */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              overflowX: 'auto',
              padding: '2px 0',
              flex: 1,
            }}
          >
            {filteredSessions.map((s) => {
              const isSelected = selectedSession?.stream_key === s.stream_key;
              const streamFindings = (dashboard?.findings || []).filter((f) =>
                f.affected_stream_keys.includes(s.stream_key)
              );
              const hasCritical = streamFindings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');

              return (
                <button
                  key={s.stream_key}
                  type="button"
                  onClick={() => selectSession(s.stream_key)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '5px 10px',
                    borderRadius: 'var(--radius-xs)',
                    backgroundColor: isSelected
                      ? 'var(--color-surface)'
                      : hasCritical
                        ? 'var(--color-sev-critical-bg)'
                        : 'var(--color-surface)',
                    border: `1px solid ${isSelected ? 'var(--color-accent)' : hasCritical ? 'var(--color-sev-critical-border)' : 'var(--color-border)'}`,
                    boxShadow: isSelected ? '0 1px 3px rgba(0,0,0,0.08)' : 'none',
                    flexShrink: 0,
                    cursor: 'pointer',
                    transition: 'all var(--transition-fast)',
                  }}
                >
                  <span
                    style={{
                      fontSize: '10px',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 800,
                      color: isSelected ? 'var(--color-accent)' : 'var(--color-ink)',
                    }}
                  >
                    #{s.tcp_stream_id} {formatProtocol(s.protocol, s.implicit_tls)}
                  </span>

                  <span
                    style={{
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--color-ink-secondary)',
                    }}
                  >
                    {formatEndpoint(s.client)} ➔ {formatEndpoint(s.server)}
                  </span>

                  {streamFindings.length > 0 && (
                    <span
                      style={{
                        fontSize: '9px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 800,
                        padding: '1px 5px',
                        borderRadius: 'var(--radius-xs)',
                        backgroundColor: hasCritical ? 'var(--color-sev-critical)' : 'var(--color-sev-medium)',
                        color: '#ffffff',
                      }}
                    >
                      {streamFindings.length} ⚠
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* ============================================================ */}
      {/* 3. MAIN INVESTIGATION WORKSPACE CANVAS */}
      {/* ============================================================ */}
      <div
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '28px',
        }}
      >
        {activeTab === 'overview' ? (
          <div style={{ maxWidth: '1180px', margin: '0 auto', width: '100%' }}>
            <InvestigationOverview onOpenScoreModal={handleOpenScoreModal} />
          </div>
        ) : selectedSession ? (
          <>
            {activeTab === 'timeline' && (
              <>
                {/* Protocol Timeline Hero Feature */}
                <ProtocolTimeline session={selectedSession} />

                {/* Sub-Timeline Conclusions Deck */}
                {currentSessionFindings.length > 0 && (
                  <div
                    style={{
                      maxWidth: '1080px',
                      margin: '0 auto',
                      width: '100%',
                      backgroundColor: 'var(--color-surface)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--color-border)',
                      padding: '20px 24px',
                      boxShadow: 'var(--shadow-subtle)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '16px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <ShieldAlert size={16} style={{ color: 'var(--color-sev-critical)' }} />
                        <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 800, color: 'var(--color-ink)' }}>
                          Attributed Cryptographic Anomalies on Stream #{selectedSession.tcp_stream_id} ({currentSessionFindings.length})
                        </h3>
                      </div>
                      <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--color-ink-muted)' }}>
                        CLICK CARD TO OPEN DETAILED DOSSIER
                      </span>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '12px' }}>
                      {currentSessionFindings.map((f, fIdx) => (
                        <div
                          key={fIdx}
                          onClick={() => selectFinding(f)}
                          style={{
                            padding: '14px 16px',
                            backgroundColor: 'var(--color-panel-card)',
                            border: '1px solid var(--color-border)',
                            borderLeft: `4px solid ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'var(--color-sev-critical)' : 'var(--color-sev-medium)'}`,
                            borderRadius: 'var(--radius-xs)',
                            cursor: 'pointer',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '8px',
                            transition: 'all var(--transition-fast)',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <SeverityBadge severity={f.severity} />
                            {f.penalising && (
                              <span
                                style={{
                                  fontSize: '10px',
                                  fontFamily: 'var(--font-mono)',
                                  fontWeight: 800,
                                  color: 'var(--color-sev-critical)',
                                }}
                              >
                                PENALISING
                              </span>
                            )}
                          </div>

                          <div style={{ fontWeight: 800, fontSize: 'var(--text-xs)', color: 'var(--color-ink)' }}>
                            {f.title}
                          </div>

                          <div style={{ fontSize: '11px', color: 'var(--color-ink-secondary)', lineHeight: 1.4 }}>
                            {f.conclusion || f.explanation}
                          </div>

                          {f.citations && f.citations.length > 0 && (
                            <div
                              style={{
                                fontSize: '10px',
                                fontFamily: 'var(--font-mono)',
                                color: 'var(--color-accent)',
                                marginTop: '4px',
                                fontWeight: 700,
                              }}
                            >
                              Standard: {f.citations[0].standard} {f.citations[0].section}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}

            {activeTab === 'evidence' && <EvidenceMatrix session={selectedSession} />}

            {activeTab === 'certs' && <CertificateForensics session={selectedSession} />}
          </>
        ) : (
          <div
            style={{
              padding: '40px',
              textAlign: 'center',
              color: 'var(--color-ink-muted)',
              fontSize: 'var(--text-sm)',
            }}
          >
            No session currently selected. Select a stream from the horizontal reel above.
          </div>
        )}
      </div>

      {/* ============================================================ */}
      {/* 4. CONTEXTUAL FORENSIC DOSSIER SLIDE-OVER DRAWER */}
      {/* ============================================================ */}
      <ContextualInspector session={selectedSession} />
    </div>
  );
};
