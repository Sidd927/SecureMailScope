import React, { useEffect } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { SeverityBadge } from '../../common/SeverityBadge';
import { ForensicHash } from '../../common/ForensicHash';
import { ArrowRight, ArrowLeft, X, ShieldAlert, BookOpen, Layers, CheckCircle2 } from 'lucide-react';
import type { SessionEvidence } from '../../../api/types';
import { formatEndpoint, formatProtocol } from '../../../utils/formatters';

interface ContextualInspectorProps {
  session: SessionEvidence | null;
  isOpen?: boolean;
  onClose?: () => void;
}

export const ContextualInspector: React.FC<ContextualInspectorProps> = ({
  session,
  isOpen: propsIsOpen,
  onClose: propsOnClose,
}) => {
  const {
    selectedFinding,
    selectFinding,
    selectedEventFrame,
    selectEventFrame,
    selectSession,
    dashboard,
  } = useInvestigation();

  const isExplicitlyOpen = propsIsOpen ?? (selectedFinding !== null || selectedEventFrame !== null);

  const handleClose = () => {
    selectFinding(null);
    selectEventFrame(null);
    if (propsOnClose) {
      propsOnClose();
    }
  };

  // Keyboard shortcut: Esc to dismiss
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isExplicitlyOpen) {
        handleClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isExplicitlyOpen]);

  if (!isExplicitlyOpen) return null;

  // Match event and transition
  const matchingEvent = session?.events?.find((e) => e.frame === selectedEventFrame);
  const matchingTransition = session?.transitions?.find((t) =>
    t.evidence_frames.includes(selectedEventFrame || -1)
  );

  // Attached findings on current frame
  const frameFindings = (dashboard?.findings || []).filter(
    (f) =>
      session &&
      f.affected_stream_keys.includes(session.stream_key) &&
      (f.frames || []).includes(selectedEventFrame || -1)
  );

  return (
    <>
      {/* Backdrop Overlay */}
      <div
        onClick={handleClose}
        style={{
          position: 'fixed',
          inset: 0,
          backgroundColor: 'rgba(15, 23, 42, 0.45)',
          backdropFilter: 'blur(2px)',
          zIndex: 999,
          transition: 'opacity 150ms ease-in-out',
        }}
        aria-hidden="true"
      />

      {/* Slide-over Drawer Surface */}
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Forensic Inspector Dossier"
        style={{
          position: 'fixed',
          top: 0,
          right: 0,
          bottom: 0,
          width: 'min(540px, 94vw)',
          backgroundColor: 'var(--color-surface)',
          borderLeft: '1px solid var(--color-border-strong)',
          boxShadow: 'var(--shadow-flyout), 0 0 40px rgba(0,0,0,0.15)',
          zIndex: 1000,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          animation: 'drawerSlideIn 200ms cubic-bezier(0.16, 1, 0.3, 1)',
        }}
      >
        {/* Drawer Header */}
        <div
          style={{
            padding: '16px 22px',
            backgroundColor: 'var(--color-panel)',
            borderBottom: '1px solid var(--color-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexShrink: 0,
          }}
        >
          <div>
            <div
              style={{
                fontSize: '10px',
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                fontWeight: 700,
                color: selectedFinding ? 'var(--color-sev-critical)' : 'var(--color-accent)',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              {selectedFinding ? (
                <>
                  <ShieldAlert size={12} />
                  <span>Security Anomaly Dossier</span>
                </>
              ) : selectedEventFrame !== null ? (
                <>
                  <Layers size={12} />
                  <span>Packet Dissection Inspector</span>
                </>
              ) : (
                <>
                  <BookOpen size={12} />
                  <span>Session Evidence File</span>
                </>
              )}
            </div>

            <h2
              style={{
                fontSize: 'var(--text-md)',
                fontWeight: 800,
                color: 'var(--color-ink)',
                marginTop: '2px',
                lineHeight: 1.25,
              }}
            >
              {selectedFinding
                ? selectedFinding.title
                : selectedEventFrame !== null
                  ? `Frame #${selectedEventFrame} Packet Inspection`
                  : `Stream #${session?.tcp_stream_id ?? 0} Forensic Summary`}
            </h2>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--font-mono)',
                color: 'var(--color-ink-muted)',
                backgroundColor: 'var(--color-surface)',
                border: '1px solid var(--color-border)',
                padding: '2px 6px',
                borderRadius: 'var(--radius-xs)',
              }}
            >
              ESC
            </span>
            <button
              type="button"
              onClick={handleClose}
              style={{
                padding: '6px',
                borderRadius: 'var(--radius-xs)',
                color: 'var(--color-ink-muted)',
                backgroundColor: 'var(--color-surface)',
                border: '1px solid var(--color-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                transition: 'all var(--transition-fast)',
              }}
              title="Close inspector (Esc)"
              aria-label="Close inspector"
            >
              <X size={15} />
            </button>
          </div>
        </div>

        {/* Drawer Scrollable Body */}
        <div
          style={{
            flex: 1,
            overflowY: 'auto',
            padding: '22px',
            display: 'flex',
            flexDirection: 'column',
            gap: '20px',
          }}
        >
          {/* ============================================================ */}
          {/* MODE A: A SECURITY FINDING IS SELECTED */}
          {/* ============================================================ */}
          {selectedFinding ? (
            <>
              {/* Finding Verdict Callout */}
              <div
                style={{
                  padding: '16px',
                  backgroundColor: 'var(--color-sev-critical-bg)',
                  border: '1px solid var(--color-sev-critical-border)',
                  borderLeft: '4px solid var(--color-sev-critical)',
                  borderRadius: 'var(--radius-sm)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <SeverityBadge severity={selectedFinding.severity} />
                    {selectedFinding.penalising && (
                      <span
                        style={{
                          fontSize: '10px',
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 800,
                          backgroundColor: 'var(--color-sev-critical)',
                          color: '#ffffff',
                          padding: '1px 6px',
                          borderRadius: 'var(--radius-xs)',
                          letterSpacing: '0.04em',
                        }}
                      >
                        PENALISING DEDUCTION
                      </span>
                    )}
                  </div>
                  {selectedFinding.frames?.length > 0 && (
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '11px',
                        color: 'var(--color-sev-critical)',
                        fontWeight: 700,
                      }}
                    >
                      Frame(s): {selectedFinding.frames.join(', ')}
                    </span>
                  )}
                </div>

                <div
                  style={{
                    fontSize: 'var(--text-base)',
                    fontWeight: 700,
                    color: 'var(--color-ink)',
                    lineHeight: 1.4,
                  }}
                >
                  {selectedFinding.conclusion || selectedFinding.explanation}
                </div>
              </div>

              {/* Detailed Technical Explanation */}
              {selectedFinding.explanation && selectedFinding.explanation !== selectedFinding.conclusion && (
                <div
                  style={{
                    padding: '14px',
                    backgroundColor: 'var(--color-panel-card)',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--color-border)',
                    fontSize: 'var(--text-xs)',
                    color: 'var(--color-ink-secondary)',
                    lineHeight: 1.5,
                  }}
                >
                  <div
                    style={{
                      fontSize: '10px',
                      fontFamily: 'var(--font-mono)',
                      textTransform: 'uppercase',
                      color: 'var(--color-ink-muted)',
                      letterSpacing: '0.05em',
                      fontWeight: 700,
                      marginBottom: '6px',
                    }}
                  >
                    Forensic Determination & Analysis
                  </div>
                  <div>{selectedFinding.explanation}</div>
                </div>
              )}

              {/* Authoritative RFC & NIST Standards Citations */}
              {selectedFinding.citations && selectedFinding.citations.length > 0 && (
                <div>
                  <div
                    style={{
                      fontSize: '10px',
                      fontFamily: 'var(--font-mono)',
                      textTransform: 'uppercase',
                      color: 'var(--color-ink-muted)',
                      letterSpacing: '0.06em',
                      fontWeight: 700,
                      marginBottom: '8px',
                    }}
                  >
                    Authoritative Standards Justification
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {selectedFinding.citations.map((cite, cIdx) => (
                      <div
                        key={cIdx}
                        style={{
                          padding: '12px 14px',
                          backgroundColor: 'var(--color-surface)',
                          border: '1px solid var(--color-border)',
                          borderLeft: '3px solid var(--color-accent)',
                          borderRadius: 'var(--radius-xs)',
                          fontSize: '11px',
                        }}
                      >
                        <div
                          style={{
                            fontWeight: 800,
                            fontFamily: 'var(--font-mono)',
                            color: 'var(--color-ink)',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px',
                          }}
                        >
                          <BookOpen size={12} style={{ color: 'var(--color-accent)' }} />
                          <span>{cite.standard} {cite.section}</span>
                        </div>

                        <div
                          style={{
                            color: 'var(--color-ink-secondary)',
                            marginTop: '6px',
                            fontStyle: 'italic',
                            lineHeight: 1.45,
                            backgroundColor: 'var(--color-panel-card)',
                            padding: '8px 10px',
                            borderRadius: 'var(--radius-xs)',
                            borderLeft: '2px solid var(--color-border-strong)',
                          }}
                        >
                          "{cite.text}"
                        </div>

                        {cite.reason && (
                          <div
                            style={{
                              color: 'var(--color-ink-muted)',
                              marginTop: '6px',
                              fontSize: '10px',
                              lineHeight: 1.35,
                            }}
                          >
                            <strong>Rationale:</strong> {cite.reason}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Mathematical Priority Factors Grid */}
              {selectedFinding.factors && Object.keys(selectedFinding.factors).length > 0 && (
                <div>
                  <div
                    style={{
                      fontSize: '10px',
                      fontFamily: 'var(--font-mono)',
                      textTransform: 'uppercase',
                      color: 'var(--color-ink-muted)',
                      letterSpacing: '0.06em',
                      fontWeight: 700,
                      marginBottom: '8px',
                    }}
                  >
                    Calculus Priority Factors
                  </div>

                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(2, 1fr)',
                      gap: '8px',
                    }}
                  >
                    {Object.entries(selectedFinding.factors).map(([factor, score]) => (
                      <div
                        key={factor}
                        style={{
                          padding: '8px 10px',
                          backgroundColor: 'var(--color-panel)',
                          border: '1px solid var(--color-border-subtle)',
                          borderRadius: 'var(--radius-xs)',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '11px',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                        }}
                      >
                        <span style={{ color: 'var(--color-ink-muted)', textTransform: 'capitalize' }}>
                          {factor.replace(/_/g, ' ')}
                        </span>
                        <strong style={{ color: 'var(--color-ink)' }}>{Number(score).toFixed(1)}</strong>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Affected Sessions Navigator */}
              {selectedFinding.affected_stream_keys && selectedFinding.affected_stream_keys.length > 0 && (
                <div>
                  <div
                    style={{
                      fontSize: '10px',
                      fontFamily: 'var(--font-mono)',
                      textTransform: 'uppercase',
                      color: 'var(--color-ink-muted)',
                      letterSpacing: '0.06em',
                      fontWeight: 700,
                      marginBottom: '8px',
                    }}
                  >
                    Affected Stream Sessions ({selectedFinding.affected_stream_keys.length})
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {selectedFinding.affected_stream_keys.map((sk) => {
                      const isCurrent = session?.stream_key === sk;
                      return (
                        <div
                          key={sk}
                          onClick={() => selectSession(sk)}
                          style={{
                            padding: '8px 12px',
                            backgroundColor: isCurrent ? 'var(--color-accent-soft)' : 'var(--color-surface)',
                            border: `1px solid ${isCurrent ? 'var(--color-accent)' : 'var(--color-border)'}`,
                            borderRadius: 'var(--radius-xs)',
                            fontFamily: 'var(--font-mono)',
                            fontSize: '11px',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            transition: 'all var(--transition-fast)',
                          }}
                        >
                          <span style={{ color: isCurrent ? 'var(--color-accent-ink)' : 'var(--color-ink)' }}>
                            {sk}
                          </span>
                          {isCurrent ? (
                            <span
                              style={{
                                fontSize: '10px',
                                fontWeight: 800,
                                color: 'var(--color-accent)',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '4px',
                              }}
                            >
                              <CheckCircle2 size={12} />
                              ACTIVE VIEW
                            </span>
                          ) : (
                            <span
                              style={{
                                fontSize: '10px',
                                color: 'var(--color-ink-muted)',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '4px',
                              }}
                            >
                              SWITCH ➔
                            </span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </>
          ) : selectedEventFrame !== null ? (
            /* ============================================================ */
            /* MODE B: A SPECIFIC TIMELINE PACKET / FRAME IS SELECTED */
            /* ============================================================ */
            <>
              {/* Frame Summary Pill */}
              <div
                style={{
                  padding: '14px 16px',
                  backgroundColor: 'var(--color-panel-card)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--color-border)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: 'var(--text-md)',
                      fontWeight: 800,
                      color: 'var(--color-ink)',
                    }}
                  >
                    FRAME #{selectedEventFrame}
                  </span>

                  {matchingEvent?.direction && (
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '5px',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '11px',
                        fontWeight: 700,
                        padding: '3px 8px',
                        borderRadius: 'var(--radius-xs)',
                        backgroundColor:
                          matchingEvent.direction === 'CLIENT_TO_SERVER'
                            ? 'var(--color-accent-soft)'
                            : 'var(--color-sev-info-bg)',
                        color:
                          matchingEvent.direction === 'CLIENT_TO_SERVER'
                            ? 'var(--color-accent)'
                            : 'var(--color-sev-info)',
                        border: `1px solid ${matchingEvent.direction === 'CLIENT_TO_SERVER' ? 'var(--color-accent-border)' : 'var(--color-sev-info-border)'}`,
                      }}
                    >
                      {matchingEvent.direction === 'CLIENT_TO_SERVER' ? (
                        <>
                          <ArrowRight size={12} />
                          <span>CLIENT ➔ SERVER</span>
                        </>
                      ) : (
                        <>
                          <ArrowLeft size={12} />
                          <span>SERVER ➔ CLIENT</span>
                        </>
                      )}
                    </span>
                  )}
                </div>

                {matchingEvent?.kind && (
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-ink-secondary)' }}>
                    Dissection Packet Kind:{' '}
                    <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-ink)' }}>
                      {matchingEvent.kind}
                    </strong>
                  </div>
                )}
              </div>

              {/* Raw Dissection Payload / Detail */}
              {matchingEvent?.detail && (
                <div>
                  <div
                    style={{
                      fontSize: '10px',
                      fontFamily: 'var(--font-mono)',
                      textTransform: 'uppercase',
                      color: 'var(--color-ink-muted)',
                      letterSpacing: '0.06em',
                      fontWeight: 700,
                      marginBottom: '6px',
                    }}
                  >
                    Packet Dissection Payload
                  </div>

                  <div
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '12px',
                      backgroundColor: 'var(--color-panel)',
                      padding: '12px 14px',
                      borderRadius: 'var(--radius-xs)',
                      border: '1px solid var(--color-border)',
                      color: 'var(--color-ink)',
                      wordBreak: 'break-all',
                      whiteSpace: 'pre-wrap',
                      lineHeight: 1.4,
                    }}
                  >
                    {matchingEvent.detail}
                  </div>
                </div>
              )}

              {/* Associated Protocol State Shift */}
              {matchingTransition && (
                <div
                  style={{
                    padding: '14px',
                    backgroundColor: 'var(--color-panel-card)',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--color-border)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px',
                  }}
                >
                  <div
                    style={{
                      fontSize: '10px',
                      fontFamily: 'var(--font-mono)',
                      textTransform: 'uppercase',
                      color: 'var(--color-accent)',
                      letterSpacing: '0.06em',
                      fontWeight: 700,
                    }}
                  >
                    Triggered State Machine Transition
                  </div>

                  <div
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: 'var(--text-xs)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                    }}
                  >
                    <span style={{ fontWeight: 600, color: 'var(--color-ink-muted)' }}>
                      {matchingTransition.from_state}
                    </span>
                    <ArrowRight size={13} style={{ color: 'var(--color-accent)' }} />
                    <span
                      style={{
                        fontWeight: 800,
                        color: 'var(--color-accent)',
                        backgroundColor: 'var(--color-accent-soft)',
                        padding: '2px 6px',
                        borderRadius: 'var(--radius-xs)',
                      }}
                    >
                      {matchingTransition.to_state}
                    </span>
                  </div>

                  <div style={{ fontSize: '11px', color: 'var(--color-ink-secondary)', marginTop: '2px' }}>
                    <strong>Basis:</strong> {matchingTransition.basis}
                  </div>
                </div>
              )}

              {/* Security Findings anchored to this frame */}
              {frameFindings.length > 0 && (
                <div>
                  <div
                    style={{
                      fontSize: '10px',
                      fontFamily: 'var(--font-mono)',
                      textTransform: 'uppercase',
                      color: 'var(--color-sev-critical)',
                      letterSpacing: '0.06em',
                      fontWeight: 700,
                      marginBottom: '8px',
                    }}
                  >
                    Anomalies Anchored to Frame #{selectedEventFrame} ({frameFindings.length})
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {frameFindings.map((f, fIdx) => (
                      <div
                        key={fIdx}
                        onClick={() => selectFinding(f)}
                        style={{
                          padding: '12px',
                          backgroundColor: 'var(--color-sev-critical-bg)',
                          border: '1px solid var(--color-sev-critical-border)',
                          borderRadius: 'var(--radius-xs)',
                          cursor: 'pointer',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '6px',
                          transition: 'all var(--transition-fast)',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <SeverityBadge severity={f.severity} />
                          <span style={{ fontSize: '10px', color: 'var(--color-sev-critical)', fontWeight: 700 }}>
                            VIEW FINDING ➔
                          </span>
                        </div>
                        <div style={{ fontWeight: 700, fontSize: 'var(--text-xs)', color: 'var(--color-ink)' }}>
                          {f.title}
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--color-ink-secondary)', lineHeight: 1.35 }}>
                          {f.conclusion}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            /* ============================================================ */
            /* MODE C: DEFAULT STREAM SUMMARY */
            /* ============================================================ */
            <>
              {session && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div
                    style={{
                      padding: '14px',
                      backgroundColor: 'var(--color-panel-card)',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--color-border)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px',
                    }}
                  >
                    <div style={{ fontWeight: 700, fontSize: 'var(--text-sm)', color: 'var(--color-ink)' }}>
                      Stream #{session.tcp_stream_id} ({formatProtocol(session.protocol, session.implicit_tls)})
                    </div>
                    <ForensicHash value={session.stream_key} length={28} label="Stream Key" />

                    <div style={{ marginTop: '4px', fontSize: 'var(--text-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <div>
                        <span style={{ color: 'var(--color-ink-muted)' }}>Client:</span>{' '}
                        <strong style={{ fontFamily: 'var(--font-mono)' }}>{formatEndpoint(session.client)}</strong>
                      </div>
                      <div>
                        <span style={{ color: 'var(--color-ink-muted)' }}>Server:</span>{' '}
                        <strong style={{ fontFamily: 'var(--font-mono)' }}>{formatEndpoint(session.server)}</strong>
                      </div>
                      <div>
                        <span style={{ color: 'var(--color-ink-muted)' }}>Packet Count:</span>{' '}
                        <strong style={{ fontFamily: 'var(--font-mono)' }}>{session.timing?.packet_count ?? 0} pkts</strong>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </aside>

      <style>{`
        @keyframes drawerSlideIn {
          from {
            transform: translateX(100%);
          }
          to {
            transform: translateX(0);
          }
        }
      `}</style>
    </>
  );
};
