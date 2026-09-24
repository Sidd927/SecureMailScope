import React from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { EvidenceBadge } from '../../common/EvidenceBadge';
import { SeverityBadge } from '../../common/SeverityBadge';
import { ArrowRight, ArrowLeft, Clock } from 'lucide-react';
import type { SessionEvidence, FindingRow } from '../../../api/types';
import { formatEndpoint, formatProtocol } from '../../../utils/formatters';

interface ProtocolTimelineProps {
  session: SessionEvidence;
}

export const ProtocolTimeline: React.FC<ProtocolTimelineProps> = ({ session }) => {
  const { dashboard, selectedEventFrame, selectEventFrame, selectFinding } = useInvestigation();

  // Find findings affecting this session
  const sessionFindings = (dashboard?.findings || []).filter((f) =>
    f.affected_stream_keys.includes(session.stream_key)
  );

  // Group findings by frame for timeline anchoring
  const findingsByFrame: Record<number, FindingRow[]> = {};
  for (const f of sessionFindings) {
    for (const frame of f.frames || []) {
      if (!findingsByFrame[frame]) findingsByFrame[frame] = [];
      findingsByFrame[frame].push(f);
    }
  }

  const { transitions = [], events = [], timing } = session;

  // Calculate duration
  const startEpoch = timing?.start_epoch;
  const endEpoch = timing?.end_epoch;
  const durationMs =
    startEpoch && endEpoch ? ((endEpoch - startEpoch) * 1000).toFixed(2) : null;

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '24px',
        width: '100%',
        maxWidth: '1080px',
        margin: '0 auto',
      }}
    >
      {/* Session Dossier Summary Banner */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
          padding: '16px 20px',
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--color-border)',
          boxShadow: 'var(--shadow-subtle)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <div
            style={{
              padding: '6px 12px',
              backgroundColor: 'var(--color-accent)',
              color: '#ffffff',
              borderRadius: 'var(--radius-xs)',
              fontSize: 'var(--text-xs)',
              fontFamily: 'var(--font-mono)',
              fontWeight: 800,
              letterSpacing: '0.04em',
            }}
          >
            STREAM #{session.tcp_stream_id} · {formatProtocol(session.protocol, session.implicit_tls)}
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
            }}
          >
            <span style={{ color: 'var(--color-ink-muted)' }}>CLIENT:</span>
            <span style={{ fontWeight: 700, color: 'var(--color-ink)' }}>{formatEndpoint(session.client)}</span>
            <span style={{ color: 'var(--color-ink-faint)' }}>⇄</span>
            <span style={{ color: 'var(--color-ink-muted)' }}>SERVER:</span>
            <span style={{ fontWeight: 700, color: 'var(--color-ink)' }}>{formatEndpoint(session.server)}</span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
          {durationMs && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--color-ink-muted)' }}>
              <Clock size={12} />
              <span>{durationMs} ms</span>
            </div>
          )}

          <div style={{ color: 'var(--color-ink-muted)' }}>
            Frames: <strong style={{ color: 'var(--color-ink)' }}>{timing?.first_frame ?? 1}–{timing?.last_frame ?? 1}</strong> ({timing?.packet_count ?? 0} pkts)
          </div>

          {session.implicit_tls ? (
            <span
              style={{
                padding: '2px 8px',
                borderRadius: 'var(--radius-xs)',
                backgroundColor: 'var(--color-accent-soft)',
                color: 'var(--color-accent)',
                fontWeight: 700,
                fontSize: '10px',
              }}
            >
              IMPLICIT TLS (DIRECT)
            </span>
          ) : (
            <span
              style={{
                padding: '2px 8px',
                borderRadius: 'var(--radius-xs)',
                backgroundColor: 'var(--color-panel)',
                color: 'var(--color-ink-secondary)',
                fontWeight: 600,
                fontSize: '10px',
              }}
            >
              EXPLICIT UPGRADE (STARTTLS)
            </span>
          )}
        </div>
      </div>

      {/* Protocol Journey Canvas */}
      <div
        style={{
          position: 'relative',
          paddingLeft: '40px',
          display: 'flex',
          flexDirection: 'column',
          gap: '24px',
        }}
      >
        {/* Continuous Spine Line */}
        <div
          style={{
            position: 'absolute',
            left: '17px',
            top: '20px',
            bottom: '20px',
            width: '2px',
            backgroundColor: 'var(--color-border-strong)',
            zIndex: 1,
          }}
          aria-hidden="true"
        />

        {/* Milestone 00: Socket Transport Established */}
        <div style={{ position: 'relative', zIndex: 2 }}>
          {/* Spine Node Dot */}
          <div
            style={{
              position: 'absolute',
              left: '-40px',
              top: '12px',
              width: '36px',
              height: '36px',
              borderRadius: '50%',
              backgroundColor: 'var(--color-surface)',
              border: '2px solid var(--color-border-strong)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '11px',
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              color: 'var(--color-ink-muted)',
              boxShadow: 'var(--shadow-subtle)',
            }}
          >
            00
          </div>

          <div
            style={{
              backgroundColor: 'var(--color-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-sm)',
              padding: '14px 18px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div
                style={{
                  fontSize: '10px',
                  fontFamily: 'var(--font-mono)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  fontWeight: 700,
                  color: 'var(--color-ink-muted)',
                }}
              >
                TCP Transport Socket Connection
              </div>
              <div style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-ink)', marginTop: '2px' }}>
                Three-Way Handshake Established
              </div>
            </div>

            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                color: 'var(--color-ink-muted)',
                backgroundColor: 'var(--color-panel)',
                padding: '3px 8px',
                borderRadius: 'var(--radius-xs)',
              }}
            >
              Frame #{timing?.first_frame ?? 1}
            </div>
          </div>
        </div>

        {/* Dynamic Milestones: Transitions from transitions[] */}
        {transitions.map((trans, idx) => {
          const stepNum = String(idx + 1).padStart(2, '0');
          const isTransitionSelected = trans.evidence_frames.includes(selectedEventFrame || -1);

          // Find findings belonging to this transition's frames
          const relatedFindings: FindingRow[] = [];
          for (const fr of trans.evidence_frames) {
            if (findingsByFrame[fr]) {
              for (const f of findingsByFrame[fr]) {
                if (!relatedFindings.some((rf) => rf.title === f.title)) {
                  relatedFindings.push(f);
                }
              }
            }
          }

          // Matching directional packets for this transition
          const matchingEvents = events.filter((ev) => trans.evidence_frames.includes(ev.frame));

          return (
            <div key={idx} style={{ position: 'relative', zIndex: 2 }}>
              {/* Spine Node Dot */}
              <div
                style={{
                  position: 'absolute',
                  left: '-40px',
                  top: '14px',
                  width: '36px',
                  height: '36px',
                  borderRadius: '50%',
                  backgroundColor: isTransitionSelected ? 'var(--color-accent)' : 'var(--color-surface)',
                  border: `2px solid ${isTransitionSelected ? 'var(--color-accent)' : 'var(--color-border-strong)'}`,
                  color: isTransitionSelected ? '#ffffff' : 'var(--color-ink)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '11px',
                  fontWeight: 800,
                  fontFamily: 'var(--font-mono)',
                  boxShadow: 'var(--shadow-subtle)',
                  transition: 'all var(--transition-fast)',
                }}
              >
                {stepNum}
              </div>

              <div
                style={{
                  backgroundColor: isTransitionSelected ? 'var(--color-accent-soft)' : 'var(--color-surface)',
                  border: `1px solid ${isTransitionSelected ? 'var(--color-accent)' : 'var(--color-border)'}`,
                  borderRadius: 'var(--radius-md)',
                  padding: '18px 20px',
                  boxShadow: isTransitionSelected ? '0 0 0 1px var(--color-accent)' : 'var(--shadow-subtle)',
                  transition: 'all var(--transition-fast)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px',
                }}
              >
                {/* State Machine Transition Header */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '11px',
                        fontWeight: 800,
                        backgroundColor: 'var(--color-panel)',
                        border: '1px solid var(--color-border)',
                        padding: '2px 8px',
                        borderRadius: 'var(--radius-xs)',
                        color: 'var(--color-ink)',
                      }}
                    >
                      {trans.from_state} ➔ {trans.to_state}
                    </span>

                    <span
                      style={{
                        fontSize: 'var(--text-sm)',
                        fontWeight: 700,
                        color: 'var(--color-ink)',
                      }}
                    >
                      {trans.event}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <EvidenceBadge state={trans.evidence_state} size="sm" />
                    {trans.timestamp_epoch !== null && (
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--color-ink-muted)' }}>
                        +{trans.timestamp_epoch.toFixed(3)}s
                      </span>
                    )}
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--color-ink-muted)' }}>
                      Frames: {trans.evidence_frames.join(', ')}
                    </span>
                  </div>
                </div>

                {/* Transition Basis Description */}
                <div
                  style={{
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--color-ink-secondary)',
                    backgroundColor: 'var(--color-panel-card)',
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-xs)',
                    border: '1px solid var(--color-border-subtle)',
                  }}
                >
                  <strong style={{ color: 'var(--color-ink)' }}>Basis:</strong> {trans.basis || 'Protocol dissection observation'}
                </div>

                {/* Directional Packet Flow (if observable events exist) */}
                {matchingEvents.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '4px' }}>
                    <div
                      style={{
                        fontSize: '10px',
                        fontFamily: 'var(--font-mono)',
                        textTransform: 'uppercase',
                        color: 'var(--color-ink-muted)',
                        letterSpacing: '0.06em',
                        fontWeight: 700,
                      }}
                    >
                      Observed Directional Handshake Packets ({matchingEvents.length})
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      {matchingEvents.map((ev, evIdx) => {
                        const isClient = ev.direction === 'CLIENT_TO_SERVER';
                        const isSelected = selectedEventFrame === ev.frame;

                        return (
                          <div
                            key={evIdx}
                            onClick={() => selectEventFrame(ev.frame)}
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              padding: '8px 12px',
                              borderRadius: 'var(--radius-xs)',
                              backgroundColor: isSelected
                                ? 'var(--color-accent-soft)'
                                : isClient
                                  ? 'var(--color-surface)'
                                  : 'var(--color-panel-card)',
                              border: `1px solid ${isSelected ? 'var(--color-accent)' : 'var(--color-border-subtle)'}`,
                              cursor: 'pointer',
                              fontFamily: 'var(--font-mono)',
                              fontSize: '11px',
                              transition: 'all var(--transition-fast)',
                            }}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                              <span style={{ color: 'var(--color-ink-muted)', width: '64px', fontWeight: 600 }}>
                                Frame #{ev.frame}
                              </span>

                              <span
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                  fontWeight: 700,
                                  color: isClient ? 'var(--color-accent)' : 'var(--color-sev-info)',
                                  width: '130px',
                                }}
                              >
                                {isClient ? <ArrowRight size={12} /> : <ArrowLeft size={12} />}
                                <span>{isClient ? 'CLIENT ➔ SERVER' : 'SERVER ➔ CLIENT'}</span>
                              </span>

                              <span
                                style={{
                                  padding: '1px 6px',
                                  backgroundColor: 'var(--color-panel)',
                                  borderRadius: 'var(--radius-xs)',
                                  fontSize: '10px',
                                  fontWeight: 600,
                                  color: 'var(--color-ink)',
                                }}
                              >
                                {ev.kind}
                              </span>

                              {ev.detail && (
                                <span
                                  style={{
                                    color: 'var(--color-ink-secondary)',
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap',
                                    maxWidth: '340px',
                                  }}
                                >
                                  {ev.detail}
                                </span>
                              )}
                            </div>

                            <span
                              style={{
                                fontSize: '10px',
                                color: isSelected ? 'var(--color-accent)' : 'var(--color-ink-faint)',
                                fontWeight: 700,
                              }}
                            >
                              INSPECT ➔
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Anchored Security Findings Alert Banner */}
                {relatedFindings.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '6px' }}>
                    {relatedFindings.map((finding, fIdx) => (
                      <div
                        key={fIdx}
                        onClick={() => selectFinding(finding)}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '10px 14px',
                          backgroundColor: 'var(--color-sev-critical-bg)',
                          border: '1px solid var(--color-sev-critical-border)',
                          borderLeft: '4px solid var(--color-sev-critical)',
                          borderRadius: 'var(--radius-xs)',
                          cursor: 'pointer',
                          transition: 'all var(--transition-fast)',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <SeverityBadge severity={finding.severity} />
                          <div>
                            <div style={{ fontWeight: 800, fontSize: 'var(--text-xs)', color: 'var(--color-ink)' }}>
                              {finding.title}
                            </div>
                            <div style={{ fontSize: '11px', color: 'var(--color-ink-secondary)', marginTop: '2px' }}>
                              {finding.conclusion}
                            </div>
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
                          {finding.penalising && (
                            <span
                              style={{
                                fontSize: '10px',
                                fontFamily: 'var(--font-mono)',
                                fontWeight: 700,
                                color: 'var(--color-sev-critical)',
                              }}
                            >
                              PENALISING
                            </span>
                          )}
                          <span
                            style={{
                              fontSize: '10px',
                              fontFamily: 'var(--font-mono)',
                              fontWeight: 800,
                              color: 'var(--color-sev-critical)',
                              backgroundColor: '#ffffff',
                              border: '1px solid var(--color-sev-critical-border)',
                              padding: '3px 8px',
                              borderRadius: 'var(--radius-xs)',
                            }}
                          >
                            OPEN DOSSIER ➔
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {/* Milestone END: Session Completion */}
        <div style={{ position: 'relative', zIndex: 2 }}>
          {/* Spine Node Dot */}
          <div
            style={{
              position: 'absolute',
              left: '-40px',
              top: '12px',
              width: '36px',
              height: '36px',
              borderRadius: '50%',
              backgroundColor: 'var(--color-surface)',
              border: '2px solid var(--color-border-strong)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '10px',
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              color: 'var(--color-ink-muted)',
              boxShadow: 'var(--shadow-subtle)',
            }}
          >
            END
          </div>

          <div
            style={{
              backgroundColor: 'var(--color-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-sm)',
              padding: '14px 18px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div
                style={{
                  fontSize: '10px',
                  fontFamily: 'var(--font-mono)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  fontWeight: 700,
                  color: 'var(--color-ink-muted)',
                }}
              >
                Session Teardown & Finalization
              </div>
              <div style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-ink)', marginTop: '2px' }}>
                Transport Flags: {session.transport_flags?.length ? session.transport_flags.join(', ') : 'NONE'}
              </div>
            </div>

            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                color: 'var(--color-ink-muted)',
                backgroundColor: 'var(--color-panel)',
                padding: '3px 8px',
                borderRadius: 'var(--radius-xs)',
              }}
            >
              Frame #{timing?.last_frame ?? 1}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
