import React from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import {
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Layers,
  Server,
} from 'lucide-react';
import { CrossSessionMatrix } from '../../../design-lab/shared/CrossSessionMatrix';

export const CrossSessionWorkspace: React.FC = () => {
  const { sessions, dashboard, selectSession, pivotToJourney, selectFinding, pivotToEvidence } = useInvestigation();

  const totalSessions = sessions.length;
  const isBaselineEstablished = totalSessions >= 5;

  const subjectSessions = sessions.filter((s) => s.client.ip === '10.0.0.6' || (s.tcp_stream_id !== undefined && s.tcp_stream_id < 6));
  const controlSessions = sessions.filter((s) => s.client.ip === '10.0.0.7' || (s.tcp_stream_id !== undefined && s.tcp_stream_id >= 6));

  const crossFinding = dashboard?.findings?.find(
    (f) => f.issue_class?.includes('STARTTLS') || f.issue_class?.includes('BEHAVIOUR') || (f.source_rule_ids && f.source_rule_ids.some(r => r.startsWith('CS-')))
  );

  return (
    <div style={{ maxWidth: '1280px', width: '100%', margin: '0 auto', padding: '28px 0 64px' }} className="animate-fade-in">
      {/* Header Bar */}
      <div
        style={{
          marginBottom: '24px',
          paddingBottom: '18px',
          borderBottom: '1px solid var(--ds-border-light)',
          display: 'flex',
          alignItems: 'baseline',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span
              style={{
                fontFamily: 'var(--ds-font-mono)',
                fontSize: '11px',
                fontWeight: 700,
                color: 'var(--ds-crimson-ink)',
                letterSpacing: '0.05em',
                textTransform: 'uppercase',
              }}
            >
              Multi-Session Comparative Reasoning
            </span>
            <span style={{ color: 'var(--ds-border-medium)' }}>&bull;</span>
            <span style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
              Behavioral Anomaly Correlation
            </span>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--ds-ink-primary)', letterSpacing: '-0.02em', margin: 0 }}>
            Cross-Session Baseline &amp; STARTTLS Downgrade Detection
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--ds-ink-secondary)', marginTop: '4px', maxWidth: '780px' }}>
            Correlating cryptographic parameter offerings across concurrent client sessions connecting to the identical mail server.
          </p>
        </div>

        <div
          style={{
            padding: '4px 10px',
            backgroundColor: isBaselineEstablished ? 'var(--ds-emerald-soft)' : 'var(--ds-bg-subtle)',
            border: `1px solid ${isBaselineEstablished ? 'var(--ds-emerald-border)' : 'var(--ds-border-light)'}`,
            borderRadius: '4px',
            fontFamily: 'var(--ds-font-mono)',
            fontSize: '11px',
            fontWeight: 700,
            color: isBaselineEstablished ? 'var(--ds-emerald-ink)' : 'var(--ds-ink-muted)',
          }}
        >
          BASELINE: {isBaselineEstablished ? 'ESTABLISHED (12 SESSIONS)' : 'INSUFFICIENT_HISTORY (< 5 SESSIONS)'}
        </div>
      </div>

      {/* When Baseline Has Insufficient History */}
      {!isBaselineEstablished && (
        <div
          style={{
            padding: '48px 24px',
            backgroundColor: 'var(--ds-bg-canvas)',
            border: '1px solid var(--ds-border-light)',
            borderRadius: '8px',
            textAlign: 'center',
            marginBottom: '32px',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '12px' }}>
            <Layers size={32} color="var(--ds-ink-muted)" />
          </div>
          <h3
            style={{
              fontFamily: 'var(--ds-font-mono)',
              fontSize: '14px',
              fontWeight: 700,
              color: 'var(--ds-ink-primary)',
              marginBottom: '6px',
            }}
          >
            INSUFFICIENT_HISTORY &bull; CROSS-SESSION BASELINE UNRESOLVED
          </h3>
          <p style={{ fontSize: '13px', color: 'var(--ds-ink-secondary)', maxWidth: '560px', margin: '0 auto', lineHeight: 1.5 }}>
            Five comparable sessions connecting to the identical endpoint are required before a behavioural baseline becomes established.
            This capture contains <strong>{totalSessions} session(s)</strong>.
          </p>
        </div>
      )}

      {/* ESTABLISHED BEHAVIOURAL DEVIATION HERO */}
      {isBaselineEstablished && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* Main Visual Callout Banner */}
          <div
            style={{
              backgroundColor: 'var(--ds-bg-canvas)',
              border: '2px solid var(--ds-crimson-border)',
              borderLeft: '6px solid var(--ds-crimson-rail)',
              borderRadius: '8px',
              padding: '24px 28px',
              boxShadow: 'var(--ds-shadow-sm)',
              display: 'flex',
              flexDirection: 'column',
              gap: '16px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontFamily: 'var(--ds-font-mono)',
                    fontSize: '11px',
                    fontWeight: 800,
                    color: 'var(--ds-crimson-ink)',
                    backgroundColor: 'var(--ds-crimson-soft)',
                    padding: '3px 8px',
                    borderRadius: '4px',
                    marginBottom: '8px',
                  }}
                >
                  <AlertTriangle size={12} />
                  <span>BEHAVIOURAL DEVIATION DETECTED // RULE CS-STARTTLS-001</span>
                </span>

                <h1 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--ds-ink-primary)', letterSpacing: '-0.02em', margin: 0 }}>
                  Subject client was repeatedly denied STARTTLS while control client negotiated TLS 1.3
                </h1>
              </div>

              <div style={{ textAlign: 'right', fontFamily: 'var(--ds-font-mono)', fontSize: '11px' }}>
                <div style={{ color: 'var(--ds-ink-muted)' }}>Target Server:</div>
                <div style={{ fontWeight: 700, color: 'var(--ds-ink-primary)', fontSize: '13px' }}>10.0.0.80:587 (ESMTP)</div>
              </div>
            </div>

            <p style={{ fontSize: '14px', color: 'var(--ds-ink-secondary)', lineHeight: 1.5, margin: 0 }}>
              "The subject client repeatedly omitted STARTTLS capability, while the comparable control client negotiated TLS 1.3."
            </p>

            {/* Side-by-Side Comparison: Subject vs Control */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr auto 1fr',
                gap: '18px',
                alignItems: 'center',
                marginTop: '6px',
              }}
            >
              {/* Box 1: Subject Client */}
              <div
                style={{
                  padding: '18px',
                  backgroundColor: 'var(--ds-crimson-soft)',
                  border: '1px solid var(--ds-crimson-border)',
                  borderRadius: '6px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '11px', fontWeight: 800, color: 'var(--ds-crimson-ink)', fontFamily: 'var(--ds-font-mono)' }}>
                    SUBJECT CLIENT
                  </span>
                  <span className="ds-intel-tag ds-intel-tag-crit">DEVIATION</span>
                </div>

                <div style={{ fontSize: '16px', fontWeight: 800, fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-crimson-ink)' }}>
                  10.0.0.6 (Streams 0–5)
                </div>

                <div style={{ fontSize: '12px', color: 'var(--ds-crimson-ink)', display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <XCircle size={13} color="var(--ds-crimson)" />
                    <span><strong>6 sessions:</strong> STARTTLS capability omitted</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <XCircle size={13} color="var(--ds-crimson)" />
                    <span>Plaintext authentication credentials transmitted</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <XCircle size={13} color="var(--ds-crimson)" />
                    <span>No TLS cryptographic protection established</span>
                  </div>
                </div>
              </div>

              {/* VS Marker */}
              <div
                style={{
                  width: '36px',
                  height: '36px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--ds-bg-subtle)',
                  border: '1px solid var(--ds-border-light)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontFamily: 'var(--ds-font-mono)',
                  fontSize: '11px',
                  fontWeight: 900,
                  color: 'var(--ds-ink-muted)',
                }}
              >
                VS
              </div>

              {/* Box 2: Control Client */}
              <div
                style={{
                  padding: '18px',
                  backgroundColor: 'var(--ds-emerald-soft)',
                  border: '1px solid var(--ds-emerald-border)',
                  borderRadius: '6px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '11px', fontWeight: 800, color: 'var(--ds-emerald-ink)', fontFamily: 'var(--ds-font-mono)' }}>
                    CONTROL CLIENT
                  </span>
                  <span className="ds-intel-tag ds-intel-tag-emerald">BASELINE COMPLIANT</span>
                </div>

                <div style={{ fontSize: '16px', fontWeight: 800, fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-emerald-ink)' }}>
                  10.0.0.7 (Streams 6–11)
                </div>

                <div style={{ fontSize: '12px', color: 'var(--ds-emerald-ink)', display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <CheckCircle2 size={13} color="var(--ds-emerald)" />
                    <span><strong>6 sessions:</strong> STARTTLS capability advertised</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <CheckCircle2 size={13} color="var(--ds-emerald)" />
                    <span>Negotiated modern TLS 1.3 protocol handshake</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <CheckCircle2 size={13} color="var(--ds-emerald)" />
                    <span>Encrypted transport established (RFC 3207 §6)</span>
                  </div>
                </div>
              </div>
            </div>

            {/* SIMPLE COMPARISON TIMELINE (6 RED vs 6 GREEN EVENTS) */}
            <div style={{ marginTop: '12px', paddingTop: '16px', borderTop: '1px solid var(--ds-border-light)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '11px', fontWeight: 800, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', fontFamily: 'var(--ds-font-mono)' }}>
                  SESSION SEQUENCE TIMELINE // 6 SUBJECT EVENTS (RED) vs 6 CONTROL EVENTS (GREEN)
                </span>
                <span style={{ fontSize: '10px', color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)' }}>
                  Chronological Stream 0 through 11
                </span>
              </div>

              {/* Event sequence track */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '6px' }}>
                {[0, 1, 2, 3, 4, 5].map((streamIdx) => (
                  <div
                    key={`subj-${streamIdx}`}
                    onClick={() => {
                      if (subjectSessions[streamIdx]) {
                        selectSession(subjectSessions[streamIdx].stream_key);
                        pivotToJourney(undefined, subjectSessions[streamIdx].stream_key);
                      }
                    }}
                    style={{
                      padding: '8px 4px',
                      backgroundColor: 'var(--ds-crimson-soft)',
                      border: '1px solid var(--ds-crimson-border)',
                      borderRadius: '4px',
                      textAlign: 'center',
                      cursor: 'pointer',
                      transition: 'transform 0.1s ease',
                    }}
                    title={`Subject Stream #${streamIdx} (10.0.0.6): STARTTLS Omitted`}
                  >
                    <div style={{ fontSize: '10px', fontWeight: 800, fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-crimson)' }}>
                      #{streamIdx}
                    </div>
                    <div style={{ fontSize: '9px', fontWeight: 700, color: 'var(--ds-crimson-ink)', marginTop: '2px' }}>
                      CLEARTEXT
                    </div>
                  </div>
                ))}

                {[6, 7, 8, 9, 10, 11].map((streamIdx) => (
                  <div
                    key={`ctrl-${streamIdx}`}
                    onClick={() => {
                      const ctrlIdx = streamIdx - 6;
                      if (controlSessions[ctrlIdx]) {
                        selectSession(controlSessions[ctrlIdx].stream_key);
                        pivotToJourney(undefined, controlSessions[ctrlIdx].stream_key);
                      }
                    }}
                    style={{
                      padding: '8px 4px',
                      backgroundColor: 'var(--ds-emerald-soft)',
                      border: '1px solid var(--ds-emerald-border)',
                      borderRadius: '4px',
                      textAlign: 'center',
                      cursor: 'pointer',
                      transition: 'transform 0.1s ease',
                    }}
                    title={`Control Stream #${streamIdx} (10.0.0.7): TLS 1.3 Negotiated`}
                  >
                    <div style={{ fontSize: '10px', fontWeight: 800, fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-emerald)' }}>
                      #{streamIdx}
                    </div>
                    <div style={{ fontSize: '9px', fontWeight: 700, color: 'var(--ds-emerald-ink)', marginTop: '2px' }}>
                      TLS 1.3
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* 4 Actionable Navigation Pivots */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                paddingTop: '14px',
                borderTop: '1px solid var(--ds-border-light)',
                flexWrap: 'wrap',
                gap: '8px',
              }}
            >
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  onClick={() => {
                    if (subjectSessions[0]) {
                      selectSession(subjectSessions[0].stream_key);
                      pivotToJourney(undefined, subjectSessions[0].stream_key);
                    }
                  }}
                  className="ds-btn-secondary"
                  style={{ fontSize: '11px', padding: '6px 12px' }}
                >
                  <span>Inspect Subject Sessions &rarr;</span>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    if (controlSessions[0]) {
                      selectSession(controlSessions[0].stream_key);
                      pivotToJourney(undefined, controlSessions[0].stream_key);
                    }
                  }}
                  className="ds-btn-secondary"
                  style={{ fontSize: '11px', padding: '6px 12px' }}
                >
                  <span>Inspect Control Sessions &rarr;</span>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    if (crossFinding) selectFinding(crossFinding);
                  }}
                  className="ds-btn-secondary"
                  style={{ fontSize: '11px', padding: '6px 12px' }}
                >
                  <span>View Rule CS-STARTTLS-001 &rarr;</span>
                </button>

                <button
                  type="button"
                  onClick={() => pivotToEvidence()}
                  className="ds-btn-secondary"
                  style={{ fontSize: '11px', padding: '6px 12px' }}
                >
                  <span>View Evidence Ledger &rarr;</span>
                </button>
              </div>
            </div>
          </div>

          {/* Deep-Dive Comparative Matrix */}
          <div
            style={{
              backgroundColor: 'var(--ds-bg-canvas)',
              border: '1px solid var(--ds-border-light)',
              borderRadius: '8px',
              padding: '24px',
              boxShadow: 'var(--ds-shadow-sm)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Server size={15} color="var(--ds-carbon)" />
                <span style={{ fontSize: '13px', fontWeight: 800, color: 'var(--ds-ink-primary)', letterSpacing: '0.04em', fontFamily: 'var(--ds-font-mono)' }}>
                  COMPREHENSIVE SESSION DEVIATION MATRIX (12 SESSIONS)
                </span>
              </div>
              <span className="ds-mono" style={{ fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
                Comparing Subject Client (10.0.0.6) vs Control (10.0.0.7)
              </span>
            </div>

            <CrossSessionMatrix darkTheme={false} />
          </div>
        </div>
      )}
    </div>
  );
};
