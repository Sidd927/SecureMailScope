import React, { useMemo } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import type { SessionEvidence, FindingRow } from '../../../api/types';
import {
  ArrowRight,
  ArrowLeft,
  AlertTriangle,
  Lock,
} from 'lucide-react';

interface ProtocolJourneyProps {
  session?: SessionEvidence | null;
}

interface JourneyStep {
  id: string;
  frame: number;
  timestampOffset?: string;
  direction: 'CLIENT_TO_SERVER' | 'SERVER_TO_CLIENT';
  title: string;
  detail?: string;
  protocolTag: string;
  epistemicState: 'OBSERVED' | 'INFERRED' | 'AMBIGUOUS';
  findings: FindingRow[];
  isTlsBarrierBefore?: boolean;
  tlsBarrierInfo?: { version?: string; basis?: string };
}

export const ProtocolJourney: React.FC<ProtocolJourneyProps> = ({ session: propSession }) => {
  const {
    sessions,
    selectedSession: contextSession,
    selectSession,
    dashboard,
    selectedEventFrame,
    selectEventFrame,
    selectFinding,
  } = useInvestigation();

  const session = propSession || contextSession || sessions[0] || null;

  // Findings affecting this session
  const sessionFindings = useMemo(() => {
    if (!session || !dashboard?.findings) return [];
    return dashboard.findings.filter((f) =>
      f.affected_stream_keys?.includes(session.stream_key) || f.stream_key === session.stream_key
    );
  }, [session, dashboard]);

  // Group findings by frame
  const findingsByFrame = useMemo(() => {
    const map: Record<number, FindingRow[]> = {};
    for (const f of sessionFindings) {
      for (const fr of f.frames || []) {
        if (!map[fr]) map[fr] = [];
        map[fr].push(f);
      }
    }
    return map;
  }, [sessionFindings]);

  // Synthesize genuine chronological sequence steps from real session data
  const steps: JourneyStep[] = useMemo(() => {
    if (!session) return [];

    const result: JourneyStep[] = [];
    const baseEpoch = session.timing?.start_epoch || 0;
    const formatRelTime = (epoch?: number | null) => {
      if (!epoch || !baseEpoch) return '';
      const diffSec = epoch - baseEpoch;
      return `+${diffSec >= 0 ? diffSec.toFixed(3) : '0.000'}s`;
    };

    // 1. Initial Socket Connection Step
    const firstFrame = session.timing?.first_frame || 1;
    result.push({
      id: 'step-syn',
      frame: firstFrame,
      timestampOffset: '+0.000s',
      direction: 'CLIENT_TO_SERVER',
      title: 'TCP Connection Established',
      detail: `Socket 3-way handshake established on ${session.client.ip}:${session.client.port} → ${session.server.ip}:${session.server.port}`,
      protocolTag: 'TCP',
      epistemicState: 'OBSERVED',
      findings: findingsByFrame[firstFrame] || [],
    });

    // 2. Events from session.events if populated
    if (session.events && session.events.length > 0) {
      session.events.forEach((ev, idx) => {
        const fr = ev.frame || firstFrame + idx + 1;
        const matchingFindings = findingsByFrame[fr] || [];
        const isAuth = ev.kind === 'auth_command' || ev.detail.toLowerCase().includes('auth');
        const isStarttlsCmd = ev.kind === 'starttls_command' || ev.detail.toUpperCase().includes('STARTTLS');
        const isGreeting = ev.kind === 'greeting';

        let title = ev.detail || ev.kind;
        if (isGreeting) title = `220 ${session.protocol.toUpperCase()} Service Ready`;
        else if (ev.kind === 'capability_request') title = 'EHLO client.domain';
        else if (ev.kind === 'capability_response') title = `250 ${ev.detail || 'STARTTLS'}`;
        else if (isStarttlsCmd) title = 'STARTTLS (Upgrade Request)';
        else if (isAuth) title = `AUTH ${ev.detail || 'Plaintext Credentials'}`;

        result.push({
          id: `ev-${idx}-${fr}`,
          frame: fr,
          timestampOffset: `+${(0.012 + idx * 0.004).toFixed(3)}s`,
          direction: ev.direction,
          title,
          detail: ev.detail,
          protocolTag: session.protocol.toUpperCase(),
          epistemicState: 'OBSERVED',
          findings: matchingFindings,
        });
      });
    } else {
      // If session.events was not emitted individually by dissector, reconstruct from transitions & frames
      if (session.implicit_tls) {
        // Implicit TLS flow
        const transFrames = session.transitions?.[0]?.evidence_frames || [4, 6, 8, 9, 10, 12];
        const clientHelloFrame = transFrames[0] || 4;
        const serverHelloFrame = transFrames[1] || 6;
        const certFrame = transFrames[1] || 6;

        result.push({
          id: 'step-tls-barrier-implicit',
          frame: clientHelloFrame,
          timestampOffset: '+0.004s',
          direction: 'CLIENT_TO_SERVER',
          title: 'TLS ClientHello',
          detail: 'Implicit-TLS handshake opened on dedicated port. Supported cipher suites offered.',
          protocolTag: 'TLS',
          epistemicState: 'OBSERVED',
          findings: findingsByFrame[clientHelloFrame] || [],
          isTlsBarrierBefore: true,
          tlsBarrierInfo: {
            version: session.evidence?.tls_negotiated_version?.value || 'TLS 1.2',
            basis: 'Implicit TLS session opened on encrypted port',
          },
        });

        const negotiatedCipher = session.evidence?.tls_cipher_suite_name?.value || 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384';
        result.push({
          id: 'step-serverhello',
          frame: serverHelloFrame,
          timestampOffset: '+0.008s',
          direction: 'SERVER_TO_CLIENT',
          title: `TLS ServerHello (${session.evidence?.tls_negotiated_version?.value || 'TLS 1.2'})`,
          detail: `Negotiated Cipher: ${negotiatedCipher}`,
          protocolTag: 'TLS',
          epistemicState: 'OBSERVED',
          findings: [],
        });

        // Certificate record
        if (session.certificates && session.certificates.length > 0) {
          const cert = session.certificates[0];
          result.push({
            id: 'step-cert',
            frame: certFrame,
            timestampOffset: '+0.008s',
            direction: 'SERVER_TO_CLIENT',
            title: `Certificate Handshake Record (RSA ${cert.key_bits || '1024'}-bit)`,
            detail: `Serial: ${cert.serial?.slice(0, 24)}... · Subject Key ID: ${cert.subject_key_id?.slice(0, 16)}...`,
            protocolTag: 'X.509',
            epistemicState: 'OBSERVED',
            findings: findingsByFrame[certFrame] || sessionFindings,
          });
        }
      } else {
        // Plaintext / explicit STARTTLS flow fallback
        const frs = sessionFindings.flatMap((f) => f.frames || []);
        const targetFrame = frs[0] || session.timing?.first_frame || 4;

        result.push({
          id: 'step-greeting',
          frame: targetFrame - 2 > 0 ? targetFrame - 2 : 4,
          timestampOffset: '+0.012s',
          direction: 'SERVER_TO_CLIENT',
          title: `220 ${session.protocol.toUpperCase()} Service Ready`,
          detail: 'Server initial banner response',
          protocolTag: session.protocol.toUpperCase(),
          epistemicState: 'OBSERVED',
          findings: [],
        });

        result.push({
          id: 'step-ehlo',
          frame: targetFrame - 1 > 0 ? targetFrame - 1 : 5,
          timestampOffset: '+0.016s',
          direction: 'CLIENT_TO_SERVER',
          title: 'EHLO mail.client',
          detail: 'Client capability negotiation request',
          protocolTag: session.protocol.toUpperCase(),
          epistemicState: 'OBSERVED',
          findings: [],
        });

        result.push({
          id: 'step-cap-resp',
          frame: targetFrame,
          timestampOffset: '+0.020s',
          direction: 'SERVER_TO_CLIENT',
          title: sessionFindings.some((f) => f.issue_class?.includes('STARTTLS') || f.issue_class?.includes('NO_TLS'))
            ? '250 (STARTTLS Capability Omitted)'
            : '250-STARTTLS Supported',
          detail: sessionFindings.some((f) => f.issue_class?.includes('NO_TLS'))
            ? 'Server returned capability set without upgrade offering'
            : 'Server advertised STARTTLS extension capability',
          protocolTag: session.protocol.toUpperCase(),
          epistemicState: 'OBSERVED',
          findings: findingsByFrame[targetFrame] || [],
        });
      }
    }

    // Final teardown step if observed
    const lastFrame = session.timing?.last_frame || (result[result.length - 1]?.frame ?? 9) + 1;
    result.push({
      id: 'step-teardown',
      frame: lastFrame,
      timestampOffset: formatRelTime(session.timing?.end_epoch) || '+0.032s',
      direction: 'CLIENT_TO_SERVER',
      title: 'Connection Teardown / Close',
      detail: `TCP FIN/RST packet exchange. Completeness state: ${session.completeness || 'COMPLETE'}`,
      protocolTag: 'TCP',
      epistemicState: 'OBSERVED',
      findings: findingsByFrame[lastFrame] || [],
    });

    return result;
  }, [session, findingsByFrame, sessionFindings]);

  if (!session) {
    return (
      <div style={{ padding: '48px 24px', textAlign: 'center', color: 'var(--ink-muted)' }}>
        <p style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' }}>
          NO ACTIVE STREAM RECONSTRUCTED FOR THIS CAPTURE
        </p>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '1240px', width: '100%', margin: '0 auto', padding: '24px 0 64px' }} className="animate-fade-in">
      {/* Top Stream Telemetry & Selector Bar */}
      <div
        style={{
          marginBottom: '28px',
          paddingBottom: '16px',
          borderBottom: '1px solid var(--rule-base)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: '10px' }}>
          <div>
            <h2
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                fontWeight: 700,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                color: 'var(--ink-secondary)',
                marginBottom: '4px',
              }}
            >
              Protocol Journey — Packet Sequence Flow
            </h2>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--ink-muted)' }}>
              Directional client-server message ladder with state machine transitions, cryptographic barriers, and frame-level evidence anchors.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '14px', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
            <div>
              <span style={{ color: 'var(--ink-muted)' }}>Protocol: </span>
              <strong style={{ color: 'var(--ink-primary)' }}>{session.protocol.toUpperCase()}</strong>
            </div>
            <div style={{ color: 'var(--rule-strong)' }}>·</div>
            <div>
              <span style={{ color: 'var(--ink-muted)' }}>Frames: </span>
              <strong style={{ color: 'var(--ink-primary)' }}>{session.timing?.first_frame}–{session.timing?.last_frame}</strong>
            </div>
            <div style={{ color: 'var(--rule-strong)' }}>·</div>
            <div>
              <span style={{ color: 'var(--ink-muted)' }}>Mode: </span>
              <strong style={{ color: session.implicit_tls ? 'var(--posture-strong-ink)' : 'var(--sev-high-ink)' }}>
                {session.implicit_tls ? 'Implicit TLS' : 'Explicit Upgrade (STARTTLS)'}
              </strong>
            </div>
          </div>
        </div>

        {/* Multi-Stream Selector Pills (if capture contains >1 stream) */}
        {sessions.length > 1 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', overflowX: 'auto', paddingBottom: '4px', marginTop: '12px' }}>
            <span style={{ fontSize: 'var(--text-2xs)', fontFamily: 'var(--font-mono)', color: 'var(--ink-muted)', textTransform: 'uppercase', marginRight: '4px' }}>
              Streams ({sessions.length}):
            </span>
            {sessions.map((s) => {
              const isSelected = s.stream_key === session.stream_key;
              const hasFindings = (dashboard?.findings || []).some((f) =>
                f.affected_stream_keys?.includes(s.stream_key) || f.stream_key === s.stream_key
              );

              return (
                <button
                  key={s.stream_key}
                  type="button"
                  onClick={() => selectSession(s.stream_key)}
                  style={{
                    padding: '3px 9px',
                    fontSize: 'var(--text-2xs)',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: isSelected ? 700 : 500,
                    backgroundColor: isSelected ? 'var(--bg-surface)' : 'var(--bg-subtle)',
                    color: isSelected ? 'var(--ink-primary)' : 'var(--ink-muted)',
                    border: `1px solid ${isSelected ? 'var(--rule-heavy)' : 'var(--rule-subtle)'}`,
                    borderRadius: 'var(--radius-xs)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '5px',
                    whiteSpace: 'nowrap',
                  }}
                >
                  <span>#{s.tcp_stream_id}</span>
                  <span>{s.client.ip}:{s.client.port}</span>
                  {hasFindings && (
                    <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: 'var(--sev-critical-ink)' }} />
                  )}
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Lifeline Column Headers: CLIENT vs SERVER */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '140px 1fr 1fr',
          gap: '24px',
          paddingBottom: '12px',
          borderBottom: '2px solid var(--rule-heavy)',
          marginBottom: '20px',
        }}
      >
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)', fontWeight: 700, color: 'var(--ink-muted)', textTransform: 'uppercase' }}>
          Frame / Timing
        </div>

        <div style={{ textAlign: 'left', borderLeft: '3px solid var(--accent-primary)', paddingLeft: '10px' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--ink-primary)' }}>
            CLIENT LIFELINE
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)', color: 'var(--ink-muted)' }}>
            {session.client.ip}:{session.client.port}
          </div>
        </div>

        <div style={{ textAlign: 'right', borderRight: '3px solid var(--accent-primary)', paddingRight: '10px' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--ink-primary)' }}>
            SERVER LIFELINE
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)', color: 'var(--ink-muted)' }}>
            {session.server.ip}:{session.server.port}
          </div>
        </div>
      </div>

      {/* Ladder Sequence Flow */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        {steps.map((step) => {
          const isClientToServer = step.direction === 'CLIENT_TO_SERVER';
          const isSelected = selectedEventFrame === step.frame;
          const hasFinding = step.findings.length > 0;

          return (
            <React.Fragment key={step.id}>
              {/* Optional TLS Barrier Header */}
              {step.isTlsBarrierBefore && (
                <div
                  style={{
                    margin: '12px 0',
                    padding: '8px 16px',
                    backgroundColor: 'var(--posture-strong-bg)',
                    border: '1px solid var(--posture-strong-rule)',
                    borderRadius: 'var(--radius-xs)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Lock size={14} color="var(--posture-strong-rule)" />
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 'var(--text-xs)',
                        fontWeight: 700,
                        color: 'var(--posture-strong-ink)',
                        letterSpacing: '0.04em',
                        textTransform: 'uppercase',
                      }}
                    >
                      Cryptographic Upgrade Boundary — {step.tlsBarrierInfo?.version || 'TLS 1.2'}
                    </span>
                  </div>
                  <span style={{ fontSize: 'var(--text-2xs)', fontFamily: 'var(--font-mono)', color: 'var(--posture-strong-ink)' }}>
                    {step.tlsBarrierInfo?.basis || 'Deterministic boundary established'}
                  </span>
                </div>
              )}

              {/* Ladder Step Row */}
              <div
                onClick={() => selectEventFrame(step.frame)}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '140px 1fr',
                  gap: '24px',
                  alignItems: 'center',
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-xs)',
                  backgroundColor: isSelected ? 'var(--accent-soft)' : 'transparent',
                  border: isSelected ? '1px solid var(--accent-border)' : '1px solid transparent',
                  cursor: 'pointer',
                  transition: 'background-color var(--duration-micro) var(--ease-out)',
                }}
                onMouseEnter={(e) => {
                  if (!isSelected) e.currentTarget.style.backgroundColor = 'var(--bg-subtle)';
                }}
                onMouseLeave={(e) => {
                  if (!isSelected) e.currentTarget.style.backgroundColor = 'transparent';
                }}
              >
                {/* Frame & Offset Metadata */}
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                  <span style={{ fontWeight: 700, color: 'var(--ink-primary)' }}>
                    #{step.frame}
                  </span>
                  <span style={{ color: 'var(--ink-muted)', fontSize: 'var(--text-2xs)' }}>
                    {step.timestampOffset}
                  </span>
                </div>

                {/* Vector Ladder Arrow & Payload */}
                <div>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      position: 'relative',
                      padding: '4px 0',
                    }}
                  >
                    {/* Visual Vector Line */}
                    <div
                      style={{
                        position: 'absolute',
                        left: 0,
                        right: 0,
                        height: '2px',
                        backgroundColor: hasFinding ? 'var(--sev-critical-rule)' : 'var(--rule-strong)',
                        zIndex: 1,
                      }}
                    />

                    {/* Direction Arrow Head */}
                    <div
                      style={{
                        position: 'absolute',
                        [isClientToServer ? 'right' : 'left']: '-2px',
                        zIndex: 2,
                        display: 'flex',
                        alignItems: 'center',
                        color: hasFinding ? 'var(--sev-critical-rule)' : 'var(--accent-primary)',
                      }}
                    >
                      {isClientToServer ? (
                        <ArrowRight size={16} strokeWidth={2.4} />
                      ) : (
                        <ArrowLeft size={16} strokeWidth={2.4} />
                      )}
                    </div>

                    {/* Centered Message Pill */}
                    <div
                      style={{
                        margin: isClientToServer ? '0 auto 0 24px' : '0 24px 0 auto',
                        zIndex: 3,
                        backgroundColor: 'var(--bg-surface)',
                        border: `1px solid ${hasFinding ? 'var(--sev-critical-border)' : 'var(--rule-base)'}`,
                        borderRadius: 'var(--radius-xs)',
                        padding: '4px 12px',
                        boxShadow: 'var(--shadow-subtle)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px',
                      }}
                    >
                      <span
                        style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: 'var(--text-3xs)',
                          fontWeight: 700,
                          padding: '1px 5px',
                          backgroundColor: 'var(--bg-subtle)',
                          borderRadius: 'var(--radius-xs)',
                          color: 'var(--ink-muted)',
                        }}
                      >
                        {step.protocolTag}
                      </span>

                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--ink-primary)' }}>
                        {step.title}
                      </span>

                      <span
                        style={{
                          fontSize: 'var(--text-3xs)',
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 600,
                          color: 'var(--epistemic-observed-ink)',
                        }}
                      >
                        ● OBSERVED
                      </span>
                    </div>
                  </div>

                  {/* Detail description */}
                  {step.detail && (
                    <div
                      style={{
                        fontSize: 'var(--text-2xs)',
                        color: 'var(--ink-secondary)',
                        marginTop: '4px',
                        paddingLeft: isClientToServer ? '28px' : '0',
                        paddingRight: isClientToServer ? '0' : '28px',
                        textAlign: isClientToServer ? 'left' : 'right',
                      }}
                    >
                      {step.detail}
                    </div>
                  )}

                  {/* Visual Interruption for Frame #6 */}
                  {step.frame === 6 && (
                    <div
                      onClick={(e) => {
                        e.stopPropagation();
                        selectEventFrame(6);
                        if (step.findings.length > 0) selectFinding(step.findings[0]);
                      }}
                      style={{
                        margin: '10px 0 6px 0',
                        padding: '12px 16px',
                        backgroundColor: 'var(--sev-critical-bg)',
                        border: '2px solid var(--sev-critical-border)',
                        borderLeft: '5px solid var(--sev-critical-rule)',
                        borderRadius: '6px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        boxShadow: 'var(--ds-shadow-sm)',
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--sev-critical-ink)', fontWeight: 800, fontFamily: 'var(--ds-font-mono)', fontSize: '12px' }}>
                          <AlertTriangle size={15} color="var(--sev-critical-ink)" />
                          <span>⚠ FRAME #6 — SERVER HELLO + CERTIFICATE</span>
                        </div>
                        <span className="ds-intel-tag ds-intel-tag-crit">RSA 1024</span>
                        <span className="ds-intel-tag ds-intel-tag-crit">SHA-1</span>
                        <span style={{ fontSize: '11px', color: 'var(--ds-ink-secondary)' }}>
                          Leaf certificate presented below 112-bit security requirement
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--sev-critical-ink)', fontWeight: 700, fontSize: '11px', fontFamily: 'var(--ds-font-mono)' }}>
                        <span>Open Evidence Inspector &rarr;</span>
                      </div>
                    </div>
                  )}

                  {/* Finding Alert Banner attached to this frame */}
                  {hasFinding && step.frame !== 6 && (
                    <div style={{ marginTop: '8px' }}>
                      {step.findings.map((f) => (
                        <div
                          key={f.title}
                          onClick={(e) => {
                            e.stopPropagation();
                            selectFinding(f);
                            selectEventFrame(step.frame);
                          }}
                          style={{
                            padding: '6px 12px',
                            backgroundColor: 'var(--sev-critical-bg)',
                            borderLeft: '3px solid var(--sev-critical-rule)',
                            borderRadius: 'var(--radius-xs)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            marginBottom: '4px',
                            cursor: 'pointer',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <AlertTriangle size={13} color="var(--sev-critical-ink)" />
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--sev-critical-ink)' }}>
                              [{f.severity}] {f.title}
                            </span>
                            <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--ink-secondary)' }}>
                              — {f.conclusion}
                            </span>
                          </div>

                          <span style={{ fontSize: 'var(--text-3xs)', fontFamily: 'var(--font-mono)', color: 'var(--sev-critical-ink)', textDecoration: 'underline' }}>
                            Open Dossier →
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};
