import React, { useState } from 'react';
import { FIXTURES, FIXTURE_METADATA, type FixtureKey } from '../fixtures';
import { ShieldCheck, ShieldAlert, ArrowUpRight, Search, Activity, Network } from 'lucide-react';
import './DirectionS.css';

interface DirectionS_CaseDeskProps {
  onOpenCase: (fixtureKey: FixtureKey) => void;
}

export const DirectionS_CaseDesk: React.FC<DirectionS_CaseDeskProps> = ({ onOpenCase }) => {
  const [searchQuery, setSearchQuery] = useState('');

  const cases: FixtureKey[] = [
    'backup_weak_certificate',
    'scene_b_certificate_honesty',
    'deepdive_cross_session_control_endpoint',
  ];

  return (
    <div className="dir-s-theme">
      {/* Station Shell Header */}
      <header className="ds-header">
        <div className="ds-brand">
          <Network size={20} color="var(--ds-indigo)" />
          <span style={{ fontSize: '15px', fontWeight: 800 }}>SECUREMAILSCOPE</span>
          <span style={{ color: 'var(--ds-ink-muted)', fontWeight: 400, fontSize: '13px' }}>/</span>
          <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--ds-ink-secondary)' }}>
            Cryptographic Posture &amp; Network Forensic Investigation
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="ds-telemetry-badge">
            <span style={{ width: '7px', height: '7px', borderRadius: '50%', backgroundColor: 'var(--ds-emerald)' }} />
            <span>PASSIVE CAPTURE INGEST</span>
          </div>

          <div className="ds-telemetry-badge">
            <span style={{ color: 'var(--ds-indigo)', fontWeight: 700 }}>ENGINE:</span>
            <span>v0.8.0-DAMPED</span>
          </div>

          <div className="ds-telemetry-badge">
            <span style={{ color: 'var(--ds-ink-muted)' }}>STANDARDS:</span>
            <span>NIST + IETF RFC</span>
          </div>
        </div>
      </header>

      {/* Main Workspace Body */}
      <main style={{ padding: '32px 36px', maxWidth: '1680px', margin: '0 auto', width: '100%', flex: 1 }}>
        {/* Workspace Title & Search Controls */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '24px' }}>
          <div>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--ds-indigo)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '4px', fontFamily: 'var(--ds-font-mono)' }}>
              INVESTIGATION WORKSTATION // ACTIVE CASES
            </div>
            <h1 style={{ fontSize: '24px', fontWeight: 800, color: 'var(--ds-ink-primary)', letterSpacing: '-0.02em' }}>
              Cryptographic Integrity &amp; Protocol Forensic Desk
            </h1>
          </div>

          <div style={{ display: 'flex', gap: '12px' }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 14px',
                borderRadius: '8px',
                backgroundColor: 'var(--ds-bg-canvas)',
                border: '1px solid var(--ds-border-light)',
                boxShadow: '0 1px 2px rgba(0,0,0,0.03)',
                width: '320px',
              }}
            >
              <Search size={15} color="var(--ds-ink-muted)" />
              <input
                type="text"
                placeholder="Search captures, stream keys, certificates..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  outline: 'none',
                  fontSize: '12px',
                  color: 'var(--ds-ink-primary)',
                  width: '100%',
                }}
              />
            </div>
          </div>
        </div>

        {/* Hero Case Triage Deck */}
        <div className="ds-case-grid">
          {cases.map((key) => {
            const data = FIXTURES[key];
            const meta = FIXTURE_METADATA[key];
            const isCrit = meta.verdict === 'CRITICAL';

            return (
              <div
                key={key}
                className={`ds-case-tile ${key === 'backup_weak_certificate' ? 'selected' : ''}`}
                onClick={() => onOpenCase(key)}
              >
                {/* Header Strip */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className={isCrit ? 'ds-badge-critical' : 'ds-badge-strong'}>
                    {isCrit ? <ShieldAlert size={12} /> : <ShieldCheck size={12} />}
                    <span>{meta.verdict}</span>
                    <span style={{ opacity: 0.6 }}>//</span>
                    <span>{meta.score.toFixed(1)}</span>
                  </span>

                  <span className="ds-mono" style={{ fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
                    {data.run.duration_ms}ms runtime
                  </span>
                </div>

                {/* Case Title & PCAP */}
                <div>
                  <h3 style={{ fontSize: '17px', fontWeight: 700, color: 'var(--ds-ink-primary)', marginBottom: '4px', letterSpacing: '-0.01em' }}>
                    {meta.label}
                  </h3>
                  <div className="ds-mono" style={{ fontSize: '12px', color: 'var(--ds-indigo)', fontWeight: 500 }}>
                    {meta.pcap}
                  </div>
                  <p style={{ fontSize: '13px', color: 'var(--ds-ink-secondary)', marginTop: '8px', lineHeight: 1.5 }}>
                    {meta.headline}
                  </p>
                </div>

                {/* Threat Indicator / Epistemic Tags */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {key === 'backup_weak_certificate' && (
                    <>
                      <span className="ds-intel-tag ds-intel-tag-crit">DEFECT: RSA-1024</span>
                      <span className="ds-intel-tag ds-intel-tag-crit">DEFECT: SHA-1 SIG</span>
                      <span className="ds-intel-tag ds-intel-tag-indigo">PORT 465 (SMTPS)</span>
                      <span className="ds-intel-tag ds-intel-tag-slate">OBSERVED</span>
                    </>
                  )}
                  {key === 'scene_b_certificate_honesty' && (
                    <>
                      <span className="ds-intel-tag ds-intel-tag-indigo">TLS 1.3 ENCRYPTED</span>
                      <span className="ds-intel-tag ds-intel-tag-slate">PORT 993 (IMAPS)</span>
                      <span className="ds-intel-tag ds-intel-tag-slate">NOT_OBSERVABLE (HONEST)</span>
                    </>
                  )}
                  {key === 'deepdive_cross_session_control_endpoint' && (
                    <>
                      <span className="ds-intel-tag ds-intel-tag-crit">STARTTLS INVERSION</span>
                      <span className="ds-intel-tag ds-intel-tag-indigo">CONTROL ENDPOINT DIFF</span>
                      <span className="ds-intel-tag ds-intel-tag-crit">SUSPICIOUS_DEVIATION</span>
                    </>
                  )}
                </div>

                {/* Quantitative Footprint Strip */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(3, 1fr)',
                    gap: '12px',
                    padding: '12px 14px',
                    borderRadius: '8px',
                    backgroundColor: 'var(--ds-bg-subtle)',
                    border: '1px solid var(--ds-border-light)',
                    fontFamily: 'var(--ds-font-mono)',
                    fontSize: '11px',
                  }}
                >
                  <div>
                    <div style={{ color: 'var(--ds-ink-muted)', fontSize: '10px' }}>SESSIONS</div>
                    <div style={{ fontWeight: 700, fontSize: '13px', color: 'var(--ds-ink-primary)' }}>
                      {data.sessions.total}
                    </div>
                  </div>
                  <div>
                    <div style={{ color: 'var(--ds-ink-muted)', fontSize: '10px' }}>FINDINGS</div>
                    <div style={{ fontWeight: 700, fontSize: '13px', color: isCrit ? 'var(--ds-crimson)' : 'var(--ds-emerald)' }}>
                      {meta.findingsCount}
                    </div>
                  </div>
                  <div>
                    <div style={{ color: 'var(--ds-ink-muted)', fontSize: '10px' }}>PROTOCOL</div>
                    <div style={{ fontWeight: 700, fontSize: '13px', color: 'var(--ds-ink-primary)' }}>
                      {data.dashboard?.protocols?.[0]?.protocol?.toUpperCase() || 'SMTP'}
                    </div>
                  </div>
                </div>

                {/* Footer Action */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    paddingTop: '8px',
                    borderTop: '1px solid var(--ds-border-light)',
                    fontSize: '12px',
                    fontWeight: 700,
                    color: 'var(--ds-indigo)',
                  }}
                >
                  <span>OPEN INVESTIGATION WORKBENCH</span>
                  <ArrowUpRight size={15} />
                </div>
              </div>
            );
          })}
        </div>

        {/* Detailed Stream Analysis & Forensic Ledger */}
        <div
          style={{
            backgroundColor: 'var(--ds-bg-canvas)',
            border: '1px solid var(--ds-border-light)',
            borderRadius: '10px',
            overflow: 'hidden',
            boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
          }}
        >
          <div
            style={{
              padding: '16px 24px',
              borderBottom: '1px solid var(--ds-border-light)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              backgroundColor: 'var(--ds-bg-subtle)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Activity size={16} color="var(--ds-indigo)" />
              <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--ds-ink-primary)', letterSpacing: '-0.01em' }}>
                CAPTURED PROTOCOL STREAMS &bull; FORENSIC TRACE LEDGER
              </span>
            </div>
            <span className="ds-mono" style={{ fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
              OFFLINE PASSIVE EXTRACTOR &bull; ZERO PACKET LOSS
            </span>
          </div>

          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
            <thead>
              <tr
                style={{
                  borderBottom: '1px solid var(--ds-border-light)',
                  color: 'var(--ds-ink-muted)',
                  fontFamily: 'var(--ds-font-mono)',
                  fontSize: '11px',
                  backgroundColor: 'var(--ds-bg-canvas)',
                }}
              >
                <th style={{ padding: '12px 24px' }}>STREAM KEY</th>
                <th style={{ padding: '12px 16px' }}>CLIENT HOST</th>
                <th style={{ padding: '12px 16px' }}>SERVER HOST</th>
                <th style={{ padding: '12px 16px' }}>PROTOCOL</th>
                <th style={{ padding: '12px 16px' }}>CRYPTOGRAPHIC STATE</th>
                <th style={{ padding: '12px 16px' }}>EPISTEMIC STATE</th>
                <th style={{ padding: '12px 24px', textAlign: 'right' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              <tr
                style={{
                  borderBottom: '1px solid var(--ds-border-light)',
                  cursor: 'pointer',
                  backgroundColor: 'var(--ds-crimson-soft)',
                }}
                onClick={() => onOpenCase('backup_weak_certificate')}
              >
                <td style={{ padding: '14px 24px', fontFamily: 'var(--ds-font-mono)', fontWeight: 600, color: 'var(--ds-indigo)' }}>
                  ce5377...501:0
                </td>
                <td style={{ padding: '14px 16px', fontFamily: 'var(--ds-font-mono)' }}>127.0.0.1:36568</td>
                <td style={{ padding: '14px 16px', fontFamily: 'var(--ds-font-mono)' }}>127.0.0.1:465</td>
                <td style={{ padding: '14px 16px' }}>
                  <span style={{ padding: '3px 7px', borderRadius: '4px', backgroundColor: 'var(--ds-bg-canvas)', border: '1px solid var(--ds-border-light)', fontSize: '11px', fontWeight: 600 }}>
                    SMTP
                  </span>
                </td>
                <td style={{ padding: '14px 16px' }}>
                  <span style={{ color: 'var(--ds-crimson)', fontWeight: 700 }}>
                    RSA 1024-bit Modulus / SHA-1 Hash (CRITICAL)
                  </span>
                </td>
                <td style={{ padding: '14px 16px' }}>
                  <span className="ds-intel-tag ds-intel-tag-slate" style={{ fontWeight: 700 }}>
                    OBSERVED
                  </span>
                </td>
                <td style={{ padding: '14px 24px', textAlign: 'right' }}>
                  <button
                    style={{
                      padding: '5px 12px',
                      borderRadius: '6px',
                      backgroundColor: 'var(--ds-bg-canvas)',
                      color: 'var(--ds-indigo)',
                      fontSize: '11px',
                      fontWeight: 700,
                      border: '1px solid var(--ds-indigo-border)',
                    }}
                  >
                    INSPECT STREAM &rarr;
                  </button>
                </td>
              </tr>

              <tr
                style={{
                  borderBottom: '1px solid var(--ds-border-light)',
                  cursor: 'pointer',
                }}
                onClick={() => onOpenCase('scene_b_certificate_honesty')}
              >
                <td style={{ padding: '14px 24px', fontFamily: 'var(--ds-font-mono)', fontWeight: 600, color: 'var(--ds-indigo)' }}>
                  d257ec...f65:0
                </td>
                <td style={{ padding: '14px 16px', fontFamily: 'var(--ds-font-mono)' }}>127.0.0.1:48202</td>
                <td style={{ padding: '14px 16px', fontFamily: 'var(--ds-font-mono)' }}>127.0.0.1:993</td>
                <td style={{ padding: '14px 16px' }}>
                  <span style={{ padding: '3px 7px', borderRadius: '4px', backgroundColor: 'var(--ds-bg-subtle)', border: '1px solid var(--ds-border-light)', fontSize: '11px', fontWeight: 600 }}>
                    IMAP
                  </span>
                </td>
                <td style={{ padding: '14px 16px' }}>
                  <span style={{ color: 'var(--ds-emerald)', fontWeight: 700 }}>
                    TLS 1.3 (Encrypted Handshake)
                  </span>
                </td>
                <td style={{ padding: '14px 16px' }}>
                  <span className="ds-intel-tag ds-intel-tag-slate">
                    NOT_OBSERVABLE (HONEST)
                  </span>
                </td>
                <td style={{ padding: '14px 24px', textAlign: 'right' }}>
                  <button
                    style={{
                      padding: '5px 12px',
                      borderRadius: '6px',
                      backgroundColor: 'var(--ds-bg-canvas)',
                      color: 'var(--ds-indigo)',
                      fontSize: '11px',
                      fontWeight: 700,
                      border: '1px solid var(--ds-border-light)',
                    }}
                  >
                    INSPECT STREAM &rarr;
                  </button>
                </td>
              </tr>

              <tr
                style={{
                  cursor: 'pointer',
                  backgroundColor: 'var(--ds-crimson-soft)',
                }}
                onClick={() => onOpenCase('deepdive_cross_session_control_endpoint')}
              >
                <td style={{ padding: '14px 24px', fontFamily: 'var(--ds-font-mono)', fontWeight: 600, color: 'var(--ds-indigo)' }}>
                  97b2b6...e83:5
                </td>
                <td style={{ padding: '14px 16px', fontFamily: 'var(--ds-font-mono)' }}>10.0.0.6:40046</td>
                <td style={{ padding: '14px 16px', fontFamily: 'var(--ds-font-mono)' }}>10.0.0.80:587</td>
                <td style={{ padding: '14px 16px' }}>
                  <span style={{ padding: '3px 7px', borderRadius: '4px', backgroundColor: 'var(--ds-bg-canvas)', border: '1px solid var(--ds-border-light)', fontSize: '11px', fontWeight: 600 }}>
                    SMTP
                  </span>
                </td>
                <td style={{ padding: '14px 16px' }}>
                  <span style={{ color: 'var(--ds-crimson)', fontWeight: 700 }}>
                    STARTTLS Inversion vs Control Endpoint Baseline
                  </span>
                </td>
                <td style={{ padding: '14px 16px' }}>
                  <span className="ds-intel-tag ds-intel-tag-crit">
                    SUSPICIOUS_DEVIATION
                  </span>
                </td>
                <td style={{ padding: '14px 24px', textAlign: 'right' }}>
                  <button
                    style={{
                      padding: '5px 12px',
                      borderRadius: '6px',
                      backgroundColor: 'var(--ds-bg-canvas)',
                      color: 'var(--ds-indigo)',
                      fontSize: '11px',
                      fontWeight: 700,
                      border: '1px solid var(--ds-crimson-border)',
                    }}
                  >
                    INSPECT STREAM &rarr;
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
};
