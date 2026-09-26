import React, { useState } from 'react';
import { FIXTURES, FIXTURE_METADATA, type FixtureKey } from '../fixtures';
import { Activity, Terminal, ArrowUpRight, Search, Cpu, Radio } from 'lucide-react';
import './DirectionA.css';

interface DirectionA_CaseDeskProps {
  onOpenCase: (fixtureKey: FixtureKey) => void;
}

export const DirectionA_CaseDesk: React.FC<DirectionA_CaseDeskProps> = ({ onOpenCase }) => {
  const [filterQuery, setFilterQuery] = useState('');

  const cases: FixtureKey[] = [
    'backup_weak_certificate',
    'scene_b_certificate_honesty',
    'deepdive_cross_session_control_endpoint',
  ];

  return (
    <div className="dir-a-theme">
      {/* Tactical Sub-Header / Telemetry */}
      <header className="da-header">
        <div className="da-header-brand">
          <Terminal size={18} color="var(--da-cyan)" />
          <span>INVESTIGATION COMMAND DESK // ACTIVE MISSIONS</span>
          <span style={{ fontSize: '11px', color: 'var(--da-text-muted)', fontFamily: 'var(--da-font-mono)' }}>
            [ENGINE v0.8.0-DAMPED]
          </span>
        </div>

        <div className="da-header-telemetry">
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span className="da-status-dot" />
            <span>SENSOR ACTIVE</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Radio size={12} color="var(--da-cyan)" />
            <span>INGEST: 100% PASSIVE</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Cpu size={12} color="var(--da-amber)" />
            <span>RULES: 12 LOADED</span>
          </div>
        </div>
      </header>

      {/* Main Console Workspace */}
      <main style={{ padding: '24px', flex: 1, maxWidth: '1600px', margin: '0 auto', width: '100%' }}>
        {/* Triage Mission Radar Header */}
        <div style={{ marginBottom: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
          <div>
            <div style={{ fontSize: '11px', color: 'var(--da-cyan)', fontFamily: 'var(--da-font-mono)', fontWeight: 700, letterSpacing: '0.1em' }}>
              OPERATIONAL PCAP TRIAGE RADAR
            </div>
            <h1 style={{ fontSize: '24px', fontWeight: 800, color: 'var(--da-text-bright)', marginTop: '4px' }}>
              Network Capture Forensics Workstation
            </h1>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '6px 12px',
                borderRadius: '6px',
                backgroundColor: 'var(--da-bg-card)',
                border: '1px solid var(--da-border-subtle)',
                fontSize: '12px',
                fontFamily: 'var(--da-font-mono)',
              }}
            >
              <Search size={14} color="var(--da-text-muted)" />
              <input
                type="text"
                placeholder="Filter by hash, stream, protocol..."
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
                style={{ background: 'transparent', border: 'none', outline: 'none', color: '#fff', width: '220px', fontSize: '11px' }}
              />
            </div>
          </div>
        </div>

        {/* Hero Case Cards */}
        <div className="da-hero-grid">
          {cases.map((key) => {
            const data = FIXTURES[key];
            const meta = FIXTURE_METADATA[key];
            const isCritical = meta.verdict === 'CRITICAL';

            return (
              <div
                key={key}
                className={`da-case-card ${key === 'backup_weak_certificate' ? 'active-case' : ''}`}
                onClick={() => onOpenCase(key)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <span className={isCritical ? 'da-badge-critical' : 'da-badge-strong'}>
                    {meta.verdict} // {meta.score.toFixed(1)}
                  </span>
                  <span style={{ fontSize: '11px', fontFamily: 'var(--da-font-mono)', color: 'var(--da-text-muted)' }}>
                    {data.run.duration_ms}ms
                  </span>
                </div>

                <div>
                  <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--da-text-bright)', marginBottom: '4px' }}>
                    {meta.label}
                  </h3>
                  <div style={{ fontSize: '11px', fontFamily: 'var(--da-font-mono)', color: 'var(--da-cyan)' }}>
                    {meta.pcap}
                  </div>
                  <p style={{ fontSize: '12px', color: 'var(--da-text-secondary)', marginTop: '8px', lineHeight: 1.4 }}>
                    {meta.headline}
                  </p>
                </div>

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(3, 1fr)',
                    gap: '8px',
                    padding: '10px',
                    borderRadius: '6px',
                    backgroundColor: 'rgba(0, 0, 0, 0.3)',
                    border: '1px solid var(--da-border-subtle)',
                    fontFamily: 'var(--da-font-mono)',
                    fontSize: '11px',
                  }}
                >
                  <div>
                    <div style={{ color: 'var(--da-text-muted)', fontSize: '9px' }}>SESSIONS</div>
                    <div style={{ fontWeight: 700, color: 'var(--da-text-bright)' }}>{data.sessions.total}</div>
                  </div>
                  <div>
                    <div style={{ color: 'var(--da-text-muted)', fontSize: '9px' }}>FINDINGS</div>
                    <div style={{ fontWeight: 700, color: isCritical ? 'var(--da-crimson)' : 'var(--da-emerald)' }}>
                      {meta.findingsCount}
                    </div>
                  </div>
                  <div>
                    <div style={{ color: 'var(--da-text-muted)', fontSize: '9px' }}>PROTO</div>
                    <div style={{ fontWeight: 700, color: 'var(--da-text-bright)' }}>
                      {data.dashboard?.protocols?.[0]?.protocol?.toUpperCase() || 'SMTP'}
                    </div>
                  </div>
                </div>

                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    paddingTop: '8px',
                    borderTop: '1px solid var(--da-border-subtle)',
                    fontSize: '11px',
                    fontWeight: 600,
                    color: 'var(--da-cyan)',
                  }}
                >
                  <span>LAUNCH INVESTIGATION WORKBENCH</span>
                  <ArrowUpRight size={14} />
                </div>
              </div>
            );
          })}
        </div>

        {/* Detailed Stream Analysis Telemetry Matrix */}
        <div
          style={{
            backgroundColor: 'var(--da-bg-card)',
            border: '1px solid var(--da-border-subtle)',
            borderRadius: '8px',
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              padding: '14px 20px',
              borderBottom: '1px solid var(--da-border-subtle)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              backgroundColor: 'rgba(0,0,0,0.2)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Activity size={16} color="var(--da-cyan)" />
              <span style={{ fontSize: '13px', fontWeight: 700, letterSpacing: '0.04em' }}>
                LIVE CAPTURE STREAMS TELEMETRY TABLE
              </span>
            </div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--da-font-mono)', color: 'var(--da-text-muted)' }}>
              14 STREAMS RECORDED // PASSIVE NON-INTERFERENCE
            </span>
          </div>

          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--da-border-subtle)', color: 'var(--da-text-muted)', fontFamily: 'var(--da-font-mono)', fontSize: '10px' }}>
                <th style={{ padding: '10px 20px' }}>STREAM KEY</th>
                <th style={{ padding: '10px 16px' }}>CLIENT ENDPOINT</th>
                <th style={{ padding: '10px 16px' }}>SERVER ENDPOINT</th>
                <th style={{ padding: '10px 16px' }}>PROTOCOL</th>
                <th style={{ padding: '10px 16px' }}>CRYPTOGRAPHIC STATE</th>
                <th style={{ padding: '10px 16px' }}>EPISTEMIC STATE</th>
                <th style={{ padding: '10px 20px', textAlign: 'right' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              <tr
                style={{ borderBottom: '1px solid var(--da-border-subtle)', cursor: 'pointer', backgroundColor: 'rgba(244, 63, 94, 0.04)' }}
                onClick={() => onOpenCase('backup_weak_certificate')}
              >
                <td style={{ padding: '12px 20px', fontFamily: 'var(--da-font-mono)', color: 'var(--da-cyan)' }}>
                  ce5377...501:0
                </td>
                <td style={{ padding: '12px 16px', fontFamily: 'var(--da-font-mono)' }}>127.0.0.1:36568</td>
                <td style={{ padding: '12px 16px', fontFamily: 'var(--da-font-mono)' }}>127.0.0.1:465</td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{ padding: '2px 6px', borderRadius: '4px', backgroundColor: '#1e293b', fontSize: '10px', fontWeight: 700 }}>
                    SMTP
                  </span>
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{ color: 'var(--da-crimson)', fontWeight: 600 }}>
                    RSA 1024-bit / SHA-1 (CRITICAL)
                  </span>
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{ padding: '2px 6px', borderRadius: '4px', backgroundColor: 'rgba(16, 185, 129, 0.15)', color: 'var(--da-emerald)', fontSize: '10px', fontWeight: 700 }}>
                    OBSERVED
                  </span>
                </td>
                <td style={{ padding: '12px 20px', textAlign: 'right' }}>
                  <button
                    style={{
                      padding: '4px 10px',
                      borderRadius: '4px',
                      backgroundColor: 'rgba(56, 189, 248, 0.15)',
                      color: 'var(--da-cyan)',
                      fontSize: '11px',
                      fontWeight: 600,
                      border: '1px solid rgba(56, 189, 248, 0.3)',
                    }}
                  >
                    INSPECT STREAM →
                  </button>
                </td>
              </tr>

              <tr
                style={{ borderBottom: '1px solid var(--da-border-subtle)', cursor: 'pointer' }}
                onClick={() => onOpenCase('scene_b_certificate_honesty')}
              >
                <td style={{ padding: '12px 20px', fontFamily: 'var(--da-font-mono)', color: 'var(--da-cyan)' }}>
                  d257ec...f65:0
                </td>
                <td style={{ padding: '12px 16px', fontFamily: 'var(--da-font-mono)' }}>127.0.0.1:48202</td>
                <td style={{ padding: '12px 16px', fontFamily: 'var(--da-font-mono)' }}>127.0.0.1:993</td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{ padding: '2px 6px', borderRadius: '4px', backgroundColor: '#1e293b', fontSize: '10px', fontWeight: 700 }}>
                    IMAP
                  </span>
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{ color: 'var(--da-emerald)', fontWeight: 600 }}>
                    TLS 1.3 (Encrypted Handshake)
                  </span>
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{ padding: '2px 6px', borderRadius: '4px', backgroundColor: 'rgba(100, 116, 139, 0.2)', color: 'var(--da-text-secondary)', fontSize: '10px', fontWeight: 700 }}>
                    NOT_OBSERVABLE (HONEST)
                  </span>
                </td>
                <td style={{ padding: '12px 20px', textAlign: 'right' }}>
                  <button
                    style={{
                      padding: '4px 10px',
                      borderRadius: '4px',
                      backgroundColor: 'rgba(56, 189, 248, 0.15)',
                      color: 'var(--da-cyan)',
                      fontSize: '11px',
                      fontWeight: 600,
                      border: '1px solid rgba(56, 189, 248, 0.3)',
                    }}
                  >
                    INSPECT STREAM →
                  </button>
                </td>
              </tr>

              <tr
                style={{ cursor: 'pointer', backgroundColor: 'rgba(244, 63, 94, 0.04)' }}
                onClick={() => onOpenCase('deepdive_cross_session_control_endpoint')}
              >
                <td style={{ padding: '12px 20px', fontFamily: 'var(--da-font-mono)', color: 'var(--da-cyan)' }}>
                  97b2b6...e83:5
                </td>
                <td style={{ padding: '12px 16px', fontFamily: 'var(--da-font-mono)' }}>10.0.0.6:40046</td>
                <td style={{ padding: '12px 16px', fontFamily: 'var(--da-font-mono)' }}>10.0.0.80:587</td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{ padding: '2px 6px', borderRadius: '4px', backgroundColor: '#1e293b', fontSize: '10px', fontWeight: 700 }}>
                    SMTP
                  </span>
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{ color: 'var(--da-crimson)', fontWeight: 600 }}>
                    STARTTLS Inversion vs Control Endpoint
                  </span>
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{ padding: '2px 6px', borderRadius: '4px', backgroundColor: 'rgba(244, 63, 94, 0.15)', color: 'var(--da-crimson)', fontSize: '10px', fontWeight: 700 }}>
                    SUSPICIOUS_DEVIATION
                  </span>
                </td>
                <td style={{ padding: '12px 20px', textAlign: 'right' }}>
                  <button
                    style={{
                      padding: '4px 10px',
                      borderRadius: '4px',
                      backgroundColor: 'rgba(56, 189, 248, 0.15)',
                      color: 'var(--da-cyan)',
                      fontSize: '11px',
                      fontWeight: 600,
                      border: '1px solid rgba(56, 189, 248, 0.3)',
                    }}
                  >
                    INSPECT STREAM →
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
