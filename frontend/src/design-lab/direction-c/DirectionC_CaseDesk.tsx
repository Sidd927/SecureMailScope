import React, { useState } from 'react';
import { FIXTURES, FIXTURE_METADATA, type FixtureKey } from '../fixtures';
import { Search, ShieldAlert, Network, ArrowRight, CheckCircle2, SlidersHorizontal } from 'lucide-react';
import './DirectionC.css';

interface DirectionC_CaseDeskProps {
  onOpenCase: (fixtureKey: FixtureKey) => void;
}

export const DirectionC_CaseDesk: React.FC<DirectionC_CaseDeskProps> = ({ onOpenCase }) => {
  const [filterQuery, setFilterQuery] = useState('');
  const [selectedProto, setSelectedProto] = useState<'ALL' | 'SMTP' | 'IMAP'>('ALL');

  const cases: FixtureKey[] = [
    'backup_weak_certificate',
    'scene_b_certificate_honesty',
    'deepdive_cross_session_control_endpoint',
  ];

  return (
    <div className="dir-c-theme">
      {/* Top Threat Intel Header */}
      <header className="dc-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 800, fontSize: '15px', color: 'var(--dc-text-bright)' }}>
            <Network size={20} color="var(--dc-violet)" />
            <span>SECUREMAILSCOPE // THREAT INTEL WORKSPACE</span>
          </div>

          <div className="dc-search-box">
            <Search size={14} color="var(--dc-text-muted)" />
            <input
              type="text"
              placeholder="Search threat entities, SHA-256 hashes, rules... (⌘K)"
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
            />
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '12px', color: 'var(--dc-text-secondary)' }}>
          <span className="dc-mono" style={{ padding: '4px 8px', borderRadius: '4px', backgroundColor: 'var(--dc-bg-surface)', fontSize: '11px' }}>
            PRESS [/] TO FILTER &bull; [J/K] NAVIGATE
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--dc-emerald)' }} />
            <span>TELEMETRY ONLINE</span>
          </div>
        </div>
      </header>

      {/* Main Workspace Container */}
      <main style={{ padding: '24px 32px', maxWidth: '1600px', margin: '0 auto', width: '100%', flex: 1 }}>
        {/* Intelligence Metrics Strip */}
        <div className="dc-metrics-strip">
          <div className="dc-metric-card">
            <span style={{ fontSize: '11px', color: 'var(--dc-text-muted)', fontWeight: 600 }}>CAPTURES INDEXED</span>
            <span style={{ fontSize: '24px', fontWeight: 800, color: 'var(--dc-text-bright)' }}>3 ACTIVE</span>
            <span style={{ fontSize: '11px', color: 'var(--dc-emerald)' }}>100% Deterministic Extraction</span>
          </div>

          <div className="dc-metric-card">
            <span style={{ fontSize: '11px', color: 'var(--dc-text-muted)', fontWeight: 600 }}>HIGH-RISK DEFECTS</span>
            <span style={{ fontSize: '24px', fontWeight: 800, color: 'var(--dc-ruby)' }}>4 CONFIRMED</span>
            <span style={{ fontSize: '11px', color: 'var(--dc-text-secondary)' }}>RSA-1024 / SHA-1 / Cleartext</span>
          </div>

          <div className="dc-metric-card">
            <span style={{ fontSize: '11px', color: 'var(--dc-text-muted)', fontWeight: 600 }}>STANDARDS VIOLATIONS</span>
            <span style={{ fontSize: '24px', fontWeight: 800, color: 'var(--dc-amber)' }}>2 BREACHES</span>
            <span style={{ fontSize: '11px', color: 'var(--dc-text-secondary)' }}>NIST SP 800-57, RFC 9155</span>
          </div>

          <div className="dc-metric-card">
            <span style={{ fontSize: '11px', color: 'var(--dc-text-muted)', fontWeight: 600 }}>BEHAVIORAL INVERSIONS</span>
            <span style={{ fontSize: '24px', fontWeight: 800, color: 'var(--dc-violet)' }}>1 ANOMALY</span>
            <span style={{ fontSize: '11px', color: 'var(--dc-text-secondary)' }}>Cross-session baseline drift</span>
          </div>
        </div>

        {/* Faceted Filter Toolbar */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div style={{ display: 'flex', gap: '8px' }}>
            {(['ALL', 'SMTP', 'IMAP'] as const).map((proto) => (
              <button
                key={proto}
                onClick={() => setSelectedProto(proto)}
                style={{
                  padding: '6px 14px',
                  borderRadius: '6px',
                  backgroundColor: selectedProto === proto ? 'var(--dc-violet)' : 'var(--dc-bg-card)',
                  color: selectedProto === proto ? '#ffffff' : 'var(--dc-text-secondary)',
                  fontSize: '12px',
                  fontWeight: 600,
                  border: `1px solid ${selectedProto === proto ? 'var(--dc-violet)' : 'var(--dc-border-subtle)'}`,
                }}
              >
                {proto} PROTOCOL
              </button>
            ))}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--dc-text-muted)' }}>
            <SlidersHorizontal size={14} />
            <span>SORT: SEVERITY TIER DESCENDING</span>
          </div>
        </div>

        {/* Threat Entity Directory */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {cases.map((key) => {
            const data = FIXTURES[key];
            const meta = FIXTURE_METADATA[key];
            const isCrit = meta.verdict === 'CRITICAL';

            return (
              <div
                key={key}
                className="dc-entity-card"
                onClick={() => onOpenCase(key)}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                  <div
                    style={{
                      width: '44px',
                      height: '44px',
                      borderRadius: '8px',
                      backgroundColor: isCrit ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      border: `1px solid ${isCrit ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`,
                    }}
                  >
                    {isCrit ? <ShieldAlert size={22} color="var(--dc-ruby)" /> : <CheckCircle2 size={22} color="var(--dc-emerald)" />}
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{ fontSize: '15px', fontWeight: 700, color: 'var(--dc-text-bright)' }}>
                        {meta.label}
                      </span>
                      <span className={isCrit ? 'dc-pill dc-pill-ruby' : 'dc-pill dc-pill-emerald'}>
                        {meta.verdict} &bull; {meta.score.toFixed(1)}
                      </span>
                      <span className="dc-mono" style={{ fontSize: '11px', color: 'var(--dc-text-muted)' }}>
                        {meta.pcap}
                      </span>
                    </div>

                    <div style={{ fontSize: '13px', color: 'var(--dc-text-secondary)' }}>
                      {meta.headline}
                    </div>

                    {/* Threat indicator tags */}
                    <div style={{ display: 'flex', gap: '6px', marginTop: '4px' }}>
                      {key === 'backup_weak_certificate' && (
                        <>
                          <span className="dc-pill dc-pill-ruby">TAG: WEAK-RSA-1024</span>
                          <span className="dc-pill dc-pill-ruby">TAG: SHA1-SIGNATURE</span>
                          <span className="dc-pill dc-pill-violet">SMTP:465</span>
                        </>
                      )}
                      {key === 'scene_b_certificate_honesty' && (
                        <>
                          <span className="dc-pill dc-pill-emerald">TLS 1.3 ENCRYPTED</span>
                          <span className="dc-pill dc-pill-violet">IMAP:993</span>
                          <span className="dc-pill" style={{ backgroundColor: '#21262d', color: '#8b949e', border: '1px solid #30363d' }}>
                            HONEST ABSTENTION
                          </span>
                        </>
                      )}
                      {key === 'deepdive_cross_session_control_endpoint' && (
                        <>
                          <span className="dc-pill dc-pill-ruby">STARTTLS-STRIPPED</span>
                          <span className="dc-pill dc-pill-violet">CONTROL-ENDPOINT-DIFF</span>
                          <span className="dc-pill dc-pill-ruby">BEHAVIORAL-DEVIATION</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                  <div style={{ textAlign: 'right', fontFamily: 'var(--dc-font-mono)', fontSize: '11px' }}>
                    <div style={{ color: 'var(--dc-text-muted)' }}>{data.sessions.total} SESSIONS</div>
                    <div style={{ color: 'var(--dc-cyan)', marginTop: '2px' }}>{data.run.duration_ms}ms runtime</div>
                  </div>

                  <button
                    style={{
                      padding: '8px 16px',
                      borderRadius: '6px',
                      backgroundColor: 'var(--dc-bg-surface)',
                      border: '1px solid var(--dc-border-subtle)',
                      color: 'var(--dc-text-bright)',
                      fontSize: '12px',
                      fontWeight: 600,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    <span>ANALYZE</span>
                    <ArrowRight size={14} />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </main>
    </div>
  );
};
