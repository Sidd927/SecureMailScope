import React from 'react';
import { FIXTURES, FIXTURE_METADATA, type FixtureKey } from '../fixtures';
import { ArrowRight } from 'lucide-react';
import './DirectionB.css';

interface DirectionB_CaseDeskProps {
  onOpenCase: (fixtureKey: FixtureKey) => void;
}

export const DirectionB_CaseDesk: React.FC<DirectionB_CaseDeskProps> = ({ onOpenCase }) => {
  const cases: FixtureKey[] = [
    'backup_weak_certificate',
    'scene_b_certificate_honesty',
    'deepdive_cross_session_control_endpoint',
  ];

  return (
    <div className="dir-b-theme">
      {/* Formal Editorial Masthead */}
      <header className="db-masthead">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div className="db-masthead-title">SECUREMAILSCOPE / FORENSIC INVESTIGATION REGISTRY</div>
            <div className="db-masthead-meta">
              OFFICIAL DOCKET ARCHIVE &bull; CRYPTOGRAPHIC INTEGRITY AUDIT &bull; VOL. XXIV
            </div>
          </div>
          <div style={{ textAlign: 'right', fontFamily: 'var(--db-font-mono)', fontSize: '11px', color: 'var(--db-ink-muted)' }}>
            <div>REGISTRY REVISION: 2026.09.25</div>
            <div>STATUS: DETERMINISTIC CITATIONS</div>
          </div>
        </div>
      </header>

      {/* Main Editorial Docket Body */}
      <main style={{ maxWidth: '1120px', margin: '40px auto', padding: '0 32px', width: '100%' }}>
        {/* Featured Case Exhibit */}
        <div
          className="db-docket-card"
          onClick={() => onOpenCase('backup_weak_certificate')}
          style={{ marginBottom: '40px', borderTop: '4px solid var(--db-crimson)' }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
            <div style={{ fontFamily: 'var(--db-font-mono)', fontSize: '12px', color: 'var(--db-ink-muted)', letterSpacing: '0.08em' }}>
              DOCKET NO. 2026-SMS-044 &bull; SMTPS TRANSPORT TRAFFIC
            </div>
            <div className="db-stamp-critical">VERDICT: CRITICAL &bull; 44.0 / 100</div>
          </div>

          <h2 className="db-serif" style={{ fontSize: '28px', color: 'var(--db-ink-black)', lineHeight: 1.25, marginBottom: '12px' }}>
            In re backup_weak_certificate.pcap: Critical Cryptographic Compromise in Flight
          </h2>

          <p style={{ fontSize: '15px', lineHeight: 1.6, color: 'var(--db-ink-body)', maxWidth: '840px', marginBottom: '24px' }}>
            A forensic analysis of passive network capture <code className="db-mono" style={{ fontSize: '13px' }}>ce5377...501</code> confirms
            that the mail server presented an X.509 leaf certificate featuring a <strong>1024-bit RSA public key modulus</strong> (violating NIST SP 800-57 §5.6.1)
            and a deprecated <strong>SHA-1 signature algorithm</strong> (prohibited under RFC 9155 and NIST SP 800-131A Rev. 2).
            The assessment deducted a total of 56.0 penalty points across two confirmed infractions.
          </p>

          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              borderTop: '1px solid var(--db-border-hairline)',
              paddingTop: '16px',
              fontSize: '12px',
              fontFamily: 'var(--db-font-mono)',
            }}
          >
            <div style={{ display: 'flex', gap: '24px', color: 'var(--db-ink-muted)' }}>
              <span>AFFECTED: STREAM #0 (PORT 465)</span>
              <span>STANDARDS CITED: NIST SP 800-57, RFC 9155</span>
              <span>PROVENANCE: CONFIRMED FRAME #6</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--db-crimson)', fontWeight: 700 }}>
              <span>READ FORENSIC REPORT</span>
              <ArrowRight size={14} />
            </div>
          </div>
        </div>

        {/* Section Heading */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', borderBottom: '1px solid var(--db-border-strong)', paddingBottom: '8px', marginBottom: '20px' }}>
          <h3 className="db-serif" style={{ fontSize: '20px', fontWeight: 700, color: 'var(--db-ink-black)' }}>
            Complete Case Filings Ledger
          </h3>
          <span className="db-mono" style={{ fontSize: '11px', color: 'var(--db-ink-muted)' }}>
            3 VERIFIED DOCKETS
          </span>
        </div>

        {/* Docket Ledger Table */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {cases.map((key) => {
            const data = FIXTURES[key];
            const meta = FIXTURE_METADATA[key];
            const isCrit = meta.verdict === 'CRITICAL';

            return (
              <div
                key={key}
                className="db-docket-card"
                onClick={() => onOpenCase(key)}
                style={{ padding: '24px 32px' }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <span className={isCrit ? 'db-stamp-critical' : 'db-stamp-strong'} style={{ fontSize: '10px', padding: '2px 8px' }}>
                        {meta.verdict} &bull; {meta.score.toFixed(1)}
                      </span>
                      <span className="db-mono" style={{ fontSize: '12px', fontWeight: 700, color: 'var(--db-ink-black)' }}>
                        {meta.pcap}
                      </span>
                    </div>
                    <div style={{ fontSize: '14px', color: 'var(--db-ink-body)', marginTop: '4px' }}>
                      {meta.headline}
                    </div>
                    <div className="db-mono" style={{ fontSize: '11px', color: 'var(--db-ink-muted)', marginTop: '2px' }}>
                      {meta.tagline}
                    </div>
                  </div>

                  <div style={{ textAlign: 'right', fontFamily: 'var(--db-font-mono)', fontSize: '11px' }}>
                    <div style={{ color: 'var(--db-ink-muted)' }}>{data.sessions.total} SESSION(S)</div>
                    <div style={{ color: isCrit ? 'var(--db-crimson)' : 'var(--db-emerald)', fontWeight: 700, marginTop: '4px' }}>
                      EXAMINE DOSSIER &rarr;
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </main>
    </div>
  );
};
