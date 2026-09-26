import React from 'react';
import { FIXTURES, FIXTURE_METADATA, type FixtureKey } from '../fixtures';
import { ProtocolLadderSvg } from '../shared/ProtocolLadderSvg';
import { CrossSessionMatrix } from '../shared/CrossSessionMatrix';
import { ArrowLeft } from 'lucide-react';
import './DirectionB.css';

interface DirectionB_OverviewProps {
  fixtureKey: FixtureKey;
  onBackToDesk: () => void;
}

export const DirectionB_Overview: React.FC<DirectionB_OverviewProps> = ({
  fixtureKey,
  onBackToDesk,
}) => {
  const data = FIXTURES[fixtureKey];
  const meta = FIXTURE_METADATA[fixtureKey];
  const isCritical = meta.verdict === 'CRITICAL';
  const findings = data.dashboard?.findings || [];

  return (
    <div className="dir-b-theme">
      {/* Editorial Top Navigation */}
      <nav
        style={{
          borderBottom: '1px solid var(--db-border-hairline)',
          backgroundColor: 'var(--db-bg-paper)',
          padding: '14px 48px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          position: 'sticky',
          top: 0,
          zIndex: 100,
        }}
      >
        <button
          onClick={onBackToDesk}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '12px',
            fontFamily: 'var(--db-font-mono)',
            fontWeight: 700,
            color: 'var(--db-ink-black)',
          }}
        >
          <ArrowLeft size={14} />
          <span>&larr; RETURN TO DOCKET REGISTRY</span>
        </button>

        <div className="db-mono" style={{ fontSize: '11px', color: 'var(--db-ink-muted)' }}>
          SECUREMAILSCOPE REPORT REF: {data.run.run_id.slice(0, 16)} &bull; {meta.pcap}
        </div>

        <div className={isCritical ? 'db-stamp-critical' : 'db-stamp-strong'} style={{ fontSize: '11px', padding: '2px 8px' }}>
          {meta.verdict} &bull; {meta.score.toFixed(1)} / 100
        </div>
      </nav>

      {/* Main Long-Form Narrative Dossier */}
      <main className="db-report-container">
        {/* Formal Legal Case Header */}
        <div style={{ borderBottom: '2px solid var(--db-ink-black)', paddingBottom: '24px', marginBottom: '32px' }}>
          <div className="db-mono" style={{ fontSize: '11px', color: 'var(--db-ink-muted)', letterSpacing: '0.1em', marginBottom: '8px' }}>
            CRYPTOGRAPHIC FORENSIC REPORT &bull; ADMISSIBLE TECHNICAL RECORD
          </div>
          <h1 className="db-serif" style={{ fontSize: '36px', fontWeight: 800, color: 'var(--db-ink-black)', lineHeight: 1.15, marginBottom: '16px' }}>
            {isCritical
              ? 'Critical Cryptographic Compromise: Sub-112-bit RSA Modulus & Deprecated Signature in SMTP Transport'
              : 'Cryptographic Security Assessment: Fully Compliant Encrypted IMAP Transport'}
          </h1>
          <div style={{ display: 'flex', gap: '32px', fontFamily: 'var(--db-font-mono)', fontSize: '12px', color: 'var(--db-ink-muted)' }}>
            <div>SUBJECT: {meta.pcap}</div>
            <div>RECORDED FRAMES: 14</div>
            <div>EVALUATED POSTURE: {meta.verdict} ({meta.score.toFixed(1)}/100)</div>
          </div>
        </div>

        {/* Section 1: Executive Forensic Verdict & Deduction Table */}
        <section id="verdict">
          <h2 className="db-section-heading">§ 1. Executive Forensic Verdict</h2>
          <p style={{ fontSize: '16px', lineHeight: 1.7, color: 'var(--db-ink-body)', marginBottom: '20px' }}>
            Upon passive packet inspection of network traffic capture <code>{meta.pcap}</code>, the assessment engine determined
            an overall security posture of <strong>{meta.verdict}</strong> with an aggregate numerical score of <strong>{meta.score.toFixed(1)} out of 100.00</strong>.
            This evaluation is derived from deterministic rules and verified against statutory standards published by NIST and the IETF.
          </p>

          {/* Forensic Deduction Ledger Table */}
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', margin: '20px 0', border: '1px solid var(--db-border-hairline)' }}>
            <thead>
              <tr style={{ backgroundColor: 'var(--db-bg-subtle)', borderBottom: '1px solid var(--db-border-strong)', textAlign: 'left', fontFamily: 'var(--db-font-mono)', fontSize: '11px' }}>
                <th style={{ padding: '10px 14px' }}>EVALUATION COMPONENT</th>
                <th style={{ padding: '10px 14px' }}>STATUTORY STANDARD</th>
                <th style={{ padding: '10px 14px' }}>CERTAINTY</th>
                <th style={{ padding: '10px 14px', textAlign: 'right' }}>SCORE IMPACT</th>
              </tr>
            </thead>
            <tbody>
              <tr style={{ borderBottom: '1px solid var(--db-border-hairline)' }}>
                <td style={{ padding: '12px 14px', fontWeight: 600 }}>Starting Posture Baseline</td>
                <td style={{ padding: '12px 14px', fontFamily: 'var(--db-font-mono)', color: 'var(--db-ink-muted)' }}>F2-group-damped model</td>
                <td style={{ padding: '12px 14px' }}>&mdash;</td>
                <td style={{ padding: '12px 14px', textAlign: 'right', fontFamily: 'var(--db-font-mono)', fontWeight: 700 }}>100.0</td>
              </tr>
              {findings.map((f: any) => (
                <tr key={f.title} style={{ borderBottom: '1px solid var(--db-border-hairline)', backgroundColor: 'var(--db-crimson-bg)' }}>
                  <td style={{ padding: '12px 14px' }}>
                    <div style={{ fontWeight: 700, color: 'var(--db-crimson)' }}>{f.title}</div>
                    <div style={{ fontSize: '12px', color: 'var(--db-ink-body)', marginTop: '2px' }}>{f.conclusion}</div>
                  </td>
                  <td style={{ padding: '12px 14px', fontFamily: 'var(--db-font-mono)', fontSize: '11px' }}>
                    {f.citations?.[0]?.text?.slice(0, 30) || 'NIST SP 800-57'}...
                  </td>
                  <td style={{ padding: '12px 14px', fontFamily: 'var(--db-font-mono)', fontSize: '11px', color: 'var(--db-crimson)', fontWeight: 700 }}>
                    {f.certainty}
                  </td>
                  <td style={{ padding: '12px 14px', textAlign: 'right', fontFamily: 'var(--db-font-mono)', color: 'var(--db-crimson)', fontWeight: 800 }}>
                    −28.0
                  </td>
                </tr>
              ))}
              <tr style={{ backgroundColor: 'var(--db-bg-subtle)', fontWeight: 800 }}>
                <td colSpan={3} style={{ padding: '12px 14px', textAlign: 'right' }}>
                  FINAL ASSESSED POSTURE SCORE:
                </td>
                <td style={{ padding: '12px 14px', textAlign: 'right', fontFamily: 'var(--db-font-mono)', fontSize: '15px', color: isCritical ? 'var(--db-crimson)' : 'var(--db-emerald)' }}>
                  {meta.score.toFixed(1)} / 100
                </td>
              </tr>
            </tbody>
          </table>
        </section>

        {/* Section 2: Forensic Exhibit 01 — Physical Certificate Specimen */}
        <section id="exhibit">
          <h2 className="db-section-heading">§ 2. Forensic Exhibit 01 — X.509 Certificate Specimen</h2>
          <p style={{ fontSize: '15px', lineHeight: 1.6, color: 'var(--db-ink-body)' }}>
            Extracted from Frame #6 of TCP stream <code>0</code> on port 465. The leaf certificate payload presented by the server during the TLS handshake was reconstructed verbatim.
          </p>

          <div className="db-exhibit-box">
            <div className="db-exhibit-label">EXHIBIT NO. A-1 &bull; CRYPTOGRAPHIC SPECIMEN DISSECTION</div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', fontFamily: 'var(--db-font-mono)', fontSize: '12px' }}>
              <div>
                <div style={{ color: 'var(--db-ink-muted)', fontSize: '10px' }}>PUBLIC KEY SPECIFICATION</div>
                <div style={{ fontSize: '14px', fontWeight: 800, color: 'var(--db-crimson)', marginTop: '4px' }}>
                  RSA (1024 BITS) [NON-COMPLIANT]
                </div>
                <div style={{ fontSize: '11px', color: 'var(--db-ink-body)', marginTop: '4px', lineHeight: 1.4 }}>
                  NIST SP 800-57 Part 1 Rev. 5 §5.6.1 mandates a minimum RSA modulus of 2048 bits for any secure data protection.
                </div>
              </div>

              <div>
                <div style={{ color: 'var(--db-ink-muted)', fontSize: '10px' }}>SIGNATURE ALGORITHM</div>
                <div style={{ fontSize: '14px', fontWeight: 800, color: 'var(--db-crimson)', marginTop: '4px' }}>
                  sha1WithRSAEncryption [PROHIBITED]
                </div>
                <div style={{ fontSize: '11px', color: 'var(--db-ink-body)', marginTop: '4px', lineHeight: 1.4 }}>
                  RFC 9155 and NIST SP 800-131A Rev. 2 declare SHA-1 cryptographically broken for digital signatures.
                </div>
              </div>
            </div>

            <div style={{ marginTop: '16px', paddingTop: '16px', borderTop: '1px solid var(--db-border-hairline)', fontFamily: 'var(--db-font-mono)', fontSize: '11px', color: 'var(--db-ink-muted)' }}>
              SERIAL: 76:e5:b2:01:4d:52:8e... &bull; VALIDITY: 2026-09-21 TO 2027-09-21 (ACTIVE) &bull; CIPHER: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            </div>
          </div>
        </section>

        {/* Section 3: Protocol Sequence Ladder Integrated into the Story */}
        <section id="protocol">
          <h2 className="db-section-heading">§ 3. Protocol Sequence Ladder &amp; Frame Trace</h2>
          <p style={{ fontSize: '15px', lineHeight: 1.6, color: 'var(--db-ink-body)', marginBottom: '16px' }}>
            The diagram below delineates the observed exchange between client <code>127.0.0.1:36568</code> and server <code>127.0.0.1:465</code>.
            Frame #6 contains the offending certificate message.
          </p>

          <div style={{ border: '1px solid var(--db-border-hairline)', padding: '20px', backgroundColor: '#faf9f6' }}>
            <ProtocolLadderSvg darkTheme={false} selectedFrame={6} />
          </div>
        </section>

        {/* Cross-Session Comparison if deepdive */}
        {fixtureKey === 'deepdive_cross_session_control_endpoint' && (
          <section id="cross-session" style={{ marginTop: '32px' }}>
            <h2 className="db-section-heading">§ 4. Cross-Session Behavioral Deviation Analysis</h2>
            <CrossSessionMatrix darkTheme={false} />
          </section>
        )}

        {/* Section 5: Epistemic Boundaries & Forensic Limitations */}
        <section id="limitations">
          <h2 className="db-section-heading">§ 5. Epistemic Boundaries &amp; Forensic Limitations</h2>
          <div style={{ backgroundColor: 'var(--db-bg-subtle)', padding: '20px', borderLeft: '4px solid var(--db-ink-black)', fontSize: '13px', lineHeight: 1.6 }}>
            <p style={{ fontWeight: 700, marginBottom: '8px' }}>
              DECLARATION OF TECHNICAL RESTRAINT (PASSIVE CAPTURE BOUNDARIES):
            </p>
            <ul style={{ paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <li>Conclusions describe exclusively what the capture shows, not the unobserved configuration of the server.</li>
              <li>No attacker, intent, or attribution is or can be established from network traffic alone.</li>
              <li>Certificate trust and revocation boundaries cannot be determined without external trust anchors or live OCSP queries, which are outside the offline scope of this analysis.</li>
            </ul>
          </div>
        </section>
      </main>
    </div>
  );
};
