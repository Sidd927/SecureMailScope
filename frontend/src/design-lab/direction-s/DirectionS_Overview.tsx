import React, { useState } from 'react';
import { FIXTURES, FIXTURE_METADATA, type FixtureKey } from '../fixtures';
import { ProtocolLadderSvg } from '../shared/ProtocolLadderSvg';
import { ProvenanceGraphSvg } from '../shared/ProvenanceGraphSvg';
import { CrossSessionMatrix } from '../shared/CrossSessionMatrix';
import { CoverageLanes } from '../shared/CoverageLanes';
import { ArrowLeft, GitBranch, Layers, Key, CheckCircle2, ShieldAlert, ShieldCheck, AlertCircle, HelpCircle } from 'lucide-react';
import './DirectionS.css';

interface DirectionS_OverviewProps {
  fixtureKey: FixtureKey;
  onBackToDesk: () => void;
}

export const DirectionS_Overview: React.FC<DirectionS_OverviewProps> = ({
  fixtureKey,
  onBackToDesk,
}) => {
  const data = FIXTURES[fixtureKey];
  const meta = FIXTURE_METADATA[fixtureKey];
  const [selectedFrame, setSelectedFrame] = useState<number>(6);
  const [selectedFindingIdx, setSelectedFindingIdx] = useState<number>(0);
  const [activeCanvasView, setActiveCanvasView] = useState<'ladder' | 'provenance' | 'coverage' | 'cross_session'>(() => {
    if (typeof window !== 'undefined') {
      const c = new URLSearchParams(window.location.search).get('canvas');
      if (c === 'provenance' || c === 'coverage' || c === 'cross_session' || c === 'ladder') return c;
    }
    return fixtureKey === 'deepdive_cross_session_control_endpoint' ? 'cross_session' : 'ladder';
  });

  const findings = data.dashboard?.findings || [];
  const activeFinding = findings[selectedFindingIdx] || findings[0];
  const isCritical = meta.verdict === 'CRITICAL';

  return (
    <div className="dir-s-theme">
      {/* Persistent Investigation Case Navigation */}
      <header className="ds-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button
            onClick={onBackToDesk}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              color: 'var(--ds-indigo)',
              fontSize: '12px',
              fontFamily: 'var(--ds-font-mono)',
              fontWeight: 700,
              padding: '6px 12px',
              borderRadius: '6px',
              backgroundColor: 'var(--ds-indigo-soft)',
              border: '1px solid var(--ds-indigo-border)',
            }}
          >
            <ArrowLeft size={13} />
            <span>&larr; CASE DESK</span>
          </button>

          <div style={{ height: '18px', width: '1px', backgroundColor: 'var(--ds-border-light)' }} />

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '12px', color: 'var(--ds-ink-muted)' }}>CASE:</span>
            <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--ds-ink-primary)', fontFamily: 'var(--ds-font-mono)' }}>
              {meta.pcap}
            </span>
          </div>

          <span style={{ color: 'var(--ds-ink-faint)' }}>/</span>

          <span className="ds-mono" style={{ fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
            CAPTURE SHA256: {data.run.run_id.slice(0, 16)}...
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className={isCritical ? 'ds-badge-critical' : 'ds-badge-strong'} style={{ fontSize: '12px', padding: '4px 10px' }}>
            {isCritical ? <ShieldAlert size={13} /> : <ShieldCheck size={13} />}
            <span>{meta.verdict}</span>
            <span style={{ opacity: 0.6 }}>//</span>
            <span>{meta.score.toFixed(1)} / 100.0</span>
          </span>

          <span className="ds-mono" style={{ fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
            EVIDENCE: DETERMINISTIC RULES
          </span>
        </div>
      </header>

      {/* 3-Column Ergonomic Investigation Workstation */}
      <div className="ds-investigation-layout">
        {/* Left Column: Verdict Anchor & Finding Stack */}
        <div className="ds-left-pane">
          {/* Monumental Verdict Card */}
          <div className={`ds-verdict-card ${isCritical ? 'critical' : ''}`}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 800,
                  letterSpacing: '0.08em',
                  color: isCritical ? 'var(--ds-crimson)' : 'var(--ds-emerald)',
                  fontFamily: 'var(--ds-font-mono)',
                  textTransform: 'uppercase',
                }}
              >
                OVERALL POSTURE VERDICT
              </span>
              <span className="ds-mono" style={{ fontSize: '10px', color: 'var(--ds-ink-muted)' }}>
                F2-GROUP-DAMPED
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
              <span className="ds-score-num" style={{ color: isCritical ? 'var(--ds-crimson)' : 'var(--ds-emerald)' }}>
                {meta.score.toFixed(1)}
              </span>
              <span style={{ fontSize: '18px', fontWeight: 600, color: 'var(--ds-ink-muted)' }}>/ 100</span>
            </div>

            {/* Clear Human Analytical Verdict Explanation */}
            <div style={{ fontSize: '13px', color: 'var(--ds-ink-secondary)', lineHeight: 1.5 }}>
              {isCritical ? (
                <>
                  <strong style={{ color: 'var(--ds-crimson-ink)' }}>−56.0 penalty points</strong> deducted for confirmed cryptographic defects. Active SMTPS transport utilizes disallowed key lengths and signature hashes.
                </>
              ) : (
                <>
                  <strong style={{ color: 'var(--ds-emerald-ink)' }}>Zero penalty points</strong> deducted. Session exhibits compliant TLS 1.3 encryption with honest epistemic disclosure.
                </>
              )}
            </div>

            {/* Score Waterfall Ledger */}
            <div
              style={{
                marginTop: '6px',
                padding: '12px',
                borderRadius: '8px',
                backgroundColor: 'var(--ds-bg-subtle)',
                border: '1px solid var(--ds-border-light)',
                fontFamily: 'var(--ds-font-mono)',
                fontSize: '11px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--ds-ink-muted)' }}>
                <span>Baseline Starting Score:</span>
                <span style={{ fontWeight: 600 }}>100.0</span>
              </div>
              {fixtureKey === 'backup_weak_certificate' && (
                <>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--ds-crimson)' }}>
                    <span>RSA 1024-bit Modulus:</span>
                    <span style={{ fontWeight: 700 }}>−28.0</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--ds-crimson)' }}>
                    <span>SHA-1 Signature Hash:</span>
                    <span style={{ fontWeight: 700 }}>−28.0</span>
                  </div>
                </>
              )}
              {fixtureKey === 'deepdive_cross_session_control_endpoint' && (
                <>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--ds-crimson)' }}>
                    <span>No TLS Protection:</span>
                    <span style={{ fontWeight: 700 }}>−40.0</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--ds-amber)' }}>
                    <span>STARTTLS Inversion:</span>
                    <span style={{ fontWeight: 700 }}>−37.85</span>
                  </div>
                </>
              )}
              <div style={{ height: '1px', backgroundColor: 'var(--ds-border-light)', margin: '2px 0' }} />
              <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 800, color: isCritical ? 'var(--ds-crimson)' : 'var(--ds-emerald)' }}>
                <span>Evaluated Final Score:</span>
                <span>{meta.score.toFixed(1)}</span>
              </div>
            </div>
          </div>

          {/* Finding Navigation Stack */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)', letterSpacing: '0.05em' }}>
                CONFIRMED FINDINGS ({findings.length})
              </span>
              <span className="ds-mono" style={{ fontSize: '10px', color: 'var(--ds-ink-muted)' }}>
                STANDARDS-BACKED
              </span>
            </div>

            {findings.length === 0 ? (
              <div
                style={{
                  padding: '18px',
                  borderRadius: '8px',
                  backgroundColor: 'var(--ds-bg-canvas)',
                  border: '1px solid var(--ds-border-light)',
                  fontSize: '13px',
                  color: 'var(--ds-emerald)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  boxShadow: '0 1px 2px rgba(0,0,0,0.02)',
                }}
              >
                <CheckCircle2 size={18} />
                <span>No security violations detected. Handshake compliant.</span>
              </div>
            ) : (
              findings.map((f: any, idx: number) => {
                const isSelected = selectedFindingIdx === idx;
                return (
                  <div
                    key={f.title + idx}
                    onClick={() => {
                      setSelectedFindingIdx(idx);
                      if (f.frames?.[0]) setSelectedFrame(f.frames[0]);
                    }}
                    style={{
                      padding: '14px 16px',
                      borderRadius: '8px',
                      backgroundColor: isSelected ? 'var(--ds-bg-canvas)' : 'var(--ds-bg-canvas)',
                      border: `1px solid ${isSelected ? 'var(--ds-crimson)' : 'var(--ds-border-light)'}`,
                      boxShadow: isSelected
                        ? '0 0 0 1px var(--ds-crimson), 0 4px 12px rgba(220, 38, 38, 0.08)'
                        : '0 1px 2px rgba(0,0,0,0.02)',
                      cursor: 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className="ds-intel-tag ds-intel-tag-crit">
                        {f.severity} // {f.source_rule_ids?.[0] || 'RULE'}
                      </span>
                      <span className="ds-mono" style={{ fontSize: '11px', color: 'var(--ds-indigo)', fontWeight: 600 }}>
                        Frame #{f.frames?.[0] || 6}
                      </span>
                    </div>

                    <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--ds-ink-primary)', letterSpacing: '-0.01em' }}>
                      {f.title}
                    </div>

                    <div style={{ fontSize: '12px', color: 'var(--ds-ink-secondary)', lineHeight: 1.4 }}>
                      {f.conclusion}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Epistemic Boundaries Declaration Card */}
          <div
            style={{
              padding: '14px',
              borderRadius: '8px',
              backgroundColor: 'var(--ds-bg-subtle)',
              border: '1px solid var(--ds-border-light)',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-secondary)', fontFamily: 'var(--ds-font-mono)' }}>
              <HelpCircle size={13} color="var(--ds-ink-muted)" />
              <span>WHAT CAN WE NOT KNOW? (PASSIVE BOUNDARIES)</span>
            </div>
            <p style={{ fontSize: '11px', color: 'var(--ds-ink-muted)', lineHeight: 1.45 }}>
              Passive capture evidence cannot verify revocation status (OCSP/CRL) or establish trust anchors without active network probes or external key material.
            </p>
          </div>
        </div>

        {/* Center Pane: Major Visual Investigation Experiences */}
        <div className="ds-center-pane">
          {/* Visual Canvas Sub-Navigation Tabs */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--ds-border-light)', paddingBottom: '14px' }}>
            <div style={{ display: 'flex', gap: '6px' }}>
              <button
                className={`ds-tab-btn ${activeCanvasView === 'ladder' ? 'active' : ''}`}
                onClick={() => setActiveCanvasView('ladder')}
              >
                <span>PROTOCOL SEQUENCE LADDER</span>
              </button>

              <button
                className={`ds-tab-btn ${activeCanvasView === 'provenance' ? 'active' : ''}`}
                onClick={() => setActiveCanvasView('provenance')}
              >
                <GitBranch size={13} />
                <span>PROVENANCE RELATIONSHIP GRAPH</span>
              </button>

              <button
                className={`ds-tab-btn ${activeCanvasView === 'coverage' ? 'active' : ''}`}
                onClick={() => setActiveCanvasView('coverage')}
              >
                <Layers size={13} />
                <span>EVIDENCE COVERAGE TIERS</span>
              </button>

              {fixtureKey === 'deepdive_cross_session_control_endpoint' && (
                <button
                  className={`ds-tab-btn ${activeCanvasView === 'cross_session' ? 'active' : ''}`}
                  onClick={() => setActiveCanvasView('cross_session')}
                  style={{
                    color: activeCanvasView === 'cross_session' ? 'var(--ds-crimson-ink)' : 'var(--ds-crimson)',
                    backgroundColor: activeCanvasView === 'cross_session' ? 'var(--ds-crimson-soft)' : 'transparent',
                    borderColor: activeCanvasView === 'cross_session' ? 'var(--ds-crimson-border)' : 'transparent',
                  }}
                >
                  <AlertCircle size={13} />
                  <span>CROSS-SESSION DEVIATION MATRIX</span>
                </button>
              )}
            </div>

            <span className="ds-mono" style={{ fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
              INTERACTIVE FORENSIC CANVAS
            </span>
          </div>

          {/* Active Canvas Body (Full Viewport Real Estate) */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            {activeCanvasView === 'ladder' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 8px' }}>
                  <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--ds-ink-secondary)' }}>
                    Client <code>127.0.0.1:36568</code> &bull; Server <code>127.0.0.1:465 (SMTPS)</code>
                  </span>
                  <span className="ds-mono" style={{ fontSize: '11px', color: 'var(--ds-indigo)' }}>
                    Click frame to pivot inspector
                  </span>
                </div>
                <ProtocolLadderSvg
                  selectedFrame={selectedFrame}
                  onSelectFrame={(f) => setSelectedFrame(f)}
                  darkTheme={false}
                  accentColor="#4f46e5"
                />
              </div>
            )}

            {activeCanvasView === 'provenance' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={{ padding: '0 8px' }}>
                  <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--ds-ink-secondary)' }}>
                    Deterministic Forensic Chain: Capture &rarr; Stream &rarr; Frame &rarr; Cert &rarr; Finding &rarr; Standard &rarr; Posture
                  </span>
                </div>
                <ProvenanceGraphSvg
                  darkTheme={false}
                  activeFindingTitle={activeFinding?.title}
                />
              </div>
            )}

            {activeCanvasView === 'coverage' && (
              <div style={{ padding: '8px' }}>
                <CoverageLanes darkTheme={false} />
              </div>
            )}

            {activeCanvasView === 'cross_session' && (
              <div style={{ padding: '8px' }}>
                <CrossSessionMatrix darkTheme={false} />
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Contextual Forensic & Standard Inspector */}
        <div className="ds-right-pane">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--ds-border-light)', paddingBottom: '14px' }}>
            <Key size={16} color="var(--ds-indigo)" />
            <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--ds-ink-primary)', letterSpacing: '-0.01em' }}>
              CONTEXTUAL EVIDENCE INSPECTOR
            </span>
          </div>

          {/* Inspecting Focus Banner */}
          <div
            style={{
              padding: '14px',
              borderRadius: '8px',
              backgroundColor: 'var(--ds-indigo-soft)',
              border: '1px solid var(--ds-indigo-border)',
              display: 'flex',
              flexDirection: 'column',
              gap: '4px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--ds-font-mono)' }}>
              <span style={{ color: 'var(--ds-indigo)', fontWeight: 700 }}>INSPECTING FRAME #{selectedFrame}</span>
              <span style={{ color: 'var(--ds-emerald)', fontWeight: 700 }}>EVIDENCE: OBSERVED</span>
            </div>
            <div style={{ fontSize: '13px', color: 'var(--ds-ink-primary)', fontWeight: 700 }}>
              {selectedFrame === 6 ? 'TLS ServerHello + Certificate Record' : `Frame #${selectedFrame} Packet Stream`}
            </div>
          </div>

          {/* X.509 Certificate Forensic Dissector */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)', letterSpacing: '0.04em' }}>
              RECONSTRUCTED CERTIFICATE SPECIMEN
            </div>

            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '10px',
                padding: '16px',
                borderRadius: '8px',
                backgroundColor: 'var(--ds-bg-subtle)',
                border: '1px solid var(--ds-border-light)',
                fontSize: '12px',
                fontFamily: 'var(--ds-font-mono)',
              }}
            >
              <div>
                <span style={{ color: 'var(--ds-ink-muted)' }}>Public Key Algorithm: </span>
                <span style={{ color: 'var(--ds-ink-primary)', fontWeight: 700 }}>RSA</span>
              </div>

              {/* Weak Modulus Alert Banner */}
              <div
                style={{
                  padding: '8px 10px',
                  borderRadius: '6px',
                  backgroundColor: 'var(--ds-crimson-soft)',
                  border: '1px solid var(--ds-crimson-border)',
                }}
              >
                <div style={{ color: 'var(--ds-crimson-ink)', fontWeight: 800 }}>
                  KEY LENGTH: 1024 BITS (DISALLOWED)
                </div>
                <div style={{ fontSize: '11px', color: 'var(--ds-crimson-ink)', marginTop: '3px', lineHeight: 1.4 }}>
                  Provides &lt;112 bits equivalent security. Violates NIST SP 800-57 Part 1 Rev. 5 §5.6.1 (mandates &ge;2048 bits).
                </div>
              </div>

              {/* Deprecated Signature Algorithm Alert Banner */}
              <div
                style={{
                  padding: '8px 10px',
                  borderRadius: '6px',
                  backgroundColor: 'var(--ds-crimson-soft)',
                  border: '1px solid var(--ds-crimson-border)',
                }}
              >
                <div style={{ color: 'var(--ds-crimson-ink)', fontWeight: 800 }}>
                  SIGNATURE: sha1WithRSAEncryption
                </div>
                <div style={{ fontSize: '11px', color: 'var(--ds-crimson-ink)', marginTop: '3px', lineHeight: 1.4 }}>
                  Collision resistance broken. Prohibited under RFC 9155 &amp; NIST SP 800-131A Rev. 2.
                </div>
              </div>

              <div>
                <span style={{ color: 'var(--ds-ink-muted)' }}>Serial Number: </span>
                <span style={{ color: 'var(--ds-indigo)', fontWeight: 600 }}>76:e5:b2:01:4d:52:8e...</span>
              </div>
              <div>
                <span style={{ color: 'var(--ds-ink-muted)' }}>Validity Window: </span>
                <span style={{ color: 'var(--ds-ink-primary)' }}>2026-09-21 to 2027-09-21 (Active)</span>
              </div>
              <div>
                <span style={{ color: 'var(--ds-ink-muted)' }}>Cipher Negotiated: </span>
                <span style={{ color: 'var(--ds-ink-primary)' }}>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</span>
              </div>
            </div>
          </div>

          {/* Statutory Standard Citation Dossier */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)', letterSpacing: '0.04em' }}>
              APPLICABLE STATUTORY STANDARD
            </div>

            <div
              style={{
                padding: '14px',
                borderRadius: '8px',
                backgroundColor: 'var(--ds-bg-canvas)',
                border: '1px solid var(--ds-border-light)',
                boxShadow: '0 1px 2px rgba(0,0,0,0.02)',
              }}
            >
              <div style={{ fontWeight: 700, color: 'var(--ds-indigo)', fontFamily: 'var(--ds-font-mono)', fontSize: '12px', marginBottom: '4px' }}>
                NIST SP 800-57 Part 1 Rev. 5 §5.6.1
              </div>
              <p style={{ color: 'var(--ds-ink-secondary)', fontSize: '12px', lineHeight: 1.5 }}>
                &ldquo;RSA moduli below 2048 bits provide less than 112 bits of security and are disallowed for protection of sensitive information.&rdquo;
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
