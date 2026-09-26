import React, { useState } from 'react';
import { FIXTURES, FIXTURE_METADATA, type FixtureKey } from '../fixtures';
import { ProtocolLadderSvg } from '../shared/ProtocolLadderSvg';
import { ProvenanceGraphSvg } from '../shared/ProvenanceGraphSvg';
import { CoverageLanes } from '../shared/CoverageLanes';
import { CrossSessionMatrix } from '../shared/CrossSessionMatrix';
import { ArrowLeft, CheckCircle2, Key } from 'lucide-react';
import './DirectionA.css';

interface DirectionA_OverviewProps {
  fixtureKey: FixtureKey;
  onBackToDesk: () => void;
}

export const DirectionA_Overview: React.FC<DirectionA_OverviewProps> = ({
  fixtureKey,
  onBackToDesk,
}) => {
  const data = FIXTURES[fixtureKey];
  const meta = FIXTURE_METADATA[fixtureKey];
  const [selectedFrame, setSelectedFrame] = useState<number>(6);
  const [selectedFindingIdx, setSelectedFindingIdx] = useState<number>(0);
  const [activeCenterView, setActiveCenterView] = useState<'ladder' | 'provenance' | 'coverage' | 'cross_session'>('ladder');

  const findings = data.dashboard?.findings || [];
  const activeFinding = findings[selectedFindingIdx] || findings[0];
  const isCritical = meta.verdict === 'CRITICAL';

  return (
    <div className="dir-a-theme">
      {/* Top Persistent Tactical Context Bar */}
      <header className="da-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button
            onClick={onBackToDesk}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              color: 'var(--da-cyan)',
              fontSize: '11px',
              fontFamily: 'var(--da-font-mono)',
              padding: '4px 8px',
              borderRadius: '4px',
              backgroundColor: 'rgba(56, 189, 248, 0.1)',
            }}
          >
            <ArrowLeft size={12} />
            <span>CASE DESK</span>
          </button>
          <div style={{ height: '16px', width: '1px', backgroundColor: 'var(--da-border-subtle)' }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px' }}>
            <span style={{ color: 'var(--da-text-muted)' }}>CASE:</span>
            <span style={{ fontWeight: 700, color: 'var(--da-text-bright)', fontFamily: 'var(--da-font-mono)' }}>
              {meta.pcap}
            </span>
          </div>
          <span style={{ color: 'var(--da-text-muted)' }}>/</span>
          <span style={{ fontSize: '11px', fontFamily: 'var(--da-font-mono)', color: 'var(--da-text-secondary)' }}>
            CAPTURE SHA256: {data.run.run_id.slice(0, 16)}...
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <span
            style={{
              padding: '4px 10px',
              borderRadius: '4px',
              backgroundColor: isCritical ? 'rgba(244, 63, 94, 0.15)' : 'rgba(16, 185, 129, 0.15)',
              color: isCritical ? 'var(--da-crimson)' : 'var(--da-emerald)',
              border: `1px solid ${isCritical ? 'var(--da-crimson)' : 'var(--da-emerald)'}`,
              fontSize: '11px',
              fontWeight: 800,
              fontFamily: 'var(--da-font-mono)',
            }}
          >
            {meta.verdict} // {meta.score.toFixed(1)} / 100.0
          </span>
          <span style={{ fontSize: '11px', color: 'var(--da-text-muted)', fontFamily: 'var(--da-font-mono)' }}>
            EVIDENCE: DETERMINISTIC RULES
          </span>
        </div>
      </header>

      {/* 3-Column Command Center Workspace */}
      <div className="da-overview-layout">
        {/* Left Column: Finding Stack & Impact Decomposition */}
        <div className="da-rail-left">
          {/* Verdict HUD */}
          <div className={`da-verdict-box ${isCritical ? 'critical' : ''}`}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '10px', fontWeight: 800, letterSpacing: '0.1em', color: isCritical ? 'var(--da-crimson)' : 'var(--da-emerald)', fontFamily: 'var(--da-font-mono)' }}>
                OVERALL POSTURE VERDICT
              </span>
              <span style={{ fontSize: '10px', color: 'var(--da-text-muted)', fontFamily: 'var(--da-font-mono)' }}>
                F2-GROUP-DAMPED
              </span>
            </div>

            <div className="da-score-large">
              <span>{meta.score.toFixed(1)}</span>
              <span className="da-score-max">/ 100</span>
            </div>

            <div style={{ fontSize: '12px', color: 'var(--da-text-secondary)', lineHeight: 1.4 }}>
              {isCritical ? (
                <>
                  <strong style={{ color: 'var(--da-crimson)' }}>−56.0 penalty points</strong> deducted for 2 confirmed cryptographic security violations.
                </>
              ) : (
                <>
                  <strong style={{ color: 'var(--da-emerald)' }}>Zero penalties deducted</strong>; TLS 1.3 encryption preserves posture integrity.
                </>
              )}
            </div>

            {/* Score waterfall breakdown */}
            <div
              style={{
                marginTop: '8px',
                padding: '10px',
                borderRadius: '6px',
                backgroundColor: 'rgba(0,0,0,0.3)',
                fontSize: '11px',
                fontFamily: 'var(--da-font-mono)',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--da-text-muted)' }}>
                <span>Baseline Starting Score:</span>
                <span>100.0</span>
              </div>
              {fixtureKey === 'backup_weak_certificate' && (
                <>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--da-crimson)' }}>
                    <span>RSA 1024-bit Modulus:</span>
                    <span>−28.0</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--da-crimson)' }}>
                    <span>SHA-1 Signature Hash:</span>
                    <span>−28.0</span>
                  </div>
                </>
              )}
              {fixtureKey === 'deepdive_cross_session_control_endpoint' && (
                <>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--da-crimson)' }}>
                    <span>No TLS Protection:</span>
                    <span>−40.0</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--da-amber)' }}>
                    <span>Behavioral Deviation:</span>
                    <span>−37.85</span>
                  </div>
                </>
              )}
              <div style={{ height: '1px', backgroundColor: 'var(--da-border-subtle)', margin: '2px 0' }} />
              <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 700, color: isCritical ? 'var(--da-crimson)' : 'var(--da-emerald)' }}>
                <span>Final Evaluated Score:</span>
                <span>{meta.score.toFixed(1)}</span>
              </div>
            </div>
          </div>

          {/* Finding Navigation Stack */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--da-text-muted)', fontFamily: 'var(--da-font-mono)', letterSpacing: '0.05em' }}>
              FINDINGS STACK ({findings.length})
            </div>

            {findings.length === 0 ? (
              <div
                style={{
                  padding: '16px',
                  borderRadius: '6px',
                  backgroundColor: 'var(--da-bg-card)',
                  border: '1px solid var(--da-border-subtle)',
                  fontSize: '12px',
                  color: 'var(--da-text-secondary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                }}
              >
                <CheckCircle2 size={16} color="var(--da-emerald)" />
                <span>No penalizing findings observed. All compliance checks passed.</span>
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
                      padding: '12px',
                      borderRadius: '6px',
                      backgroundColor: isSelected ? 'var(--da-bg-elevated)' : 'var(--da-bg-card)',
                      border: `1px solid ${isSelected ? 'var(--da-crimson)' : 'var(--da-border-subtle)'}`,
                      cursor: 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px',
                      transition: 'border-color 0.16s ease',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span
                        style={{
                          fontSize: '9px',
                          fontWeight: 800,
                          padding: '2px 6px',
                          borderRadius: '3px',
                          backgroundColor: 'rgba(244, 63, 94, 0.15)',
                          color: 'var(--da-crimson)',
                          fontFamily: 'var(--da-font-mono)',
                        }}
                      >
                        {f.severity} // {f.source_rule_ids?.[0] || 'RULE'}
                      </span>
                      <span style={{ fontSize: '10px', fontFamily: 'var(--da-font-mono)', color: 'var(--da-cyan)' }}>
                        Frame #{f.frames?.[0] || 6}
                      </span>
                    </div>

                    <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--da-text-bright)' }}>
                      {f.title}
                    </div>

                    <div style={{ fontSize: '11px', color: 'var(--da-text-secondary)', lineHeight: 1.3 }}>
                      {f.conclusion}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Center Investigation Canvas */}
        <div className="da-canvas-center">
          {/* Canvas Sub-Nav */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--da-border-subtle)', paddingBottom: '12px' }}>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                onClick={() => setActiveCenterView('ladder')}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  backgroundColor: activeCenterView === 'ladder' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                  color: activeCenterView === 'ladder' ? 'var(--da-cyan)' : 'var(--da-text-secondary)',
                  border: `1px solid ${activeCenterView === 'ladder' ? 'rgba(56, 189, 248, 0.4)' : 'transparent'}`,
                  fontSize: '11px',
                  fontWeight: 700,
                  fontFamily: 'var(--da-font-mono)',
                }}
              >
                PROTOCOL LADDER
              </button>
              <button
                onClick={() => setActiveCenterView('provenance')}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  backgroundColor: activeCenterView === 'provenance' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                  color: activeCenterView === 'provenance' ? 'var(--da-cyan)' : 'var(--da-text-secondary)',
                  border: `1px solid ${activeCenterView === 'provenance' ? 'rgba(56, 189, 248, 0.4)' : 'transparent'}`,
                  fontSize: '11px',
                  fontWeight: 700,
                  fontFamily: 'var(--da-font-mono)',
                }}
              >
                PROVENANCE CHAIN
              </button>
              <button
                onClick={() => setActiveCenterView('coverage')}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  backgroundColor: activeCenterView === 'coverage' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                  color: activeCenterView === 'coverage' ? 'var(--da-cyan)' : 'var(--da-text-secondary)',
                  border: `1px solid ${activeCenterView === 'coverage' ? 'rgba(56, 189, 248, 0.4)' : 'transparent'}`,
                  fontSize: '11px',
                  fontWeight: 700,
                  fontFamily: 'var(--da-font-mono)',
                }}
              >
                COVERAGE TIERS
              </button>
              {fixtureKey === 'deepdive_cross_session_control_endpoint' && (
                <button
                  onClick={() => setActiveCenterView('cross_session')}
                  style={{
                    padding: '6px 12px',
                    borderRadius: '4px',
                    backgroundColor: activeCenterView === 'cross_session' ? 'rgba(244, 63, 94, 0.2)' : 'transparent',
                    color: activeCenterView === 'cross_session' ? 'var(--da-crimson)' : 'var(--da-text-secondary)',
                    border: `1px solid ${activeCenterView === 'cross_session' ? 'var(--da-crimson)' : 'transparent'}`,
                    fontSize: '11px',
                    fontWeight: 700,
                    fontFamily: 'var(--da-font-mono)',
                  }}
                >
                  CROSS-SESSION DEVIATION
                </button>
              )}
            </div>

            <div style={{ fontSize: '11px', fontFamily: 'var(--da-font-mono)', color: 'var(--da-text-muted)' }}>
              CLICK ANY PACKET / NODE TO INSPECT
            </div>
          </div>

          {/* Active Canvas Body */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            {activeCenterView === 'ladder' && (
              <ProtocolLadderSvg
                selectedFrame={selectedFrame}
                onSelectFrame={(f) => setSelectedFrame(f)}
                darkTheme={true}
              />
            )}
            {activeCenterView === 'provenance' && (
              <ProvenanceGraphSvg
                darkTheme={true}
                activeFindingTitle={activeFinding?.title}
              />
            )}
            {activeCenterView === 'coverage' && (
              <CoverageLanes darkTheme={true} />
            )}
            {activeCenterView === 'cross_session' && (
              <CrossSessionMatrix darkTheme={true} />
            )}
          </div>
        </div>

        {/* Right Column: Contextual Forensic Inspector */}
        <div className="da-rail-right">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--da-border-subtle)', paddingBottom: '12px' }}>
            <Key size={16} color="var(--da-cyan)" />
            <span style={{ fontSize: '13px', fontWeight: 700, letterSpacing: '0.04em' }}>
              CONTEXTUAL FORENSIC INSPECTOR
            </span>
          </div>

          {/* Inspector Target Banner */}
          <div
            style={{
              padding: '12px',
              borderRadius: '6px',
              backgroundColor: 'rgba(56, 189, 248, 0.08)',
              border: '1px solid rgba(56, 189, 248, 0.25)',
              display: 'flex',
              flexDirection: 'column',
              gap: '4px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--da-font-mono)' }}>
              <span style={{ color: 'var(--da-cyan)', fontWeight: 700 }}>INSPECTING FRAME #{selectedFrame}</span>
              <span style={{ color: 'var(--da-emerald)' }}>EVIDENCE: OBSERVED</span>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--da-text-bright)', fontWeight: 600 }}>
              {selectedFrame === 6 ? 'TLS ServerHello + Certificate Record' : `Frame #${selectedFrame} Packet Stream`}
            </div>
          </div>

          {/* X.509 Certificate Forensic Dissection */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--da-text-muted)', fontFamily: 'var(--da-font-mono)' }}>
              CERTIFICATE ARTIFACT SPECIMEN
            </div>

            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
                padding: '12px',
                borderRadius: '6px',
                backgroundColor: 'var(--da-bg-card)',
                border: '1px solid var(--da-border-subtle)',
                fontSize: '11px',
                fontFamily: 'var(--da-font-mono)',
              }}
            >
              <div>
                <span style={{ color: 'var(--da-text-muted)' }}>Public Key Algorithm: </span>
                <span style={{ color: 'var(--da-text-bright)', fontWeight: 700 }}>RSA</span>
              </div>

              {/* Weak Modulus Alert */}
              <div
                style={{
                  padding: '6px 8px',
                  borderRadius: '4px',
                  backgroundColor: 'rgba(244, 63, 94, 0.15)',
                  border: '1px solid var(--da-crimson)',
                }}
              >
                <div style={{ color: 'var(--da-crimson)', fontWeight: 800 }}>
                  KEY LENGTH: 1024 BITS (DISALLOWED)
                </div>
                <div style={{ fontSize: '10px', color: '#fda4af', marginTop: '2px', lineHeight: 1.3 }}>
                  Provides &lt;112 bits equivalent security. Violates NIST SP 800-57 Part 1 Rev. 5 §5.6.1 (requires ≥2048 bits).
                </div>
              </div>

              {/* Deprecated Signature Algorithm */}
              <div
                style={{
                  padding: '6px 8px',
                  borderRadius: '4px',
                  backgroundColor: 'rgba(244, 63, 94, 0.15)',
                  border: '1px solid var(--da-crimson)',
                }}
              >
                <div style={{ color: 'var(--da-crimson)', fontWeight: 800 }}>
                  SIGNATURE: sha1WithRSAEncryption
                </div>
                <div style={{ fontSize: '10px', color: '#fda4af', marginTop: '2px', lineHeight: 1.3 }}>
                  Collision resistance broken. Prohibited under RFC 9155 and NIST SP 800-131A Rev. 2.
                </div>
              </div>

              <div>
                <span style={{ color: 'var(--da-text-muted)' }}>Serial Number: </span>
                <span style={{ color: 'var(--da-cyan)' }}>76:e5:b2:01:4d...</span>
              </div>
              <div>
                <span style={{ color: 'var(--da-text-muted)' }}>Validity Window: </span>
                <span style={{ color: 'var(--da-text-bright)' }}>2026-09-21 to 2027-09-21</span>
              </div>
              <div>
                <span style={{ color: 'var(--da-text-muted)' }}>Cipher Negotiated: </span>
                <span style={{ color: 'var(--da-text-bright)' }}>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</span>
              </div>
            </div>
          </div>

          {/* Statutory Standard Citation Box */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--da-text-muted)', fontFamily: 'var(--da-font-mono)' }}>
              STATUTORY CITATION REGISTRY
            </div>

            <div
              style={{
                padding: '12px',
                borderRadius: '6px',
                backgroundColor: 'var(--da-bg-card)',
                border: '1px solid var(--da-border-subtle)',
                fontSize: '11px',
                lineHeight: 1.4,
              }}
            >
              <div style={{ fontWeight: 700, color: 'var(--da-cyan)', fontFamily: 'var(--da-font-mono)', marginBottom: '4px' }}>
                NIST SP 800-57 Part 1 Rev. 5 §5.6.1
              </div>
              <p style={{ color: 'var(--da-text-secondary)', fontSize: '11px' }}>
                &ldquo;RSA moduli below 2048 bits provide less than 112 bits of security and are disallowed for protection of sensitive Federal information.&rdquo;
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
