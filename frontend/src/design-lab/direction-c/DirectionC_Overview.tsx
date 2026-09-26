import React, { useState } from 'react';
import { FIXTURES, FIXTURE_METADATA, type FixtureKey } from '../fixtures';
import { ProvenanceGraphSvg } from '../shared/ProvenanceGraphSvg';
import { ProtocolLadderSvg } from '../shared/ProtocolLadderSvg';
import { CrossSessionMatrix } from '../shared/CrossSessionMatrix';
import { CoverageLanes } from '../shared/CoverageLanes';
import { ArrowLeft, GitBranch, Layers } from 'lucide-react';
import './DirectionC.css';

interface DirectionC_OverviewProps {
  fixtureKey: FixtureKey;
  onBackToDesk: () => void;
}

export const DirectionC_Overview: React.FC<DirectionC_OverviewProps> = ({
  fixtureKey,
  onBackToDesk,
}) => {
  const data = FIXTURES[fixtureKey];
  const meta = FIXTURE_METADATA[fixtureKey];
  const [activeCenterTab, setActiveCenterTab] = useState<'graph' | 'ladder' | 'cross_session' | 'coverage'>('graph');
  const [selectedFindingIdx, setSelectedFindingIdx] = useState(0);

  const findings = data.dashboard?.findings || [];
  const activeFinding = findings[selectedFindingIdx] || findings[0];
  const isCritical = meta.verdict === 'CRITICAL';

  return (
    <div className="dir-c-theme">
      {/* Top Entity Bar */}
      <header className="dc-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button
            onClick={onBackToDesk}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              color: 'var(--dc-cyan)',
              fontSize: '12px',
              fontFamily: 'var(--dc-font-mono)',
              padding: '4px 10px',
              borderRadius: '6px',
              backgroundColor: 'var(--dc-bg-surface)',
              border: '1px solid var(--dc-border-subtle)',
            }}
          >
            <ArrowLeft size={14} />
            <span>THREAT DIRECTORY</span>
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '13px', color: 'var(--dc-text-muted)' }}>ENTITY:</span>
            <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--dc-text-bright)', fontFamily: 'var(--dc-font-mono)' }}>
              127.0.0.1:465 (SMTP-TLS)
            </span>
          </div>

          <span className="dc-pill dc-pill-violet">CAPTURE: {meta.pcap}</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className={isCritical ? 'dc-pill dc-pill-ruby' : 'dc-pill dc-pill-emerald'}>
            THREAT LEVEL: {meta.verdict} // SCORE: {meta.score.toFixed(1)}
          </span>
          <span className="dc-mono" style={{ fontSize: '11px', color: 'var(--dc-text-muted)' }}>
            EVIDENCE: DETERMINISTIC RULES
          </span>
        </div>
      </header>

      {/* 3-Pane Threat Intelligence Workbench */}
      <div className="dc-workspace-grid">
        {/* Left Pane: Finding & Threat Breakdown */}
        <div className="dc-pane">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--dc-border-subtle)', paddingBottom: '10px' }}>
            <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--dc-text-bright)', letterSpacing: '0.04em' }}>
              THREAT INDICATORS ({findings.length})
            </span>
            <span className="dc-mono" style={{ fontSize: '10px', color: 'var(--dc-text-muted)' }}>
              PRIORITIZED
            </span>
          </div>

          {findings.length === 0 ? (
            <div style={{ padding: '16px', borderRadius: '6px', backgroundColor: 'var(--dc-bg-surface)', fontSize: '12px', color: 'var(--dc-emerald)' }}>
              No threat indicators detected. Encrypted transport verified.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {findings.map((f: any, idx: number) => {
                const isSelected = selectedFindingIdx === idx;
                return (
                  <div
                    key={f.title + idx}
                    onClick={() => setSelectedFindingIdx(idx)}
                    style={{
                      padding: '12px',
                      borderRadius: '6px',
                      backgroundColor: isSelected ? 'var(--dc-bg-surface)' : 'var(--dc-bg-root)',
                      border: `1px solid ${isSelected ? 'var(--dc-violet)' : 'var(--dc-border-subtle)'}`,
                      cursor: 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className="dc-pill dc-pill-ruby" style={{ fontSize: '9px', padding: '1px 6px' }}>
                        {f.severity} // −28 PTS
                      </span>
                      <span className="dc-mono" style={{ fontSize: '10px', color: 'var(--dc-cyan)' }}>
                        {f.source_rule_ids?.[0] || 'RULE'}
                      </span>
                    </div>

                    <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--dc-text-bright)' }}>
                      {f.title}
                    </div>

                    <div style={{ fontSize: '11px', color: 'var(--dc-text-secondary)', lineHeight: 1.3 }}>
                      {f.conclusion}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Quick Threat Intel Score Summary */}
          <div
            style={{
              marginTop: 'auto',
              padding: '12px',
              borderRadius: '6px',
              backgroundColor: 'var(--dc-bg-root)',
              border: '1px solid var(--dc-border-subtle)',
              fontFamily: 'var(--dc-font-mono)',
              fontSize: '11px',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--dc-text-muted)' }}>
              <span>Damped Deductions:</span>
              <span style={{ color: 'var(--dc-ruby)' }}>−56.0</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 700 }}>
              <span style={{ color: 'var(--dc-text-bright)' }}>Post-Analysis Score:</span>
              <span style={{ color: isCritical ? 'var(--dc-ruby)' : 'var(--dc-emerald)' }}>
                {meta.score.toFixed(1)} / 100
              </span>
            </div>
          </div>
        </div>

        {/* Center Pane: Interactive Relationship Graph & Sequence Canvas */}
        <div className="dc-pane">
          {/* Canvas Sub-Tabs */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--dc-border-subtle)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                onClick={() => setActiveCenterTab('graph')}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  backgroundColor: activeCenterTab === 'graph' ? 'var(--dc-violet)' : 'var(--dc-bg-surface)',
                  color: '#ffffff',
                  fontSize: '11px',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <GitBranch size={13} />
                <span>RELATIONSHIP GRAPH</span>
              </button>

              <button
                onClick={() => setActiveCenterTab('ladder')}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  backgroundColor: activeCenterTab === 'ladder' ? 'var(--dc-violet)' : 'var(--dc-bg-surface)',
                  color: '#ffffff',
                  fontSize: '11px',
                  fontWeight: 600,
                }}
              >
                PROTOCOL LADDER
              </button>

              <button
                onClick={() => setActiveCenterTab('coverage')}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  backgroundColor: activeCenterTab === 'coverage' ? 'var(--dc-violet)' : 'var(--dc-bg-surface)',
                  color: '#ffffff',
                  fontSize: '11px',
                  fontWeight: 600,
                }}
              >
                COVERAGE TIERS
              </button>

              {fixtureKey === 'deepdive_cross_session_control_endpoint' && (
                <button
                  onClick={() => setActiveCenterTab('cross_session')}
                  style={{
                    padding: '6px 12px',
                    borderRadius: '4px',
                    backgroundColor: activeCenterTab === 'cross_session' ? 'var(--dc-ruby)' : 'var(--dc-bg-surface)',
                    color: '#ffffff',
                    fontSize: '11px',
                    fontWeight: 600,
                  }}
                >
                  CONTROL DIFF MATRIX
                </button>
              )}
            </div>

            <span className="dc-mono" style={{ fontSize: '11px', color: 'var(--dc-text-muted)' }}>
              NODE-LINK FORENSIC TOPOLOGY
            </span>
          </div>

          {/* Active Canvas Body */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            {activeCenterTab === 'graph' && (
              <ProvenanceGraphSvg darkTheme={true} activeFindingTitle={activeFinding?.title} />
            )}
            {activeCenterTab === 'ladder' && (
              <ProtocolLadderSvg darkTheme={true} selectedFrame={6} />
            )}
            {activeCenterTab === 'coverage' && (
              <CoverageLanes darkTheme={true} />
            )}
            {activeCenterTab === 'cross_session' && (
              <CrossSessionMatrix darkTheme={true} />
            )}
          </div>
        </div>

        {/* Right Pane: Evidence & Payload Inspector */}
        <div className="dc-pane">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--dc-border-subtle)', paddingBottom: '10px' }}>
            <Layers size={16} color="var(--dc-cyan)" />
            <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--dc-text-bright)', letterSpacing: '0.04em' }}>
              EVIDENCE &amp; ENTITY INSPECTOR
            </span>
          </div>

          {/* Active Finding Deep Dive */}
          <div
            style={{
              padding: '12px',
              borderRadius: '6px',
              backgroundColor: 'var(--dc-bg-root)',
              border: '1px solid var(--dc-border-subtle)',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', fontFamily: 'var(--dc-font-mono)' }}>
              <span style={{ color: 'var(--dc-violet)', fontWeight: 700 }}>SELECTED DEFECT</span>
              <span className="dc-pill dc-pill-ruby" style={{ fontSize: '9px', padding: '1px 6px' }}>
                OBSERVED ISSUE
              </span>
            </div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--dc-text-bright)' }}>
              {activeFinding?.title || 'Certificate public key strength'}
            </div>
            <p style={{ fontSize: '11px', color: 'var(--dc-text-secondary)', lineHeight: 1.4 }}>
              {activeFinding?.explanation || 'leaf uses a 1024-bit RSA key. NIST SP 800-57 Part 1 Rev. 5 §5.6.1: RSA moduli below 2048 bits provide less than 112 bits of security.'}
            </p>
          </div>

          {/* Target Metadata & Cryptographic Hashes */}
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
              padding: '12px',
              borderRadius: '6px',
              backgroundColor: 'var(--dc-bg-root)',
              border: '1px solid var(--dc-border-subtle)',
              fontFamily: 'var(--dc-font-mono)',
              fontSize: '11px',
            }}
          >
            <div style={{ color: 'var(--dc-text-muted)', fontSize: '10px', fontWeight: 700 }}>
              CRYPTOGRAPHIC HANDSHAKE ATTRIBUTES
            </div>
            <div>
              <span style={{ color: 'var(--dc-text-muted)' }}>Cipher Suite: </span>
              <span style={{ color: 'var(--dc-text-bright)' }}>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)</span>
            </div>
            <div>
              <span style={{ color: 'var(--dc-text-muted)' }}>Key Exchange: </span>
              <span style={{ color: 'var(--dc-emerald)' }}>ECDHE (Forward Secrecy Observed)</span>
            </div>
            <div>
              <span style={{ color: 'var(--dc-text-muted)' }}>Public Key Modulus: </span>
              <span style={{ color: 'var(--dc-ruby)', fontWeight: 700 }}>RSA 1024 bits (Weak)</span>
            </div>
            <div>
              <span style={{ color: 'var(--dc-text-muted)' }}>Signature Hash: </span>
              <span style={{ color: 'var(--dc-ruby)', fontWeight: 700 }}>sha1WithRSAEncryption (Deprecated)</span>
            </div>
            <div>
              <span style={{ color: 'var(--dc-text-muted)' }}>Frames Cited: </span>
              <span style={{ color: 'var(--dc-cyan)' }}>Frame #6 (Stream #0)</span>
            </div>
          </div>

          {/* Standards & Authority Reference */}
          <div
            style={{
              padding: '12px',
              borderRadius: '6px',
              backgroundColor: 'var(--dc-bg-root)',
              border: '1px solid var(--dc-border-subtle)',
              fontSize: '11px',
            }}
          >
            <div style={{ color: 'var(--dc-violet)', fontWeight: 700, fontFamily: 'var(--dc-font-mono)', marginBottom: '4px' }}>
              NIST SP 800-57 Part 1 Rev. 5 §5.6.1
            </div>
            <div style={{ color: 'var(--dc-text-secondary)', fontSize: '11px', lineHeight: 1.4 }}>
              Disallowed. Provides &lt;112 bits of cryptographic strength. Replacement with RSA ≥2048 or ECC required.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
