import React, { useState, useMemo } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import type { FindingRow } from '../../../api/types';
import {
  FileCode,
  Network,
  Radio,
  KeyRound,
  AlertTriangle,
  Scale,
  MinusCircle,
  ChevronRight,
  Info,
} from 'lucide-react';
import { ProvenanceGraphSvg } from '../../../design-lab/shared/ProvenanceGraphSvg';

export const ProvenanceGraph: React.FC = () => {
  const {
    activeRun,
    dashboard,
    sessions,
    selectedFinding,
    selectFinding,
    pivotToJourney,
  } = useInvestigation();

  const findings = dashboard?.findings || [];
  const [activeFindingIndex, setActiveFindingIndex] = useState<number>(() => {
    if (selectedFinding && findings.length > 0) {
      const idx = findings.findIndex((f) => f.title === selectedFinding.title);
      return idx >= 0 ? idx : 0;
    }
    return 0;
  });

  const currentFinding: FindingRow | undefined = findings[activeFindingIndex] || findings[0];

  // Resolve matching session
  const matchingSession = useMemo(() => {
    if (!currentFinding) return sessions[0] || null;
    const streamKey = currentFinding.affected_stream_keys?.[0] || currentFinding.stream_key;
    return sessions.find((s) => s.stream_key === streamKey) || sessions[0] || null;
  }, [currentFinding, sessions]);

  // Resolve matching penalty from score components
  const matchingPenalty = useMemo(() => {
    if (!currentFinding || !dashboard?.posture?.components) return null;
    return dashboard.posture.components.find(
      (c) => c.issue_class === currentFinding.issue_class
    );
  }, [currentFinding, dashboard]);

  if (!findings.length || !currentFinding) {
    return (
      <div style={{ padding: '48px 24px', textAlign: 'center', color: 'var(--ink-muted)' }}>
        <p style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', marginBottom: '8px' }}>
          NO FORENSIC FINDING ANOMALIES ESTABLISHED
        </p>
        <p style={{ fontSize: 'var(--text-xs)' }}>
          The observable evidence in this capture satisfies applicable baseline standards without penalty deductions.
        </p>
      </div>
    );
  }

  // Construct Provenance Chain Nodes
  const frameNum = currentFinding.frames?.[0] || matchingSession?.timing?.first_frame || 1;
  const standardCitation = currentFinding.citations?.[0]?.text || currentFinding.citations?.[0]?.standard || 'NIST SP 800-52r2';
  const standardSection = currentFinding.citations?.[0]?.section ? `§${currentFinding.citations[0].section}` : '';
  const penaltyValue = matchingPenalty?.penalty ? `-${matchingPenalty.penalty.toFixed(1)}` : '-28.0';

  // Specific artifact extraction from finding
  let artifactName = 'Cryptographic Parameter';
  let artifactDetail = currentFinding.conclusion;
  if (currentFinding.issue_class === 'CERTIFICATE_KEY_STRENGTH') {
    artifactName = 'RSA 1024-bit Modulus';
    artifactDetail = 'Disallowed weak public key modulus observed in X.509 leaf certificate';
  } else if (currentFinding.issue_class === 'CERTIFICATE_SIGNATURE_ALGORITHM') {
    artifactName = 'sha1WithRSAEncryption';
    artifactDetail = 'Deprecated SHA-1 signature algorithm observed in certificate chain';
  } else if (currentFinding.issue_class === 'STARTTLS_BEHAVIOUR_DEVIATION') {
    artifactName = 'STARTTLS Capability Absent';
    artifactDetail = 'Upgrade advertisement omitted while 6 baseline peer sessions upgraded';
  } else if (currentFinding.issue_class === 'PLAINTEXT_AUTH_EXPOSURE') {
    artifactName = 'Cleartext AUTH Command';
    artifactDetail = 'Authentication credentials observed outside encrypted TLS channel';
  } else if (currentFinding.issue_class === 'NO_TLS_PROTECTION') {
    artifactName = 'Cleartext TCP Stream';
    artifactDetail = 'Session carried no TLS record layer encryption';
  }

  const nodes = [
    {
      id: 'capture',
      label: 'CAPTURE ARTIFACT',
      title: activeRun?.source_filename || 'capture.pcap',
      subtitle: activeRun?.capture_id ? `${activeRun.capture_id.slice(0, 14)}...` : 'PCAP Ingest',
      icon: <FileCode size={16} color="var(--accent-primary)" />,
      badge: 'OFFLINE RAW',
      color: 'var(--accent-primary)',
      onClick: () => {},
    },
    {
      id: 'stream',
      label: 'TCP STREAM',
      title: `Stream #${matchingSession?.tcp_stream_id ?? 0} (${matchingSession?.protocol || 'smtp'})`,
      subtitle: matchingSession ? `${matchingSession.client.ip}:${matchingSession.client.port} → ${matchingSession.server.ip}:${matchingSession.server.port}` : 'Stream Dissection',
      icon: <Network size={16} color="var(--accent-primary)" />,
      badge: 'DISSECTED',
      color: 'var(--accent-primary)',
      onClick: () => pivotToJourney(frameNum, matchingSession?.stream_key),
    },
    {
      id: 'frame',
      label: 'PACKET FRAME',
      title: `Frame #${frameNum}`,
      subtitle: 'Observed protocol packet containing cryptographic payload',
      icon: <Radio size={16} color="var(--epistemic-observed-border)" />,
      badge: 'OBSERVED',
      color: 'var(--epistemic-observed-border)',
      onClick: () => pivotToJourney(frameNum, matchingSession?.stream_key),
    },
    {
      id: 'artifact',
      label: 'CRYPTOGRAPHIC ARTIFACT',
      title: artifactName,
      subtitle: artifactDetail,
      icon: <KeyRound size={16} color="var(--sev-high-ink)" />,
      badge: currentFinding.certainty || 'CONFIRMED',
      color: 'var(--sev-high-ink)',
      onClick: () => selectFinding(currentFinding),
    },
    {
      id: 'finding',
      label: 'FINDING CONCLUSION',
      title: currentFinding.title,
      subtitle: currentFinding.conclusion,
      icon: <AlertTriangle size={16} color="var(--sev-critical-ink)" />,
      badge: currentFinding.severity || 'HIGH',
      color: 'var(--sev-critical-ink)',
      onClick: () => selectFinding(currentFinding),
    },
    {
      id: 'standard',
      label: 'AUTHORITATIVE STANDARD',
      title: standardCitation.slice(0, 48),
      subtitle: `${currentFinding.citations?.[0]?.reason || 'Mandatory security constraint'} ${standardSection}`,
      icon: <Scale size={16} color="var(--ink-secondary)" />,
      badge: 'REGULATORY',
      color: 'var(--ink-secondary)',
      onClick: () => selectFinding(currentFinding),
    },
    {
      id: 'posture',
      label: 'POSTURE IMPACT',
      title: `${penaltyValue} PTS`,
      subtitle: `Deduction under ${dashboard?.posture?.formula_id || 'F2-group-damped'} calculus`,
      icon: <MinusCircle size={16} color="var(--sev-critical-ink)" />,
      badge: 'PENALTY',
      color: 'var(--sev-critical-ink)',
      onClick: () => {},
    },
  ];

  return (
    <div style={{ maxWidth: '1240px', width: '100%', margin: '0 auto', padding: '24px 0 48px' }} className="animate-fade-in">
      {/* Header and Finding Selector */}
      <div style={{ marginBottom: '24px', borderBottom: '1px solid var(--rule-base)', paddingBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: '8px' }}>
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
              Provenance — Cryptographic Evidence Trace
            </h2>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--ink-muted)' }}>
              Deterministic evidence lineage tracing raw PCAP capture bytes to authoritative standard citations and posture score deductions.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: 'var(--text-2xs)', fontFamily: 'var(--font-mono)', color: 'var(--ink-muted)' }}>
            <Info size={12} />
            <span>Click any node to pivot investigation context</span>
          </div>
        </div>

        {/* Finding Selector Pills */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '14px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 'var(--text-2xs)', fontFamily: 'var(--font-mono)', color: 'var(--ink-muted)', textTransform: 'uppercase' }}>
            Select Trace:
          </span>
          {findings.map((f, idx) => {
            const isSelected = idx === activeFindingIndex;
            return (
              <button
                key={f.title}
                type="button"
                onClick={() => {
                  setActiveFindingIndex(idx);
                  selectFinding(f);
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '4px 10px',
                  fontSize: 'var(--text-xs)',
                  fontFamily: 'var(--font-mono)',
                  backgroundColor: isSelected ? 'var(--bg-surface)' : 'var(--bg-subtle)',
                  color: isSelected ? 'var(--ink-primary)' : 'var(--ink-muted)',
                  border: `1px solid ${isSelected ? 'var(--rule-heavy)' : 'var(--rule-subtle)'}`,
                  borderRadius: 'var(--radius-xs)',
                  fontWeight: isSelected ? 700 : 500,
                  transition: 'all var(--duration-micro) var(--ease-out)',
                }}
              >
                <span style={{ color: f.severity === 'CRITICAL' ? 'var(--sev-critical-ink)' : 'var(--sev-high-ink)' }}>
                  F-0{idx + 1}
                </span>
                <span>{f.title}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Top Visual SVG Topological Relationship Graph */}
      <div
        style={{
          backgroundColor: 'var(--bg-surface)',
          border: '1px solid var(--rule-base)',
          borderRadius: 'var(--radius-sm)',
          padding: '24px',
          boxShadow: 'var(--shadow-subtle)',
          marginBottom: '24px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--ink-secondary)', fontFamily: 'var(--font-mono)' }}>
            TOPOLOGICAL FORENSIC PROVENANCE GRAPH
          </span>
          <span style={{ fontSize: '11px', color: 'var(--ink-muted)', fontFamily: 'var(--font-mono)' }}>
            EVIDENCE INTEGRITY CHAIN
          </span>
        </div>
        <ProvenanceGraphSvg darkTheme={false} activeFindingTitle={currentFinding.title} />
      </div>

      {/* SVG Connecting Flow Architecture */}
      <div
        style={{
          backgroundColor: 'var(--bg-surface)',
          border: '1px solid var(--rule-base)',
          borderRadius: 'var(--radius-sm)',
          padding: '28px 24px',
          boxShadow: 'var(--shadow-subtle)',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {nodes.map((node, i) => {
            const isLast = i === nodes.length - 1;
            return (
              <React.Fragment key={node.id}>
                <div
                  onClick={node.onClick}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '14px 18px',
                    backgroundColor: 'var(--bg-app)',
                    border: '1px solid var(--rule-subtle)',
                    borderLeft: `4px solid ${node.color}`,
                    borderRadius: 'var(--radius-xs)',
                    cursor: 'pointer',
                    transition: 'all var(--duration-micro) var(--ease-out)',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-subtle)')}
                  onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-app)')}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
                    <div
                      style={{
                        width: '32px',
                        height: '32px',
                        borderRadius: 'var(--radius-xs)',
                        backgroundColor: 'var(--bg-surface)',
                        border: '1px solid var(--rule-subtle)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      {node.icon}
                    </div>

                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                        <span
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 'var(--text-3xs)',
                            fontWeight: 700,
                            letterSpacing: '0.08em',
                            textTransform: 'uppercase',
                            color: 'var(--ink-muted)',
                          }}
                        >
                          Step 0{i + 1} · {node.label}
                        </span>
                        <span
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 'var(--text-3xs)',
                            fontWeight: 600,
                            padding: '1px 5px',
                            backgroundColor: 'var(--bg-surface)',
                            border: '1px solid var(--rule-subtle)',
                            borderRadius: 'var(--radius-xs)',
                            color: node.color,
                          }}
                        >
                          {node.badge}
                        </span>
                      </div>

                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--ink-primary)' }}>
                        {node.title}
                      </div>

                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--ink-secondary)', marginTop: '2px' }}>
                        {node.subtitle}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--ink-muted)', fontSize: 'var(--text-2xs)', fontFamily: 'var(--font-mono)' }}>
                    <span>Inspect</span>
                    <ChevronRight size={14} />
                  </div>
                </div>

                {!isLast && (
                  <div style={{ display: 'flex', justifyContent: 'center', margin: '-6px 0' }}>
                    <svg width="20" height="24" viewBox="0 0 20 24" fill="none" style={{ color: 'var(--rule-strong)' }}>
                      <line x1="10" y1="0" x2="10" y2="18" stroke="currentColor" strokeWidth="2" strokeDasharray="3 3" />
                      <polygon points="6,16 14,16 10,22" fill="currentColor" />
                    </svg>
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </div>
  );
};
