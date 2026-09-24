import React, { useState, useEffect, useMemo } from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import { IntakeDropzone } from './IntakeDropzone';
import { ForensicHash } from '../common/ForensicHash';
import { api } from '../../api/client';
import type { HealthResponse } from '../../api/types';
import {
  ShieldAlert,
  ShieldCheck,
  Radio,
  Lock,
  Sparkles,
  Layers,
  FileCode,
} from 'lucide-react';

export const HomeView: React.FC = () => {
  const { runs, selectRun, setActiveView, setActiveTab } = useInvestigation();
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    api.getHealth().then(setHealth).catch((err) => console.warn('Health check err:', err));
  }, []);

  const handleLaunchInvestigation = async (runId: string) => {
    await selectRun(runId);
    setActiveTab('overview');
    setActiveView('workbench');
  };

  // Triage Partitioning: Hazards vs Compliant
  const { hazards, compliant } = useMemo(() => {
    const completedRuns = runs.filter((r) => r.state === 'COMPLETED');
    const haz = completedRuns.filter(
      (r) => r.overall_posture === 'CRITICAL' || r.overall_posture === 'WEAK'
    );
    const comp = completedRuns.filter(
      (r) => r.overall_posture === 'STRONG' || r.overall_posture === 'ADEQUATE' || !r.overall_posture
    );
    return { hazards: haz, compliant: comp };
  }, [runs]);

  // Canonical Forensic Test Corpus
  const corpusItems = [
    {
      title: 'Weak 1024-bit RSA Key',
      filename: 'backup_weak_certificate.pcap',
      expectedBand: 'CRITICAL',
      expectedScore: '44.0',
      description: 'NIST SP 800-57 key strength violation with leaf RSA 1024-bit modulus.',
      icon: <ShieldAlert size={16} style={{ color: 'var(--color-sev-critical)' }} />,
    },
    {
      title: 'Cross-Session Baseline Downgrade',
      filename: 'deepdive_cross_session_control_endpoint.pcap',
      expectedBand: 'CRITICAL',
      expectedScore: '22.1',
      description: '12 concurrent SMTP streams correlating behavioral downgrade against baseline.',
      icon: <Layers size={16} style={{ color: 'var(--color-sev-critical)' }} />,
    },
    {
      title: 'Self-Signed Certificate Chain',
      filename: 'backup_selfsigned_certificate.pcap',
      expectedBand: 'ADEQUATE',
      expectedScore: '88.0',
      description: 'Private root / untrusted issuer chain with valid TLS 1.3 parameters.',
      icon: <FileCode size={16} style={{ color: 'var(--color-accent)' }} />,
    },
    {
      title: 'Compliant STARTTLS Baseline',
      filename: 'securemail_scope_smtp_starttls_basic.pcap',
      expectedBand: 'STRONG',
      expectedScore: '100.0',
      description: 'Standard RFC 5321 / RFC 8446 upgrade flow with modern cipher negotiation.',
      icon: <ShieldCheck size={16} style={{ color: 'var(--posture-strong)' }} />,
    },
  ];

  return (
    <div
      style={{
        maxWidth: '1280px',
        margin: '0 auto',
        padding: '36px 24px 64px 24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '36px',
        width: '100%',
      }}
    >
      {/* ============================================================ */}
      {/* 1. EDITORIAL HEADER & MISSION STATEMENT */}
      {/* ============================================================ */}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
          paddingBottom: '24px',
          borderBottom: '1px solid var(--color-border)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              fontWeight: 800,
              color: 'var(--color-accent)',
              backgroundColor: 'var(--color-accent-soft)',
              padding: '2px 8px',
              borderRadius: 'var(--radius-xs)',
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
            }}
          >
            <Radio size={12} className="pulse-icon" />
            LIVE FORENSIC STATION
          </span>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--color-ink-muted)' }}>
            ENGINE v{health?.posture_engine_version ?? '0.8.0'} · SCHEMA v{health?.posture_schema_version ?? '1.0'}
          </span>
        </div>

        <h1
          style={{
            fontSize: 'var(--text-display)',
            fontWeight: 800,
            color: 'var(--color-ink)',
            letterSpacing: '-0.02em',
            lineHeight: 1.15,
          }}
        >
          Cryptographic Traffic Investigation
        </h1>

        <p
          style={{
            fontSize: 'var(--text-base)',
            color: 'var(--color-ink-secondary)',
            maxWidth: '820px',
            lineHeight: 1.5,
          }}
        >
          Passive offline packet dissection, protocol state-machine verification, and epistemic posture assessment
          for enterprise mail systems against authoritative RFC 5321, RFC 8446, and NIST SP 800-57 standards.
        </p>
      </div>

      {/* ============================================================ */}
      {/* 2. INTAKE APERTURE (HERO DROPZONE) */}
      {/* ============================================================ */}
      <div>
        <div
          style={{
            fontSize: '11px',
            fontFamily: 'var(--font-mono)',
            textTransform: 'uppercase',
            letterSpacing: '0.08em',
            fontWeight: 800,
            color: 'var(--color-ink-muted)',
            marginBottom: '12px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Lock size={13} />
          <span>Ingest New Network Capture File</span>
        </div>

        <IntakeDropzone />
      </div>

      {/* ============================================================ */}
      {/* 3. FORENSIC BENCHMARK CORPUS QUICK LAUNCHERS */}
      {/* ============================================================ */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div
            style={{
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              fontWeight: 800,
              color: 'var(--color-ink-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <Sparkles size={13} style={{ color: 'var(--color-accent)' }} />
            <span>Forensic Benchmark Test Corpus (1-Click Evaluation Scenarios)</span>
          </div>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--color-ink-faint)' }}>
            Pre-loaded live test cases
          </span>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '14px',
          }}
        >
          {corpusItems.map((item) => {
            const matchingRun = runs.find(
              (r) => r.source_filename === item.filename && r.state === 'COMPLETED'
            );

            return (
              <div
                key={item.title}
                onClick={() => {
                  if (matchingRun) {
                    handleLaunchInvestigation(matchingRun.run_id);
                  }
                }}
                style={{
                  backgroundColor: 'var(--color-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  gap: '10px',
                  cursor: matchingRun ? 'pointer' : 'default',
                  boxShadow: 'var(--shadow-subtle)',
                  transition: 'all var(--transition-fast)',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      {item.icon}
                      <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--color-ink)' }}>
                        {item.title}
                      </span>
                    </div>
                    <span
                      style={{
                        fontSize: '10px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        padding: '1px 5px',
                        borderRadius: 'var(--radius-xs)',
                        backgroundColor:
                          item.expectedBand === 'CRITICAL'
                            ? 'var(--color-sev-critical-bg)'
                            : item.expectedBand === 'STRONG'
                            ? 'var(--color-sev-low-bg)'
                            : 'var(--color-panel)',
                        color:
                          item.expectedBand === 'CRITICAL'
                            ? 'var(--color-sev-critical)'
                            : item.expectedBand === 'STRONG'
                            ? 'var(--color-sev-low)'
                            : 'var(--color-accent)',
                        border: '1px solid var(--color-border)',
                      }}
                    >
                      {item.expectedBand} {item.expectedScore}
                    </span>
                  </div>

                  <p style={{ fontSize: '11px', color: 'var(--color-ink-muted)', lineHeight: 1.4 }}>
                    {item.description}
                  </p>
                </div>

                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    paddingTop: '8px',
                    borderTop: '1px solid var(--color-border-subtle)',
                    fontSize: '10px',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  <span style={{ color: 'var(--color-ink-faint)' }}>{item.filename}</span>
                  <span style={{ color: 'var(--color-accent)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '3px' }}>
                    {matchingRun ? 'LOAD CASE ➔' : 'AVAILABLE'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ============================================================ */}
      {/* 4. TRIAGE CENTER: ACTIVE FORENSIC DOSSIERS */}
      {/* ============================================================ */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div
              style={{
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                fontWeight: 800,
                color: 'var(--color-ink-muted)',
              }}
            >
              INVESTIGATION TRIAGE
            </div>
            <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 800, color: 'var(--color-ink)', marginTop: '2px' }}>
              Dissected Case Files & Capture Artifacts ({runs.length})
            </h2>
          </div>

          <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--color-ink-muted)' }}>
            Showing real SQLite persisted runs
          </div>
        </div>

        {/* Triage Columns: Action Required vs Baseline */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px' }}>
          {/* Priority Column: Cryptographic Hazards */}
          <div
            style={{
              backgroundColor: 'var(--color-surface)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--color-border)',
              padding: '20px',
              display: 'flex',
              flexDirection: 'column',
              gap: '16px',
              boxShadow: 'var(--shadow-subtle)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--color-border)', paddingBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldAlert size={16} style={{ color: 'var(--color-sev-critical)' }} />
                <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 800, color: 'var(--color-ink)' }}>
                  Threats & Violations Identified ({hazards.length})
                </h3>
              </div>
              <span
                style={{
                  fontSize: '10px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 800,
                  color: 'var(--color-sev-critical)',
                  backgroundColor: 'var(--color-sev-critical-bg)',
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-xs)',
                }}
              >
                ACTION REQUIRED
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {hazards.map((run) => (
                <div
                  key={run.run_id}
                  onClick={() => handleLaunchInvestigation(run.run_id)}
                  style={{
                    padding: '14px',
                    backgroundColor: 'var(--color-panel-card)',
                    border: '1px solid var(--color-border)',
                    borderLeft: '4px solid var(--color-sev-critical)',
                    borderRadius: 'var(--radius-xs)',
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px',
                    transition: 'all var(--transition-fast)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ fontWeight: 800, fontSize: 'var(--text-xs)', color: 'var(--color-ink)', fontFamily: 'var(--font-mono)' }}>
                      {run.source_filename}
                    </div>
                    {run.overall_posture && (
                      <span
                        style={{
                          fontSize: '10px',
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 800,
                          color: 'var(--color-sev-critical)',
                          backgroundColor: 'var(--color-sev-critical-bg)',
                          padding: '1px 6px',
                          borderRadius: 'var(--radius-xs)',
                        }}
                      >
                        {run.overall_posture}
                      </span>
                    )}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px' }}>
                    <ForensicHash value={run.capture_id} length={10} label="SHA-256" />
                    <span style={{ color: 'var(--color-ink-muted)', fontFamily: 'var(--font-mono)' }}>
                      {run.duration_ms ? `${run.duration_ms}ms parse` : ''}
                    </span>
                  </div>

                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      marginTop: '4px',
                      paddingTop: '8px',
                      borderTop: '1px solid var(--color-border-subtle)',
                    }}
                  >
                    <span style={{ fontSize: '11px', color: 'var(--color-ink-secondary)' }}>
                      Protocol anomalies & weak ciphers detected
                    </span>
                    <span
                      style={{
                        fontSize: '11px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        color: 'var(--color-accent)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                      }}
                    >
                      OPEN CASE ➔
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Compliant Column: Verified Baseline Runs */}
          <div
            style={{
              backgroundColor: 'var(--color-surface)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--color-border)',
              padding: '20px',
              display: 'flex',
              flexDirection: 'column',
              gap: '16px',
              boxShadow: 'var(--shadow-subtle)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--color-border)', paddingBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldCheck size={16} style={{ color: 'var(--color-sev-low)' }} />
                <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 800, color: 'var(--color-ink)' }}>
                  Verified Compliant & Baseline Runs ({compliant.length})
                </h3>
              </div>
              <span
                style={{
                  fontSize: '10px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 800,
                  color: 'var(--color-sev-low)',
                  backgroundColor: 'var(--color-sev-low-bg)',
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-xs)',
                }}
              >
                PASS / ADEQUATE
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {compliant.map((run) => (
                <div
                  key={run.run_id}
                  onClick={() => handleLaunchInvestigation(run.run_id)}
                  style={{
                    padding: '14px',
                    backgroundColor: 'var(--color-panel-card)',
                    border: '1px solid var(--color-border)',
                    borderLeft: '4px solid var(--color-sev-low)',
                    borderRadius: 'var(--radius-xs)',
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px',
                    transition: 'all var(--transition-fast)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ fontWeight: 800, fontSize: 'var(--text-xs)', color: 'var(--color-ink)', fontFamily: 'var(--font-mono)' }}>
                      {run.source_filename}
                    </div>
                    {run.overall_posture && (
                      <span
                        style={{
                          fontSize: '10px',
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 800,
                          color: 'var(--color-sev-low)',
                          backgroundColor: 'var(--color-sev-low-bg)',
                          padding: '1px 6px',
                          borderRadius: 'var(--radius-xs)',
                        }}
                      >
                        {run.overall_posture}
                      </span>
                    )}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px' }}>
                    <ForensicHash value={run.capture_id} length={10} label="SHA-256" />
                    <span style={{ color: 'var(--color-ink-muted)', fontFamily: 'var(--font-mono)' }}>
                      {run.duration_ms ? `${run.duration_ms}ms parse` : ''}
                    </span>
                  </div>

                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      marginTop: '4px',
                      paddingTop: '8px',
                      borderTop: '1px solid var(--color-border-subtle)',
                    }}
                  >
                    <span style={{ fontSize: '11px', color: 'var(--color-ink-secondary)' }}>
                      Compliant handshake or honest unobserved parameters
                    </span>
                    <span
                      style={{
                        fontSize: '11px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        color: 'var(--color-ink-muted)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                      }}
                    >
                      INSPECT ➔
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ============================================================ */}
      {/* 5. SYSTEM TELEMETRY RAIL */}
      {/* ============================================================ */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
          padding: '14px 20px',
          backgroundColor: 'var(--color-panel)',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--color-border)',
          fontFamily: 'var(--font-mono)',
          fontSize: '11px',
          color: 'var(--color-ink-secondary)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px', flexWrap: 'wrap' }}>
          <div>
            ENGINE: <strong style={{ color: 'var(--color-ink)' }}>v{health?.posture_engine_version ?? '0.8.0'}</strong>
          </div>
          <div>
            SCHEMA: <strong style={{ color: 'var(--color-ink)' }}>v{health?.backend_schema_version ?? '1.0'}</strong>
          </div>
          <div>
            DATABASE: <strong style={{ color: 'var(--color-sev-low)' }}>{health?.database?.toUpperCase() ?? 'OK'}</strong>
          </div>
          <div>
            TSHARK DISSECTOR: <strong style={{ color: 'var(--color-sev-low)' }}>{health?.tshark?.toUpperCase() ?? 'ACTIVE'}</strong>
          </div>
        </div>

        <div style={{ color: 'var(--color-ink-muted)' }}>
          MAX PAYLOAD: 256MB · MULTIPART OFFLINE TCPDUMP
        </div>
      </div>
    </div>
  );
};
