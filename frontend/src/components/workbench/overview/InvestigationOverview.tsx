import React from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { SeverityBadge } from '../../common/SeverityBadge';
import {
  ShieldCheck,
  ArrowRight,
  Calculator,
  Compass,
  Network,
  Layers,
  Database,
} from 'lucide-react';

interface InvestigationOverviewProps {
  onOpenScoreModal: () => void;
}

export const InvestigationOverview: React.FC<InvestigationOverviewProps> = ({ onOpenScoreModal }) => {
  const {
    activeRun,
    dashboard,
    sessions,
    selectedSession,
    selectFinding,
    selectSession,
    selectEventFrame,
    setActiveTab,
  } = useInvestigation();

  if (!dashboard || !activeRun) {
    return (
      <div style={{ padding: '60px 40px', textAlign: 'center', color: 'var(--color-ink-muted)' }}>
        Loading investigation overview...
      </div>
    );
  }

  const { posture, coverage, findings } = dashboard;
  const primaryFinding = findings && findings.length > 0 ? findings[0] : null;

  // Compute coverage fractions
  const obsCounts = coverage?.observation_counts || {
    OBSERVED: 0,
    INFERRED: 0,
    AMBIGUOUS: 0,
    UNKNOWN: 0,
    INCOMPLETE: 0,
    NOT_OBSERVABLE: 0,
  };
  const totalObs = Object.values(obsCounts).reduce((a, b) => a + b, 0) || 1;
  const pctObserved = Math.round(((obsCounts.OBSERVED || 0) / totalObs) * 100);
  const pctInferred = Math.round(((obsCounts.INFERRED || 0) / totalObs) * 100);
  const pctAmbiguous = Math.round(((obsCounts.AMBIGUOUS || 0) / totalObs) * 100);
  const pctNotObservable = Math.round(((obsCounts.NOT_OBSERVABLE || 0) / totalObs) * 100);
  const pctOther = Math.max(0, 100 - (pctObserved + pctInferred + pctAmbiguous + pctNotObservable));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '32px', width: '100%', paddingBottom: '60px' }}>
      {/* 1. EXECUTIVE POSTURE VERDICT BLOCK */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(320px, 1.4fr) minmax(280px, 1fr)',
          gap: '24px',
          padding: '24px 28px',
          backgroundColor: 'var(--color-surface)',
          border: '1px solid var(--color-border)',
          borderRadius: 'var(--radius-md)',
          boxShadow: 'var(--shadow-subtle)',
        }}
      >
        {/* Left: Authoritative Verdict */}
        <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px' }}>
          <div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                color: 'var(--color-ink-muted)',
                marginBottom: '8px',
              }}
            >
              <Compass size={13} style={{ color: 'var(--color-accent)' }} />
              <span>Cryptographic Posture Assessment Verdict</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'baseline', gap: '16px', marginBottom: '8px' }}>
              <span
                style={{
                  fontSize: '28px',
                  fontWeight: 800,
                  letterSpacing: '-0.02em',
                  color:
                    posture.value === 'CRITICAL'
                      ? 'var(--color-sev-critical)'
                      : posture.value === 'STRONG'
                      ? 'var(--posture-strong)'
                      : 'var(--color-ink)',
                }}
              >
                {posture.value}
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-ink)' }}>
                {posture.score_value !== null ? posture.score_value.toFixed(1) : '—'}
                <span style={{ fontSize: '14px', color: 'var(--color-ink-muted)', fontWeight: 500 }}> / 100</span>
              </span>
            </div>

            <p
              style={{
                fontSize: 'var(--text-base)',
                lineHeight: 1.5,
                color: 'var(--color-ink-secondary)',
                maxWidth: '680px',
              }}
            >
              {posture.basis ||
                (findings.length > 0
                  ? `${findings.length} cryptographic finding(s) materially impact the verified security posture.`
                  : 'Traffic exhibits compliant cryptographic posture with verified cipher negotiation.')}
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', paddingTop: '8px' }}>
            <button
              type="button"
              onClick={onOpenScoreModal}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 12px',
                backgroundColor: 'var(--color-panel)',
                border: '1px solid var(--color-border-strong)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                fontWeight: 600,
                color: 'var(--color-ink)',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)',
              }}
            >
              <Calculator size={13} />
              <span>Inspect Deterministic Calculus ({posture.components?.length || 0} penalties) ➔</span>
            </button>
            <span style={{ fontSize: '11px', color: 'var(--color-ink-faint)', fontFamily: 'var(--font-mono)' }}>
              Formula: {posture.formula_id || 'f2-group-damped'}
            </span>
          </div>
        </div>

        {/* Right: Epistemic Evidence Coverage Breakdown */}
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            paddingLeft: '24px',
            borderLeft: '1px solid var(--color-border-subtle)',
          }}
        >
          <div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                color: 'var(--color-ink-muted)',
                marginBottom: '10px',
              }}
            >
              <span>Evidence Coverage & Observability</span>
              <span style={{ fontWeight: 700, color: 'var(--color-ink)' }}>{coverage.percent_text}</span>
            </div>

            {/* Stacked Coverage Bar */}
            <div
              style={{
                display: 'flex',
                height: '10px',
                width: '100%',
                borderRadius: 'var(--radius-xs)',
                overflow: 'hidden',
                backgroundColor: 'var(--color-panel)',
                marginBottom: '14px',
              }}
            >
              {pctObserved > 0 && (
                <div
                  title={`Observed: ${pctObserved}% (${obsCounts.OBSERVED} fields)`}
                  style={{ width: `${pctObserved}%`, backgroundColor: '#111827' }}
                />
              )}
              {pctInferred > 0 && (
                <div
                  title={`Inferred: ${pctInferred}% (${obsCounts.INFERRED} fields)`}
                  style={{ width: `${pctInferred}%`, backgroundColor: '#3b82f6' }}
                />
              )}
              {pctAmbiguous > 0 && (
                <div
                  title={`Ambiguous: ${pctAmbiguous}% (${obsCounts.AMBIGUOUS} fields)`}
                  style={{ width: `${pctAmbiguous}%`, backgroundColor: '#ca8a04' }}
                />
              )}
              {pctNotObservable > 0 && (
                <div
                  title={`Not Observable: ${pctNotObservable}% (${obsCounts.NOT_OBSERVABLE} fields)`}
                  style={{ width: `${pctNotObservable}%`, backgroundColor: '#9ca3af' }}
                />
              )}
              {pctOther > 0 && (
                <div
                  title={`Other: ${pctOther}%`}
                  style={{ width: `${pctOther}%`, backgroundColor: '#e5e7eb' }}
                />
              )}
            </div>

            {/* Coverage Legend Grid */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: '8px',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '1px', backgroundColor: '#111827' }} />
                <span style={{ color: 'var(--color-ink-muted)' }}>Observed:</span>
                <span style={{ fontWeight: 600, color: 'var(--color-ink)' }}>{obsCounts.OBSERVED || 0}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '1px', backgroundColor: '#3b82f6' }} />
                <span style={{ color: 'var(--color-ink-muted)' }}>Inferred:</span>
                <span style={{ fontWeight: 600, color: 'var(--color-ink)' }}>{obsCounts.INFERRED || 0}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '1px', backgroundColor: '#ca8a04' }} />
                <span style={{ color: 'var(--color-ink-muted)' }}>Ambiguous:</span>
                <span style={{ fontWeight: 600, color: 'var(--color-ink)' }}>{obsCounts.AMBIGUOUS || 0}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '1px', backgroundColor: '#9ca3af' }} />
                <span style={{ color: 'var(--color-ink-muted)' }}>Not Observable:</span>
                <span style={{ fontWeight: 600, color: 'var(--color-ink)' }}>{obsCounts.NOT_OBSERVABLE || 0}</span>
              </div>
            </div>
          </div>

          <div
            style={{
              paddingTop: '12px',
              fontSize: '11px',
              color: 'var(--color-ink-faint)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <span>Assessed {coverage.sessions_assessed || 1} of {coverage.sessions_total || 1} stream session(s)</span>
            <span
              onClick={() => setActiveTab('evidence')}
              style={{ color: 'var(--color-accent)', cursor: 'pointer', fontWeight: 600 }}
            >
              View Ledger ➔
            </span>
          </div>
        </div>
      </div>

      {/* 2. SIGNATURE VISUAL EVIDENCE GRAPH / PROVENANCE CHAIN */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div
            style={{
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              fontWeight: 700,
              color: 'var(--color-ink-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <Layers size={13} style={{ color: 'var(--color-accent)' }} />
            <span>Interactive Forensic Provenance Chain (Traceability Flow)</span>
          </div>
          <span style={{ fontSize: '11px', color: 'var(--color-ink-faint)', fontFamily: 'var(--font-mono)' }}>
            Click any node in the chain to pivot investigation context
          </span>
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '16px 20px',
            backgroundColor: 'var(--color-panel)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-md)',
            overflowX: 'auto',
          }}
        >
          {/* Node 1: Capture File */}
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '2px',
              padding: '8px 12px',
              backgroundColor: '#ffffff',
              border: '1px solid var(--color-border-strong)',
              borderRadius: 'var(--radius-sm)',
              minWidth: '150px',
            }}
          >
            <div style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--color-ink-faint)', textTransform: 'uppercase' }}>
              1. Ingested PCAP
            </div>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--color-ink)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {activeRun.source_filename}
            </div>
          </div>

          <ArrowRight size={14} style={{ color: 'var(--color-ink-faint)', flexShrink: 0 }} />

          {/* Node 2: Selected Session */}
          <div
            onClick={() => setActiveTab('timeline')}
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '2px',
              padding: '8px 12px',
              backgroundColor: '#ffffff',
              border: '1px solid var(--color-accent-border)',
              borderRadius: 'var(--radius-sm)',
              minWidth: '160px',
              cursor: 'pointer',
              transition: 'all var(--transition-fast)',
            }}
          >
            <div style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--color-accent)', textTransform: 'uppercase', fontWeight: 600 }}>
              2. Dissected Stream
            </div>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--color-ink)', fontFamily: 'var(--font-mono)' }}>
              #{selectedSession?.tcp_stream_id ?? 0} {selectedSession?.protocol ?? 'SMTP'} ({selectedSession?.timing.packet_count ?? 0} pkts)
            </div>
          </div>

          <ArrowRight size={14} style={{ color: 'var(--color-ink-faint)', flexShrink: 0 }} />

          {/* Node 3: Protocol Frame / Event */}
          <div
            onClick={() => {
              setActiveTab('timeline');
              if (primaryFinding && primaryFinding.frames.length > 0) {
                selectEventFrame(primaryFinding.frames[0]);
              }
            }}
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '2px',
              padding: '8px 12px',
              backgroundColor: '#ffffff',
              border: '1px solid var(--color-border-strong)',
              borderRadius: 'var(--radius-sm)',
              minWidth: '140px',
              cursor: 'pointer',
            }}
          >
            <div style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--color-ink-faint)', textTransform: 'uppercase' }}>
              3. Handshake Frame
            </div>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--color-ink)', fontFamily: 'var(--font-mono)' }}>
              {primaryFinding && primaryFinding.frames.length > 0
                ? `Frame #${primaryFinding.frames.join(', #')}`
                : 'Frame #1-14'}
            </div>
          </div>

          <ArrowRight size={14} style={{ color: 'var(--color-ink-faint)', flexShrink: 0 }} />

          {/* Node 4: Cryptographic Entity (Cert / Cipher) */}
          <div
            onClick={() => setActiveTab('certs')}
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '2px',
              padding: '8px 12px',
              backgroundColor: '#ffffff',
              border: '1px solid var(--color-border-strong)',
              borderRadius: 'var(--radius-sm)',
              minWidth: '150px',
              cursor: 'pointer',
            }}
          >
            <div style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--color-ink-faint)', textTransform: 'uppercase' }}>
              4. PKI / Cipher Entity
            </div>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--color-ink)' }}>
              {selectedSession?.certificates && selectedSession.certificates.length > 0
                ? `RSA ${selectedSession.certificates[0].key_bits || 1024}-bit Leaf`
                : 'TLS Handshake'}
            </div>
          </div>

          <ArrowRight size={14} style={{ color: 'var(--color-ink-faint)', flexShrink: 0 }} />

          {/* Node 5: Primary Finding */}
          <div
            onClick={() => {
              if (primaryFinding) selectFinding(primaryFinding);
            }}
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '2px',
              padding: '8px 12px',
              backgroundColor:
                primaryFinding?.severity === 'CRITICAL' || primaryFinding?.severity === 'HIGH'
                  ? 'var(--color-sev-critical-bg)'
                  : '#ffffff',
              border: `1px solid ${
                primaryFinding?.severity === 'CRITICAL' || primaryFinding?.severity === 'HIGH'
                  ? 'var(--color-sev-critical-border)'
                  : 'var(--color-border-strong)'
              }`,
              borderRadius: 'var(--radius-sm)',
              minWidth: '180px',
              cursor: 'pointer',
            }}
          >
            <div
              style={{
                fontSize: '10px',
                fontFamily: 'var(--font-mono)',
                color:
                  primaryFinding?.severity === 'CRITICAL' || primaryFinding?.severity === 'HIGH'
                    ? 'var(--color-sev-critical)'
                    : 'var(--color-ink-faint)',
                textTransform: 'uppercase',
                fontWeight: 600,
              }}
            >
              5. Detected Finding
            </div>
            <div
              style={{
                fontSize: '12px',
                fontWeight: 700,
                color: 'var(--color-ink)',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              {primaryFinding ? primaryFinding.title : 'Compliant Protocol'}
            </div>
          </div>

          <ArrowRight size={14} style={{ color: 'var(--color-ink-faint)', flexShrink: 0 }} />

          {/* Node 6: Posture Impact */}
          <div
            onClick={onOpenScoreModal}
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '2px',
              padding: '8px 12px',
              backgroundColor: '#ffffff',
              border: '1px solid var(--color-border-strong)',
              borderRadius: 'var(--radius-sm)',
              minWidth: '140px',
              cursor: 'pointer',
            }}
          >
            <div style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--color-ink-faint)', textTransform: 'uppercase' }}>
              6. Calculus Impact
            </div>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--color-sev-critical)', fontFamily: 'var(--font-mono)' }}>
              -{posture.total_penalty?.toFixed(1) || '0.0'} pts deduction
            </div>
          </div>
        </div>
      </div>

      {/* 3. KEY FINDINGS ACTION DECK (CONCLUSION FIRST) */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h3 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--color-ink)' }}>
              Identified Cryptographic Deviations & Findings ({findings.length})
            </h3>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-ink-muted)' }}>
              Authoritative deductions from passive packet dissection against RFC 5321, RFC 8446, and NIST SP 800-57.
            </p>
          </div>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--color-ink-faint)' }}>
            SORTED BY DETERMINISTIC IMPACT
          </span>
        </div>

        {findings.length === 0 ? (
          <div
            style={{
              padding: '36px',
              backgroundColor: 'var(--color-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-md)',
              textAlign: 'center',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            <ShieldCheck size={28} style={{ color: 'var(--posture-strong)' }} />
            <div style={{ fontSize: 'var(--text-md)', fontWeight: 700, color: 'var(--color-ink)' }}>
              Zero Security Deviations Detected
            </div>
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--color-ink-muted)', maxWidth: '480px' }}>
              This capture conforms to cryptographic standards with acceptable key lengths, modern cipher parameters, and compliant state transitions.
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {findings.map((f, index) => {
              const isHigh = f.severity === 'CRITICAL' || f.severity === 'HIGH';
              const numStr = String(index + 1).padStart(2, '0');
              const citation = f.citations && f.citations.length > 0 ? f.citations[0] : null;

              return (
                <div
                  key={f.title + index}
                  style={{
                    backgroundColor: 'var(--color-surface)',
                    border: `1px solid ${isHigh ? 'var(--color-sev-critical-border)' : 'var(--color-border)'}`,
                    borderRadius: 'var(--radius-md)',
                    borderLeft: `4px solid ${isHigh ? 'var(--color-sev-critical)' : 'var(--color-accent)'}`,
                    padding: '18px 22px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '12px',
                    boxShadow: 'var(--shadow-subtle)',
                    transition: 'border-color var(--transition-fast)',
                  }}
                >
                  {/* Top Bar: Index + Severity + Action Button */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <span
                        style={{
                          fontSize: '12px',
                          fontWeight: 700,
                          fontFamily: 'var(--font-mono)',
                          color: 'var(--color-ink-muted)',
                        }}
                      >
                        {numStr}
                      </span>
                      <SeverityBadge severity={f.severity} size="sm" />
                      <h4
                        style={{
                          fontSize: 'var(--text-md)',
                          fontWeight: 700,
                          color: 'var(--color-ink)',
                          letterSpacing: '-0.01em',
                        }}
                      >
                        {f.title}
                      </h4>
                    </div>

                    <button
                      type="button"
                      onClick={() => selectFinding(f)}
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        padding: '6px 14px',
                        backgroundColor: isHigh ? 'var(--color-sev-critical-bg)' : 'var(--color-panel)',
                        border: `1px solid ${isHigh ? 'var(--color-sev-critical-border)' : 'var(--color-border-strong)'}`,
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '11px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        color: isHigh ? 'var(--color-sev-critical)' : 'var(--color-accent)',
                        cursor: 'pointer',
                        transition: 'all var(--transition-fast)',
                      }}
                    >
                      <span>INSPECT EVIDENCE DOSSIER ➔</span>
                    </button>
                  </div>

                  {/* Plain-English Conclusion & Why it Matters */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--color-ink)' }}>
                      {f.conclusion || f.explanation}
                    </div>
                    {f.remediation?.why_it_matters && (
                      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--color-ink-muted)', lineHeight: 1.5 }}>
                        <strong>Why it matters:</strong> {f.remediation.why_it_matters}
                      </div>
                    )}
                  </div>

                  {/* Provenance Footnote: Stream, Frame, Standard */}
                  <div
                    style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      alignItems: 'center',
                      gap: '16px',
                      paddingTop: '8px',
                      borderTop: '1px solid var(--color-border-subtle)',
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--color-ink-faint)',
                    }}
                  >
                    <span>
                      Stream: <strong style={{ color: 'var(--color-ink)' }}>#{f.tcp_stream_id ?? 0}</strong>
                    </span>
                    {f.frames.length > 0 && (
                      <span>
                        Frame(s):{' '}
                        <strong
                          onClick={() => {
                            setActiveTab('timeline');
                            selectEventFrame(f.frames[0]);
                          }}
                          style={{ color: 'var(--color-accent)', cursor: 'pointer', textDecoration: 'underline' }}
                        >
                          #{f.frames.join(', #')}
                        </strong>
                      </span>
                    )}
                    {citation && (
                      <span>
                        Authoritative Standard:{' '}
                        <strong style={{ color: 'var(--color-ink-secondary)' }}>
                          {citation.standard} {citation.section ? `§${citation.section}` : ''}
                        </strong>
                      </span>
                    )}
                    {f.factors && f.factors.severity !== undefined && (
                      <span>
                        Calculus Factor: <strong style={{ color: 'var(--color-ink)' }}>{f.factors.severity} sev</strong>
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 4. STREAM ARCHITECTURE & CROSS-SESSION BASELINE */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(280px, 1fr) minmax(280px, 1fr)',
          gap: '20px',
        }}
      >
        {/* Stream Distribution Summary */}
        <div
          style={{
            padding: '20px',
            backgroundColor: 'var(--color-surface)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-md)',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Network size={16} style={{ color: 'var(--color-accent)' }} />
            <h4 style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-ink)' }}>
              Dissected Stream Inventory ({sessions.length})
            </h4>
          </div>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-ink-muted)' }}>
            Multi-stream forensic grouping by TCP conversation and application protocol layer.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {sessions.slice(0, 3).map((s) => (
              <div
                key={s.stream_key}
                onClick={() => {
                  selectSession(s.stream_key);
                  setActiveTab('timeline');
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 12px',
                  backgroundColor: 'var(--color-panel)',
                  borderRadius: 'var(--radius-xs)',
                  border: '1px solid var(--color-border)',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  cursor: 'pointer',
                }}
              >
                <span style={{ fontWeight: 600, color: 'var(--color-ink)' }}>
                  #{s.tcp_stream_id} {s.protocol}: {s.client.ip}:{s.client.port} → {s.server.ip}:{s.server.port}
                </span>
                <span style={{ color: 'var(--color-accent)', fontWeight: 700 }}>Inspect ➔</span>
              </div>
            ))}
            {sessions.length > 3 && (
              <div
                onClick={() => setActiveTab('timeline')}
                style={{
                  textAlign: 'center',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--color-accent)',
                  cursor: 'pointer',
                  paddingTop: '4px',
                }}
              >
                + {sessions.length - 3} more stream sessions in Protocol Journey
              </div>
            )}
          </div>
        </div>

        {/* Cross-Session Baseline Comparison */}
        <div
          style={{
            padding: '20px',
            backgroundColor: 'var(--color-surface)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-md)',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Database size={16} style={{ color: 'var(--color-accent)' }} />
            <h4 style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-ink)' }}>
              Cross-Session Behavioral Baseline
            </h4>
          </div>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-ink-muted)' }}>
            Comparing current observed cryptographic behavior against endpoint historical expectations.
          </p>
          <div
            style={{
              padding: '12px',
              backgroundColor: 'var(--color-panel)',
              borderRadius: 'var(--radius-xs)',
              border: '1px solid var(--color-border)',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--color-ink-muted)' }}>
                Baseline Status:
              </span>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--color-ink)' }}>
                {sessions.length > 1 ? 'MULTI-SESSION CORRELATED' : 'SINGLE STREAM OBSERVED'}
              </span>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--color-ink-secondary)', lineHeight: 1.4 }}>
              {sessions.length > 1
                ? `Cross-session reasoning active across ${sessions.length} sessions. Cryptographic capabilities and downgrade anomalies correlated across endpoints.`
                : 'Isolated stream capture. Epistemic determinations based strictly on passive evidence within this conversation.'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
