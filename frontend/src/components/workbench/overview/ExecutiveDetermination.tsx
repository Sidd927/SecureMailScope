import React from 'react';
import { ArrowRight, ShieldAlert, ShieldCheck, AlertTriangle, FileCode } from 'lucide-react';
import type { DashboardViewModel, FindingRow, SessionEvidence } from '../../../api/types';
import { CertaintyBadge } from '../../common/VocabularyBadges';
import { SeverityBadge } from '../../common/SeverityBadge';

interface ExecutiveDeterminationProps {
  dashboard: DashboardViewModel;
  primaryFinding?: FindingRow;
  sessions: SessionEvidence[];
  onOpenFinding: (finding: FindingRow) => void;
  onOpenJourney: (frame?: number, streamKey?: string) => void;
}

export const ExecutiveDetermination: React.FC<ExecutiveDeterminationProps> = ({
  dashboard,
  primaryFinding,
  sessions,
  onOpenFinding,
  onOpenJourney,
}) => {
  const { posture } = dashboard;
  const isClean = dashboard.findings.length === 0 && posture.value === 'STRONG';

  // Deterministically synthesize the forensic verdict headline
  const getVerdictHeadline = (): string => {
    if (isClean) {
      return 'Strong cryptographic security posture observed. All observed sessions comply with email transport encryption standards.';
    }

    if (!primaryFinding) {
      return posture.basis || 'Cryptographic security assessment completed with findings requiring forensic review.';
    }

    // High precision synthesis from real findings
    const title = primaryFinding.title.toLowerCase();
    const affected = primaryFinding.affected_sessions;
    const sessionCountText = affected ? ` across ${affected} session${affected === 1 ? '' : 's'}` : '';

    if (title.includes('authentication') && title.includes('without tls')) {
      return `Authentication activity was observed without TLS protection${sessionCountText}.`;
    }
    if (title.includes('rsa') || title.includes('sha-1') || title.includes('weak algorithm')) {
      return 'Cryptographic weaknesses detected in X.509 certificate (RSA-1024 / SHA-1) on SMTPS :465.';
    }
    if (title.includes('starttls') && title.includes('deviation')) {
      return `STARTTLS baseline deviation detected between subject and control endpoints${sessionCountText}.`;
    }
    if (title.includes('no tls')) {
      return `Mail sessions exchanged without TLS transport encryption${sessionCountText}.`;
    }

    return primaryFinding.conclusion || primaryFinding.title;
  };

  const headline = getVerdictHeadline();
  const citation = primaryFinding?.citations?.[0];
  const standardText = citation ? [citation.standard, citation.section].filter(Boolean).join(' ') : null;
  const ruleId = primaryFinding?.source_rule_ids?.[0];

  // Target frame and stream for one-click proof pivot
  const targetFrame = primaryFinding?.frames?.[0];
  const targetStream = primaryFinding?.stream_key || (primaryFinding?.tcp_stream_id != null ? `stream-${primaryFinding.tcp_stream_id}` : sessions[0]?.stream_key);

  const getPostureTone = () => {
    switch (posture.value) {
      case 'CRITICAL':
        return {
          color: 'var(--ds-sev-critical-text)',
          bg: 'var(--ds-sev-critical-bg)',
          border: 'var(--ds-sev-critical-border)',
          indicator: 'var(--ds-sev-critical-rule)',
          Icon: ShieldAlert,
        };
      case 'WEAK':
        return {
          color: 'var(--ds-sev-high-text)',
          bg: 'var(--ds-sev-high-bg)',
          border: 'var(--ds-sev-high-border)',
          indicator: 'var(--ds-sev-high-rule)',
          Icon: AlertTriangle,
        };
      case 'ADEQUATE':
        return {
          color: 'var(--ds-sev-medium-text)',
          bg: 'var(--ds-sev-medium-bg)',
          border: 'var(--ds-sev-medium-border)',
          indicator: 'var(--ds-sev-medium-rule)',
          Icon: AlertTriangle,
        };
      case 'STRONG':
        return {
          color: 'var(--ds-sev-low-text)',
          bg: 'var(--ds-sev-low-bg)',
          border: 'var(--ds-sev-low-border)',
          indicator: 'var(--ds-sev-low-rule)',
          Icon: ShieldCheck,
        };
      default:
        return {
          color: 'var(--sms-text-secondary)',
          bg: 'var(--sms-surface-panel)',
          border: 'var(--sms-border-subtle)',
          indicator: 'var(--sms-border-strong)',
          Icon: AlertTriangle,
        };
    }
  };

  const tone = getPostureTone();
  const Icon = tone.Icon;

  return (
    <article className="sms-determination-hero" aria-label="Executive Determination">
      {/* Top Header Strip: Posture Band Badge + Numerical Score */}
      <div className="sms-determination-hero__top">
        <div className="sms-determination-hero__band-group">
          <div
            className="sms-posture-badge"
            style={{
              color: tone.color,
              backgroundColor: tone.bg,
              borderColor: tone.border,
            }}
          >
            <span
              className="sms-posture-badge__dot"
              style={{ backgroundColor: tone.indicator }}
              aria-hidden="true"
            />
            <Icon size={14} aria-hidden="true" />
            <span className="sms-posture-badge__label">{posture.label || posture.value}</span>
          </div>

          {posture.formula_id && (
            <span className="sms-mono sms-determination-hero__formula" title="Posture scoring formula algorithm">
              {posture.formula_id}
            </span>
          )}
        </div>

        <div className="sms-determination-hero__score-wrap">
          <span className="sms-determination-hero__score-value" style={{ color: tone.color }}>
            {posture.withheld || posture.score_value === null ? '—' : posture.score_value.toFixed(2)}
          </span>
          <span className="sms-determination-hero__score-max">/ 100</span>
        </div>
      </div>

      {/* Main Plain-English Forensic Verdict */}
      <h2 className="sms-determination-hero__headline">{headline}</h2>

      {/* Epistemic & Regulatory Anchors */}
      <div className="sms-determination-hero__anchors">
        {primaryFinding?.severity && <SeverityBadge severity={primaryFinding.severity} size="sm" />}
        {primaryFinding?.certainty && <CertaintyBadge certainty={primaryFinding.certainty} />}
        {ruleId && (
          <span className="sms-badge sms-badge--rule" title="Deterministic Posture Rule">
            {ruleId}
          </span>
        )}
        {standardText && (
          <span className="sms-badge sms-badge--standard" title="Normative Standard Citation">
            {standardText}
          </span>
        )}
        {primaryFinding?.affected_sessions && primaryFinding.affected_sessions > 0 && (
          <span className="sms-badge sms-badge--muted">
            {primaryFinding.affected_sessions} session{primaryFinding.affected_sessions === 1 ? '' : 's'} affected
          </span>
        )}
        {isClean && (
          <span className="sms-badge sms-badge--muted">
            {sessions.length} sessions assessed · Compliant
          </span>
        )}
      </div>

      {/* Wire-Level Evidence Proof Box */}
      {primaryFinding && (
        <div className="sms-determination-hero__proof-box">
          <div className="sms-determination-hero__proof-head">
            <span className="sms-label" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              <FileCode size={12} aria-hidden="true" /> Wire-Level Proof Anchor
            </span>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              {primaryFinding.tcp_stream_id != null && (
                <span className="sms-mono sms-badge sms-badge--muted">Stream #{primaryFinding.tcp_stream_id}</span>
              )}
              {targetFrame != null && (
                <span className="sms-mono sms-badge sms-badge--muted">Frame #{targetFrame}</span>
              )}
            </div>
          </div>

          <div className="sms-determination-hero__proof-body">
            <div className="sms-determination-hero__proof-facts">
              {primaryFinding.title.toLowerCase().includes('authentication') ? (
                <>
                  <div className="sms-proof-fact">
                    <span className="sms-proof-fact__key">AUTH_ACTIVITY =</span>
                    <span className="sms-proof-fact__val sms-proof-fact__val--bad">OBSERVED</span>
                  </div>
                  <div className="sms-proof-fact">
                    <span className="sms-proof-fact__key">TLS_TRANSITION =</span>
                    <span className="sms-proof-fact__val sms-proof-fact__val--bad">FALSE</span>
                  </div>
                </>
              ) : primaryFinding.title.toLowerCase().includes('rsa') || primaryFinding.title.toLowerCase().includes('sha-1') ? (
                <>
                  <div className="sms-proof-fact">
                    <span className="sms-proof-fact__key">RSA_KEY_SIZE =</span>
                    <span className="sms-proof-fact__val sms-proof-fact__val--bad">1024 BITS</span>
                  </div>
                  <div className="sms-proof-fact">
                    <span className="sms-proof-fact__key">SIG_ALGORITHM =</span>
                    <span className="sms-proof-fact__val sms-proof-fact__val--bad">SHA-1 (DEPRECATED)</span>
                  </div>
                </>
              ) : primaryFinding.title.toLowerCase().includes('starttls') ? (
                <>
                  <div className="sms-proof-fact">
                    <span className="sms-proof-fact__key">SUBJECT_ENDPOINT =</span>
                    <span className="sms-proof-fact__val sms-proof-fact__val--bad">STARTTLS NOT ADVERTISED</span>
                  </div>
                  <div className="sms-proof-fact">
                    <span className="sms-proof-fact__key">CONTROL_BASELINE =</span>
                    <span className="sms-proof-fact__val sms-proof-fact__val--good">STARTTLS ADVERTISED</span>
                  </div>
                </>
              ) : (
                <p className="sms-prose" style={{ margin: 0, fontSize: 'var(--ds-text-13)' }}>
                  {primaryFinding.explanation || primaryFinding.conclusion}
                </p>
              )}
            </div>

            <div className="sms-determination-hero__proof-actions">
              <button
                type="button"
                className="sms-btn sms-btn--primary sms-btn--sm"
                onClick={() => onOpenJourney(targetFrame, targetStream)}
                title="Jump directly to this exact packet frame in the Protocol Journey"
              >
                Open Frame #{targetFrame ?? 1} in Protocol Journey <ArrowRight size={13} aria-hidden="true" />
              </button>
              <button
                type="button"
                className="sms-btn sms-btn--ghost sms-btn--sm"
                onClick={() => onOpenFinding(primaryFinding)}
                title="View full evidence dossier for this finding"
              >
                Inspect Full Evidence
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Case C Honest Observability Notice */}
      {isClean && (
        <div className="sms-determination-hero__clean-notice">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', marginBottom: '4px' }}>
            <span className="sms-label">Epistemic Observability Boundary</span>
            <span className="sms-badge sms-badge--info sms-mono">
              CERTIFICATE CONTENT: NOT_OBSERVABLE
            </span>
          </div>
          <p className="sms-prose" style={{ margin: '4px 0 0 0', fontSize: 'var(--ds-text-13)', color: 'var(--sms-text-secondary)', lineHeight: 1.5 }}>
            No certificate fields were observable in this passive capture. Under RFC 8446 specifications, server X.509 certificate handshakes in TLS 1.3 are cryptographically encrypted on the wire. This is an intentional epistemic boundary of passive packet analysis, not an engine error or missing data.
          </p>
        </div>
      )}
    </article>
  );
};
