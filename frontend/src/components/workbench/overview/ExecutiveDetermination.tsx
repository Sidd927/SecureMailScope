import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, ExternalLink, GitBranch } from 'lucide-react';
import type { DashboardViewModel, FindingRow, SessionEvidence } from '../../../api/types';
import { CertaintyBadge } from '../../common/VocabularyBadges';
import { SeverityBadge } from '../../common/SeverityBadge';

interface ExecutiveDeterminationProps {
  dashboard: DashboardViewModel;
  primaryFinding?: FindingRow;
  sessions: SessionEvidence[];
  onOpenFinding?: (finding: FindingRow) => void;
  onOpenFrame?: (frame: number, streamKey?: string) => void;
  onTraceProvenance?: (finding?: FindingRow) => void;
}

export const ExecutiveDetermination: React.FC<ExecutiveDeterminationProps> = ({
  dashboard,
  primaryFinding,
  sessions,
  onOpenFinding,
  onOpenFrame,
  onTraceProvenance,
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
            {sessions.length} session{sessions.length === 1 ? '' : 's'} assessed · Compliant
          </span>
        )}
      </div>

      {/* Primary Investigation Actions */}
      {primaryFinding && (
        <div className="sms-determination-hero__actions">
          {onOpenFrame && primaryFinding.frames && primaryFinding.frames.length > 0 && (
            <button
              type="button"
              className="sms-btn sms-btn--primary sms-btn--sm"
              onClick={() => onOpenFrame(primaryFinding.frames[0], primaryFinding.stream_key || undefined)}
              title={`Jump directly to wire evidence Frame #${primaryFinding.frames[0]}`}
            >
              <ExternalLink size={13} aria-hidden="true" />
              <span>Open Frame #{primaryFinding.frames[0]}</span>
            </button>
          )}
          {onTraceProvenance && (
            <button
              type="button"
              className="sms-btn sms-btn--secondary sms-btn--sm"
              onClick={() => onTraceProvenance(primaryFinding)}
              title="Trace analytical provenance from packet to posture"
            >
              <GitBranch size={13} aria-hidden="true" />
              <span>Trace Provenance</span>
            </button>
          )}
          {onOpenFinding && (
            <button
              type="button"
              className="sms-btn sms-btn--ghost sms-btn--sm"
              onClick={() => onOpenFinding(primaryFinding)}
              title="Inspect comprehensive finding details"
            >
              <ShieldAlert size={13} aria-hidden="true" />
              <span>Inspect Finding ({ruleId || 'Detail'})</span>
            </button>
          )}
        </div>
      )}
    </article>
  );
};
