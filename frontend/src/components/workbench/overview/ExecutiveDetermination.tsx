import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, GitBranch } from 'lucide-react';
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
      return 'TLS on every observed session. No plaintext credentials on the wire.';
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
  const scoreText = posture.withheld || posture.score_value === null ? '—' : posture.score_value.toFixed(2);
  const others = dashboard.findings.filter((f) => f !== primaryFinding);
  const sevColor = (severity: string | null) => {
    if (severity === 'CRITICAL') return 'var(--ds-sev-critical-rule)';
    if (severity === 'HIGH') return 'var(--ds-sev-high-rule)';
    if (severity === 'MEDIUM') return 'var(--ds-sev-medium-rule)';
    if (severity === 'LOW') return 'var(--ds-sev-low-rule)';
    return 'var(--ds-sev-info-rule)';
  };

  return (
    <article className="sms-verdict" aria-label="Executive Determination">
      <div className="sms-verdict__main">
        <div className="sms-verdict__shield" style={{ color: tone.color, background: tone.bg, borderColor: tone.border }} aria-hidden="true">
          <Icon size={28} />
        </div>
        <div className="sms-verdict__copy">
          <div className="sms-verdict__band">
            <span className="sms-posture-badge" style={{ color: tone.color, backgroundColor: tone.bg, borderColor: tone.border }}>
              <span className="sms-posture-badge__dot" style={{ backgroundColor: tone.indicator }} aria-hidden="true" />
              <span>{posture.label || posture.value}</span>
            </span>
            {posture.formula_id && (
              <span className="sms-mono sms-verdict__formula" title="Posture scoring formula">
                {posture.formula_id}
              </span>
            )}
          </div>
          <div className="sms-verdict__score">
            <span style={{ color: tone.color }}>{scoreText}</span>
            <span className="sms-verdict__max">/ 100</span>
          </div>
          <h2 className="sms-verdict__headline">{headline}</h2>
          <div className="sms-verdict__anchors">
            {primaryFinding?.severity && <SeverityBadge severity={primaryFinding.severity} size="sm" />}
            {primaryFinding?.certainty && <CertaintyBadge certainty={primaryFinding.certainty} />}
            {ruleId && <span className="sms-badge sms-badge--rule">{ruleId}</span>}
            {standardText && <span className="sms-badge sms-badge--standard">{standardText}</span>}
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
        </div>
      </div>

      <aside className="sms-verdict__side" aria-label="Other verdicts">
        <div className="sms-verdict__side-head">
          <h3>Other verdicts</h3>
          <p>{others.length === 0 ? 'None on this capture.' : 'Also recorded on this capture.'}</p>
        </div>
        {others.length > 0 && (
          <ul className="sms-verdict__list">
            {others.map((finding, idx) => (
              <li key={`${finding.title}-${idx}`}>
                <button type="button" onClick={() => onOpenFinding?.(finding)} disabled={!onOpenFinding}>
                  <span className="sms-dot" style={{ background: sevColor(finding.severity) }} aria-hidden="true" />
                  <span>{finding.title}</span>
                  {finding.affected_sessions != null && finding.affected_sessions > 0 && (
                    <span className="sms-verdict__count">{finding.affected_sessions} session{finding.affected_sessions === 1 ? '' : 's'}</span>
                  )}
                </button>
              </li>
            ))}
          </ul>
        )}
        {primaryFinding && (
          <div className="sms-verdict__actions">
            {onOpenFrame && primaryFinding.frames && primaryFinding.frames.length > 0 && (
              <button
                type="button"
                className="sms-btn sms-btn--primary sms-btn--sm"
                onClick={() => onOpenFrame(primaryFinding.frames[0], primaryFinding.stream_key || undefined)}
                title={`Jump directly to wire evidence Frame #${primaryFinding.frames[0]}`}
              >
                <span>Open Frame #{primaryFinding.frames[0]}</span>
              </button>
            )}
            {onTraceProvenance && (
              <button
                type="button"
                className="sms-btn sms-btn--sm"
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
                className="sms-btn sms-btn--sm"
                onClick={() => onOpenFinding(primaryFinding)}
                title="Inspect comprehensive finding details"
              >
                <span>Inspect Finding</span>
              </button>
            )}
          </div>
        )}
      </aside>
    </article>
  );
};
