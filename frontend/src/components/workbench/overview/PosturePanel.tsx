import React from 'react';
import type { DashboardViewModel } from '../../../api/types';
import { SEVERITY_ORDER, getSeverityTokens, normalizeSeverity } from '../../../utils/severity';

const BAND_TOKEN: Record<string, string> = {
  STRONG: 'strong',
  ADEQUATE: 'adequate',
  WEAK: 'weak',
  CRITICAL: 'critical',
  INSUFFICIENT_EVIDENCE: 'insufficient',
};

export const PosturePanel: React.FC<{ dashboard: DashboardViewModel }> = ({ dashboard }) => {
  const { posture, coverage, findings, limitations } = dashboard;
  const token = posture.known ? BAND_TOKEN[posture.value] : undefined;
  const counts = SEVERITY_ORDER.map((level) => ({
    level,
    n: findings.filter((f) => normalizeSeverity(f.severity) === level).length,
  }));
  const unrated = findings.filter((f) => !normalizeSeverity(f.severity)).length;

  return (
    <aside className="sms-panel" aria-label="Posture">
      <div
        className="sms-posture-band"
        style={{
          color: token ? `var(--ds-posture-${token}-text)` : 'var(--ds-ink-muted)',
          background: token ? `var(--ds-posture-${token}-bg)` : 'transparent',
          boxShadow: token ? `inset 0 0 0 1px var(--ds-posture-${token}-rule)` : undefined,
          borderRadius: 'var(--ds-radius-md) var(--ds-radius-md) 0 0',
        }}
      >
        <span className="sms-dot" aria-hidden="true" style={{ width: 10, height: 10, background: token ? `var(--ds-posture-${token}-rule)` : 'var(--ds-border-strong)' }} />
        {posture.withheld ? 'WITHHELD' : token ? posture.label || posture.value : 'NOT GRADED'}
      </div>

      <div className="sms-panel__body sms-stack">
        <div>
          <span className="sms-label">Posture score</span>
          <p className="sms-score" style={{ marginTop: 'var(--ds-space-4)' }}>
            {posture.withheld || posture.score_value === null ? '—' : posture.score_value.toFixed(2)}
            <span className="sms-score__max">/ 100</span>
          </p>
          {posture.formula_id && <p className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>{posture.formula_id}</p>}
          {posture.withheld && posture.withheld_note && <p className="sms-prose" style={{ marginTop: 'var(--ds-space-8)' }}>{posture.withheld_note}</p>}
        </div>

        {coverage?.summary_text && (
          <p className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>{coverage.summary_text}</p>
        )}

        <hr className="sms-divider" />

        <div className="sms-stack sms-stack--tight">
          <span className="sms-label">Findings by severity</span>
          {counts.map(({ level, n }) => {
            const t = getSeverityTokens(level)!;
            return (
              <div key={level} className="sms-stat" style={{ opacity: n === 0 ? 0.5 : 1 }}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--ds-space-8)' }}>
                  <span className="sms-dot" aria-hidden="true" style={{ background: t.rule }} />
                  {level}
                </span>
                <span className="sms-stat__value">{n}</span>
              </div>
            );
          })}
          {unrated > 0 && (
            <div className="sms-stat">
              <span>Severity not reported</span>
              <span className="sms-stat__value">{unrated}</span>
            </div>
          )}
        </div>

        {posture.basis && (
          <>
            <hr className="sms-divider" />
            <div className="sms-stack sms-stack--tight">
              <span className="sms-label">How the score was computed</span>
              <p className="sms-prose">{posture.basis}</p>
            </div>
          </>
        )}

        {limitations?.length > 0 && (
          <>
            <hr className="sms-divider" />
            <div className="sms-stack sms-stack--tight">
              <span className="sms-label">What this capture cannot show</span>
              <ul className="sms-list sms-list--bulleted">
                {limitations.map((l) => <li key={l}>{l}</li>)}
              </ul>
            </div>
          </>
        )}
      </div>
    </aside>
  );
};
