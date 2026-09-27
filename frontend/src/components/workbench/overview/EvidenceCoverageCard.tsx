import React from 'react';
import { Activity } from 'lucide-react';
import type { Coverage } from '../../../api/types';

interface EvidenceCoverageCardProps {
  coverage?: Coverage;
}

export const EvidenceCoverageCard: React.FC<EvidenceCoverageCardProps> = ({ coverage }) => {
  if (!coverage) return null;

  const obs = coverage.observation_counts || ({} as Record<string, number>);
  const cObserved = Number(obs.OBSERVED || 0);
  const cUnknown = Number(obs.UNKNOWN || 0);
  const cAmbiguous = Number(obs.AMBIGUOUS || 0);
  const cIncomplete = Number(obs.INCOMPLETE || 0);
  const cNotObservable = Number(obs.NOT_OBSERVABLE || 0);

  const total = (cObserved + cUnknown + cAmbiguous + cIncomplete + cNotObservable) || 1;
  const pObserved = Math.round((cObserved / total) * 100);
  const pUnknown = Math.round((cUnknown / total) * 100);
  const pAmbiguous = Math.round((cAmbiguous / total) * 100);
  const pNotObservable = Math.round((cNotObservable / total) * 100);

  return (
    <div className="sms-context-card" aria-label="Evidence Epistemic Coverage">
      <div className="sms-context-card__head">
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Activity size={13} style={{ color: 'var(--sms-brand-cyan)' }} aria-hidden="true" />
          <span className="sms-label">Evidence Coverage</span>
        </div>
        <span className="sms-mono sms-badge sms-badge--muted">
          {coverage.sessions_assessed ?? 0} / {coverage.sessions_total ?? 0} sessions
        </span>
      </div>

      <div className="sms-context-card__body sms-stack sms-stack--tight">
        {/* Multi-segment Coverage Bar */}
        <div className="sms-coverage-bar" title="Epistemic distribution of passive observation facts">
          {cObserved > 0 && (
            <div
              className="sms-coverage-bar__seg sms-coverage-bar__seg--observed"
              style={{ width: `${pObserved}%` }}
              title={`Observed: ${cObserved} facts (${pObserved}%)`}
            />
          )}
          {cUnknown > 0 && (
            <div
              className="sms-coverage-bar__seg sms-coverage-bar__seg--unknown"
              style={{ width: `${pUnknown}%` }}
              title={`Unknown: ${cUnknown} facts (${pUnknown}%)`}
            />
          )}
          {cAmbiguous > 0 && (
            <div
              className="sms-coverage-bar__seg sms-coverage-bar__seg--ambiguous"
              style={{ width: `${pAmbiguous}%` }}
              title={`Ambiguous: ${cAmbiguous} facts (${pAmbiguous}%)`}
            />
          )}
          {cNotObservable > 0 && (
            <div
              className="sms-coverage-bar__seg sms-coverage-bar__seg--not-observable"
              style={{ width: `${pNotObservable}%` }}
              title={`Not Observable: ${cNotObservable} facts (${pNotObservable}%)`}
            />
          )}
        </div>

        {/* Legend */}
        <div className="sms-coverage-legend">
          <div className="sms-coverage-legend__item">
            <span className="sms-dot" style={{ backgroundColor: 'var(--sms-brand-cyan)' }} aria-hidden="true" />
            <span className="sms-coverage-legend__label">Observed</span>
            <span className="sms-mono sms-coverage-legend__val">{cObserved} ({pObserved}%)</span>
          </div>

          {cUnknown > 0 && (
            <div className="sms-coverage-legend__item">
              <span className="sms-dot" style={{ backgroundColor: 'var(--sms-text-muted)' }} aria-hidden="true" />
              <span className="sms-coverage-legend__label">Unknown</span>
              <span className="sms-mono sms-coverage-legend__val">{cUnknown} ({pUnknown}%)</span>
            </div>
          )}

          {cAmbiguous > 0 && (
            <div className="sms-coverage-legend__item">
              <span className="sms-dot" style={{ backgroundColor: 'var(--ds-sev-medium-rule)' }} aria-hidden="true" />
              <span className="sms-coverage-legend__label">Ambiguous</span>
              <span className="sms-mono sms-coverage-legend__val">{cAmbiguous} ({pAmbiguous}%)</span>
            </div>
          )}

          {cNotObservable > 0 && (
            <div className="sms-coverage-legend__item">
              <span className="sms-dot" style={{ backgroundColor: 'var(--sms-brand-blue)' }} aria-hidden="true" />
              <span className="sms-coverage-legend__label">Not Observable</span>
              <span className="sms-mono sms-coverage-legend__val">{cNotObservable} ({pNotObservable}%)</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
