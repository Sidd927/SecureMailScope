import React, { useState } from 'react';
import { BarChart3 } from 'lucide-react';
import type { Posture } from '../../../api/types';
import { getSeverityTokens } from '../../../utils/severity';
import { ScoreDecomposition } from '../../shell/ScoreDecomposition';

interface ScoreWaterfallProps {
  posture: Posture;
  onInspectCalculation?: () => void;
}

export const ScoreWaterfall: React.FC<ScoreWaterfallProps> = ({ posture, onInspectCalculation }) => {
  const [modalOpen, setModalOpen] = useState(false);
  const starting = posture.starting_value ?? 100;
  const components = posture.components ?? [];
  const final = posture.score_value ?? 0;
  const totalPenalty = posture.total_penalty ?? 0;

  const handleOpenCalculation = () => {
    if (onInspectCalculation) {
      onInspectCalculation();
    } else {
      setModalOpen(true);
    }
  };

  const finalColor =
    posture.value === 'CRITICAL'
      ? 'var(--ds-sev-critical-text)'
      : posture.value === 'WEAK'
      ? 'var(--ds-sev-high-text)'
      : posture.value === 'ADEQUATE'
      ? 'var(--ds-sev-medium-text)'
      : 'var(--ds-sev-low-text)';

  return (
    <>
      <section className="sms-score-waterfall" aria-label="Why this score">
        <div className="sms-score-waterfall__head">
          <div className="sms-score-waterfall__title-wrap">
            <BarChart3 size={16} aria-hidden="true" />
            <div>
              <span className="sms-score-waterfall__title">Why this score</span>
            </div>
          </div>
          <button
            type="button"
            className="sms-btn sms-btn--sm"
            onClick={handleOpenCalculation}
            title="Inspect mathematical formula and weights"
            aria-label="Inspect score calculation details"
          >
            <span>Inspect calculation</span>
          </button>
        </div>

        <table className="sms-score-table">
          <thead>
            <tr>
              <th>Factor</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Baseline</td>
              <td className="sms-mono">{starting.toFixed(2)}</td>
            </tr>
            {components.length === 0 ? (
              <tr>
                <td>No deductions</td>
                <td className="sms-mono">0.00</td>
              </tr>
            ) : (
              components.map((c, idx) => {
                const sev = getSeverityTokens(c.severity);
                const title = c.issue_class_label || c.issue_class;
                return (
                  <tr key={`${c.issue_class}-${idx}`}>
                    <td>
                      <span className="sms-dot" style={{ backgroundColor: sev ? sev.rule : 'var(--ds-border-strong)', marginRight: 6 }} aria-hidden="true" />
                      {title}
                      {c.recurrence != null && c.recurrence > 1 ? ` · ${c.recurrence} sessions` : ''}
                    </td>
                    <td className="sms-mono">−{(c.penalty ?? 0).toFixed(2)}</td>
                  </tr>
                );
              })
            )}
            <tr className="sms-score-table__end">
              <td>
                Final score
                {posture.formula_id && <span className="sms-muted"> · {posture.formula_id}</span>}
              </td>
              <td className="sms-mono" style={{ color: finalColor }}>
                {final.toFixed(2)}
                <span className="sms-score-table__band"> · {posture.value || 'UNRATED'}</span>
              </td>
            </tr>
          </tbody>
        </table>
        <p className="sms-score-waterfall__note">
          {totalPenalty > 0
            ? `−${totalPenalty.toFixed(2)} total deduction across ${components.length} factor group${components.length === 1 ? '' : 's'}`
            : 'No deductions applied.'}
        </p>
      </section>

      {modalOpen && (
        <ScoreDecomposition posture={posture} onClose={() => setModalOpen(false)} />
      )}
    </>
  );
};
