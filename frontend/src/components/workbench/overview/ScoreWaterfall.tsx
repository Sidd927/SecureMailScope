import React, { useState } from 'react';
import { Calculator, ChevronRight } from 'lucide-react';
import type { Posture } from '../../../api/types';
import { getSeverityTokens } from '../../../utils/severity';
import { ScoreDecomposition } from '../../shell/ScoreDecomposition';

interface ScoreWaterfallProps {
  posture: Posture;
}

export const ScoreWaterfall: React.FC<ScoreWaterfallProps> = ({ posture }) => {
  const [modalOpen, setModalOpen] = useState(false);
  const starting = posture.starting_value ?? 100;
  const components = posture.components ?? [];
  const final = posture.score_value ?? 0;
  const totalPenalty = posture.total_penalty ?? 0;

  return (
    <>
      <section className="sms-score-waterfall" aria-label="Forensic Score Waterfall">
        <div className="sms-score-waterfall__head">
          <span className="sms-label">Why This Score?</span>
          <button
            type="button"
            className="sms-btn sms-btn--ghost sms-btn--sm"
            onClick={() => setModalOpen(true)}
            title="Inspect complete mathematical formula and weights"
          >
            <Calculator size={13} aria-hidden="true" />
            <span>Mathematical Formula</span>
          </button>
        </div>

        <div className="sms-score-waterfall__tree">
          {/* Starting Score Baseline */}
          <div className="sms-waterfall-node sms-waterfall-node--start">
            <div className="sms-waterfall-node__spine" aria-hidden="true">
              <span className="sms-waterfall-node__dot sms-waterfall-node__dot--start" />
              <span className="sms-waterfall-node__line" />
            </div>
            <div className="sms-waterfall-node__content">
              <div className="sms-waterfall-node__desc">
                <span className="sms-waterfall-node__title">Starting Baseline Posture</span>
                <span className="sms-muted sms-mono sms-text-xs">Normative 100-point baseline</span>
              </div>
              <span className="sms-mono sms-waterfall-node__val sms-waterfall-node__val--base">
                {starting.toFixed(2)}
              </span>
            </div>
          </div>

          {/* Deductions from Score Components */}
          {components.length === 0 ? (
            <div className="sms-waterfall-node">
              <div className="sms-waterfall-node__spine" aria-hidden="true">
                <span className="sms-waterfall-node__branch">├─</span>
                <span className="sms-waterfall-node__line" />
              </div>
              <div className="sms-waterfall-node__content">
                <div className="sms-waterfall-node__desc">
                  <span className="sms-waterfall-node__title" style={{ color: 'var(--ds-sev-low-text)' }}>
                    Zero Cryptographic Penalties
                  </span>
                  <span className="sms-muted sms-text-xs">No policy violations or cryptographic weaknesses</span>
                </div>
                <span className="sms-mono sms-waterfall-node__val" style={{ color: 'var(--ds-sev-low-text)' }}>
                  0.00
                </span>
              </div>
            </div>
          ) : (
            components.map((c, idx) => {
              const sev = getSeverityTokens(c.severity);
              const isLast = idx === components.length - 1;
              const penalty = c.penalty ?? 0;
              const title = c.issue_class_label || c.issue_class;

              return (
                <div key={`${c.issue_class}-${idx}`} className="sms-waterfall-node sms-waterfall-node--deduction">
                  <div className="sms-waterfall-node__spine" aria-hidden="true">
                    <span className="sms-waterfall-node__branch">{isLast ? '└─' : '├─'}</span>
                    {!isLast && <span className="sms-waterfall-node__line" />}
                  </div>
                  <div className="sms-waterfall-node__content" title={c.explanation}>
                    <div className="sms-waterfall-node__desc">
                      <div className="sms-waterfall-node__title-wrap">
                        <span
                          className="sms-dot"
                          style={{ backgroundColor: sev ? sev.rule : 'var(--ds-border-strong)' }}
                          aria-hidden="true"
                        />
                        <span className="sms-waterfall-node__title">{title}</span>
                      </div>
                      <div className="sms-waterfall-node__sub">
                        {c.recurrence != null && c.recurrence > 0 && (
                          <span className="sms-mono sms-muted">
                            {c.recurrence} session{c.recurrence === 1 ? '' : 's'}
                          </span>
                        )}
                        {c.severity && (
                          <span className="sms-mono sms-muted" style={{ color: sev?.rule }}>
                            · {c.severity}
                          </span>
                        )}
                      </div>
                    </div>
                    <span className="sms-mono sms-waterfall-node__val sms-waterfall-node__val--deduct">
                      −{penalty.toFixed(2)}
                    </span>
                  </div>
                </div>
              );
            })
          )}

          {/* Final Posture Output */}
          <div className="sms-waterfall-node sms-waterfall-node--final">
            <div className="sms-waterfall-node__spine" aria-hidden="true">
              <span className="sms-waterfall-node__dot sms-waterfall-node__dot--final" />
            </div>
            <div className="sms-waterfall-node__content">
              <div className="sms-waterfall-node__desc">
                <span className="sms-waterfall-node__title sms-waterfall-node__title--final">
                  Final Posture Score
                </span>
                <span className="sms-muted sms-mono sms-text-xs">
                  {posture.formula_id || 'Deterministic Scoring Engine'}
                </span>
              </div>
              <div className="sms-waterfall-node__val-group">
                <span className="sms-mono sms-waterfall-node__val sms-waterfall-node__val--final">
                  {final.toFixed(2)}
                </span>
                <span className="sms-muted sms-text-xs">/ 100</span>
              </div>
            </div>
          </div>
        </div>

        {/* Footer summary bar */}
        <div className="sms-score-waterfall__foot">
          <span className="sms-muted sms-text-xs">
            {totalPenalty > 0
              ? `Total deductions: −${totalPenalty.toFixed(2)} pts across ${components.length} factor group${components.length === 1 ? '' : 's'}`
              : 'Full compliance — zero deductions applied'}
          </span>
          <button
            type="button"
            className="sms-link"
            style={{ fontSize: 'var(--ds-text-12)', display: 'inline-flex', alignItems: 'center', gap: '2px' }}
            onClick={() => setModalOpen(true)}
          >
            Inspect calculations <ChevronRight size={12} aria-hidden="true" />
          </button>
        </div>
      </section>

      {modalOpen && (
        <ScoreDecomposition posture={posture} onClose={() => setModalOpen(false)} />
      )}
    </>
  );
};
