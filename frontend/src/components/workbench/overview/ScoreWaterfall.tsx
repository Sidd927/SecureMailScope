import React, { useState } from 'react';
import { Calculator, ChevronRight } from 'lucide-react';
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

  return (
    <>
      <section className="sms-score-waterfall" aria-label="Forensic Score Waterfall">
        <div className="sms-score-waterfall__head">
          <div className="sms-score-waterfall__title-wrap">
            <span className="sms-label">Why This Score?</span>
            <span className="sms-muted sms-text-xs">
              Sequential deductions from normative baseline
            </span>
          </div>

          <button
            type="button"
            className="sms-btn sms-btn--ghost sms-btn--sm"
            onClick={handleOpenCalculation}
            title="Inspect mathematical formula and weights"
            aria-label="Inspect score calculation details"
          >
            <Calculator size={13} aria-hidden="true" />
            <span>Inspect calculation</span>
          </button>
        </div>

        <div className="sms-score-waterfall__tree">
          {/* 1. Starting Baseline */}
          <div className="sms-waterfall-node sms-waterfall-node--start">
            <div className="sms-waterfall-node__spine" aria-hidden="true">
              <span className="sms-waterfall-node__dot sms-waterfall-node__dot--start" />
              <span className="sms-waterfall-node__line" />
            </div>
            <div className="sms-waterfall-node__content">
              <div className="sms-waterfall-node__desc">
                <span className="sms-waterfall-node__title">Starting Baseline</span>
                <span className="sms-waterfall-node__meta">Normative transport security ceiling</span>
              </div>
              <span className="sms-mono sms-waterfall-node__val sms-waterfall-node__val--base">
                {starting.toFixed(2)}
              </span>
            </div>
          </div>

          {/* 2. Deductions (Clean, Uncluttered) */}
          {components.length === 0 ? (
            <div className="sms-waterfall-node">
              <div className="sms-waterfall-node__spine" aria-hidden="true">
                <span className="sms-waterfall-node__branch">├─</span>
                <span className="sms-waterfall-node__line" />
              </div>
              <div className="sms-waterfall-node__content">
                <div className="sms-waterfall-node__desc">
                  <span className="sms-waterfall-node__title" style={{ color: 'var(--ds-sev-low-text)' }}>
                    Zero Deductions
                  </span>
                  <span className="sms-waterfall-node__meta">All observed sessions comply with cryptographic rules</span>
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
                  <div className="sms-waterfall-node__content">
                    <div className="sms-waterfall-node__desc">
                      <div className="sms-waterfall-node__title-wrap">
                        <span
                          className="sms-dot"
                          style={{ backgroundColor: sev ? sev.rule : 'var(--ds-border-strong)' }}
                          aria-hidden="true"
                        />
                        <span className="sms-waterfall-node__title">{title}</span>
                        {c.recurrence != null && c.recurrence > 1 && (
                          <span className="sms-badge sms-badge--muted sms-badge--xs sms-mono">
                            {c.recurrence} sessions
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

          {/* 3. Final Posture */}
          <div className="sms-waterfall-node sms-waterfall-node--final">
            <div className="sms-flow-connector--down-spine" aria-hidden="true" />
            <div className="sms-waterfall-node__content">
              <div className="sms-waterfall-node__desc">
                <span className="sms-waterfall-node__title sms-waterfall-node__title--final">
                  Final Posture Score
                </span>
                <span className="sms-waterfall-node__meta">
                  {posture.formula_id || 'Deterministic Scoring Engine'}
                </span>
              </div>
              <div className="sms-waterfall-node__val-group">
                <span
                  className="sms-mono sms-waterfall-node__val sms-waterfall-node__val--final"
                  style={{
                    color:
                      posture.value === 'CRITICAL'
                        ? 'var(--ds-sev-critical-text)'
                        : posture.value === 'WEAK'
                        ? 'var(--ds-sev-high-text)'
                        : posture.value === 'ADEQUATE'
                        ? 'var(--ds-sev-medium-text)'
                        : 'var(--ds-sev-low-text)',
                  }}
                >
                  {final.toFixed(2)}
                </span>
                <span className="sms-badge sms-badge--xs" style={{ marginLeft: 6 }}>
                  {posture.value || 'UNRATED'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Footer with progressive disclosure trigger */}
        <div className="sms-score-waterfall__foot">
          <span className="sms-muted sms-text-xs">
            {totalPenalty > 0
              ? `−${totalPenalty.toFixed(2)} total deduction across ${components.length} factor group${components.length === 1 ? '' : 's'}`
              : 'Full compliance — zero deductions applied'}
          </span>
          <button
            type="button"
            className="sms-link"
            style={{ fontSize: 'var(--ds-text-12)', display: 'inline-flex', alignItems: 'center', gap: '3px' }}
            onClick={handleOpenCalculation}
          >
            Inspect calculation <ChevronRight size={12} aria-hidden="true" />
          </button>
        </div>
      </section>

      {modalOpen && (
        <ScoreDecomposition posture={posture} onClose={() => setModalOpen(false)} />
      )}
    </>
  );
};
