import React from 'react';
import type { Posture } from '../../api/types';
import { SeverityBadge } from './SeverityBadge';
import { X } from 'lucide-react';

interface ScoreDecompositionProps {
  posture: Posture;
  onClose: () => void;
}

export const ScoreDecomposition: React.FC<ScoreDecompositionProps> = ({ posture, onClose }) => {
  const starting = posture.starting_value ?? 100.0;
  const penalty = posture.total_penalty ?? 0.0;
  const finalScore = posture.score_value ?? 100.0;

  return (
    <div
      role="dialog"
      aria-labelledby="score-decomposition-title"
      aria-modal="true"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(21, 25, 30, 0.4)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: '24px',
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '680px',
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--color-border-strong)',
          boxShadow: 'var(--shadow-flyout)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          maxHeight: '90vh',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '16px 20px',
            borderBottom: '1px solid var(--color-border)',
            backgroundColor: 'var(--color-panel)',
          }}
        >
          <div>
            <div
              style={{
                fontSize: 'var(--text-xs)',
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                color: 'var(--color-ink-muted)',
                letterSpacing: '0.06em',
              }}
            >
              Deterministic Posture Calculus
            </div>
            <h2
              id="score-decomposition-title"
              style={{
                fontSize: 'var(--text-lg)',
                fontWeight: 700,
                color: 'var(--color-ink)',
                marginTop: '2px',
              }}
            >
              Score Decomposition &amp; Penalties
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{
              padding: '6px',
              color: 'var(--color-ink-muted)',
              borderRadius: 'var(--radius-xs)',
            }}
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </div>

        {/* Math Summary Strip */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-around',
            padding: '16px 20px',
            backgroundColor: 'var(--color-panel-card)',
            borderBottom: '1px solid var(--color-border)',
            fontFamily: 'var(--font-mono)',
            fontSize: 'var(--text-sm)',
          }}
        >
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--color-ink-faint)' }}>
              STARTING BASE
            </div>
            <div style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-ink)' }}>
              {starting.toFixed(1)}
            </div>
          </div>
          <div style={{ color: 'var(--color-ink-faint)', fontSize: 'var(--text-lg)' }}>−</div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--color-sev-critical)' }}>
              DEDUCTIONS
            </div>
            <div
              style={{
                fontSize: 'var(--text-xl)',
                fontWeight: 700,
                color: 'var(--color-sev-critical)',
              }}
            >
              {penalty.toFixed(1)}
            </div>
          </div>
          <div style={{ color: 'var(--color-ink-faint)', fontSize: 'var(--text-lg)' }}>=</div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--color-accent)' }}>
              FINAL SCORE
            </div>
            <div
              style={{
                fontSize: 'var(--text-xl)',
                fontWeight: 700,
                color: 'var(--color-accent)',
              }}
            >
              {finalScore.toFixed(1)}
              <span style={{ fontSize: '11px', color: 'var(--color-ink-muted)' }}>/100</span>
            </div>
          </div>
        </div>

        {/* Formula Basis Note */}
        <div
          style={{
            padding: '12px 20px',
            fontSize: 'var(--text-xs)',
            color: 'var(--color-ink-muted)',
            backgroundColor: 'var(--color-page)',
            borderBottom: '1px solid var(--color-border)',
            fontFamily: 'var(--font-mono)',
          }}
        >
          <strong>Formula:</strong> {posture.formula_id || 'Standard'} — {posture.basis}
        </div>

        {/* Breakdown Items List */}
        <div style={{ padding: '20px', overflowY: 'auto' }}>
          <div
            style={{
              fontSize: 'var(--text-xs)',
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              color: 'var(--color-ink-muted)',
              marginBottom: '12px',
            }}
          >
            Penalty Components ({posture.components.length})
          </div>

          {posture.components.length === 0 ? (
            <div
              style={{
                padding: '24px',
                textAlign: 'center',
                backgroundColor: 'var(--color-panel)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--color-ink-muted)',
                fontSize: 'var(--text-sm)',
              }}
            >
              No penalty deductions were incurred. Baseline score remained intact.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {posture.components.map((comp, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: '14px',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--color-border)',
                    backgroundColor: 'var(--color-surface)',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      marginBottom: '8px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <SeverityBadge severity={comp.severity} size="sm" />
                      <span style={{ fontWeight: 600, fontSize: 'var(--text-sm)' }}>
                        {comp.issue_class_label}
                      </span>
                    </div>
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        color: 'var(--color-sev-critical)',
                        fontSize: 'var(--text-sm)',
                      }}
                    >
                      −{(comp.penalty ?? 0).toFixed(2)} pts
                    </span>
                  </div>

                  <div
                    style={{
                      fontSize: 'var(--text-xs)',
                      color: 'var(--color-ink-secondary)',
                      marginBottom: '8px',
                      lineHeight: 1.4,
                    }}
                  >
                    {comp.explanation}
                  </div>

                  {/* Math Breakdown Row */}
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 'var(--text-2xs)',
                      color: 'var(--color-ink-muted)',
                      backgroundColor: 'var(--color-panel)',
                      padding: '6px 10px',
                      borderRadius: 'var(--radius-xs)',
                    }}
                  >
                    <span>
                      Base Weight: <strong>{comp.base_weight ?? '—'}</strong>
                    </span>
                    <span>×</span>
                    <span>
                      Multiplier: <strong>{(comp.recurrence_multiplier ?? 1).toFixed(2)}</strong>
                    </span>
                    <span>(Recurrence: {comp.recurrence ?? 1} session)</span>
                    <span style={{ marginLeft: 'auto', color: 'var(--color-sev-critical)' }}>
                      = −{(comp.penalty ?? 0).toFixed(2)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '12px 20px',
            borderTop: '1px solid var(--color-border)',
            backgroundColor: 'var(--color-panel)',
            display: 'flex',
            justifyContent: 'flex-end',
          }}
        >
          <button
            type="button"
            onClick={onClose}
            style={{
              padding: '6px 16px',
              fontSize: 'var(--text-xs)',
              fontWeight: 600,
              backgroundColor: 'var(--color-accent)',
              color: '#ffffff',
              borderRadius: 'var(--radius-xs)',
            }}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
