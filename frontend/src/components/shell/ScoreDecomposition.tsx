import React from 'react';
import type { Posture } from '../../api/types';
import { Modal } from '../common/Modal';
import { SeverityBadge } from '../common/SeverityBadge';

const num = (v: number | null | undefined, digits = 2) => (v === null || v === undefined ? null : v.toFixed(digits));

export const ScoreDecomposition: React.FC<{ posture: Posture; onClose: () => void }> = ({ posture, onClose }) => {
  const starting = num(posture.starting_value);
  const total = num(posture.total_penalty);
  const final = num(posture.score_value);

  return (
    <Modal title="Score breakdown" onClose={onClose} width={720}>
      <div className="sms-stack">
        {posture.basis && <p className="sms-prose">{posture.basis}</p>}
        {posture.withheld && posture.withheld_note && (
          <p className="sms-prose" style={{ color: 'var(--ds-amber-ink)' }}>{posture.withheld_note}</p>
        )}

        <table className="sms-table">
          <thead>
            <tr>
              <th>Component</th>
              <th>Severity</th>
              <th style={{ textAlign: 'right' }}>Sessions</th>
              <th style={{ textAlign: 'right' }}>Weight</th>
              <th style={{ textAlign: 'right' }}>Multiplier</th>
              <th style={{ textAlign: 'right' }}>Penalty</th>
            </tr>
          </thead>
          <tbody>
            {starting && (
              <tr>
                <td className="sms-cell-title" colSpan={5}>Starting score</td>
                <td className="sms-mono" style={{ textAlign: 'right', color: 'var(--ds-ink-primary)' }}>{starting}</td>
              </tr>
            )}
            {posture.components.map((c) => (
              <tr key={c.issue_class} title={c.explanation}>
                <td className="sms-cell-title">{c.issue_class_label || c.issue_class}</td>
                <td><SeverityBadge severity={c.severity} size="sm" /></td>
                <td className="sms-mono" style={{ textAlign: 'right' }}>{c.recurrence ?? '—'}</td>
                <td className="sms-mono" style={{ textAlign: 'right' }}>{c.base_weight ?? '—'}</td>
                <td className="sms-mono" style={{ textAlign: 'right' }}>{num(c.recurrence_multiplier) ?? '—'}</td>
                <td className="sms-mono" style={{ textAlign: 'right', color: 'var(--ds-crimson-ink)' }}>{c.penalty != null ? `−${num(c.penalty)}` : '—'}</td>
              </tr>
            ))}
            {total && (
              <tr>
                <td className="sms-cell-title" colSpan={5}>Total penalty</td>
                <td className="sms-mono" style={{ textAlign: 'right', color: 'var(--ds-crimson-ink)' }}>−{total}</td>
              </tr>
            )}
            <tr>
              <td className="sms-cell-title" colSpan={5}>Final posture score{posture.formula_id ? ` (${posture.formula_id})` : ''}</td>
              <td className="sms-mono" style={{ textAlign: 'right', color: 'var(--ds-ink-primary)', fontWeight: 600 }}>{final ?? '—'}</td>
            </tr>
          </tbody>
        </table>
        {posture.components.length === 0 && <p className="sms-prose">The engine reported no penalty components for this capture.</p>}
      </div>
    </Modal>
  );
};
