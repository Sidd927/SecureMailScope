import React from 'react';
import { Scale } from 'lucide-react';
import type { Standards } from '../../../api/types';

interface StandardsCardProps {
  standards?: Standards | null;
}

export const StandardsCard: React.FC<StandardsCardProps> = ({ standards }) => {
  if (!standards || !standards.standards || standards.standards.length === 0) {
    return null;
  }

  const items = standards.standards;
  const unmapped = standards.unmapped_citations ?? [];

  return (
    <div className="sms-standards-dossier" aria-label="Normative Standards and Regulatory Baseline">
      <div className="sms-standards-dossier__head">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Scale size={16} style={{ color: 'var(--sms-brand-cyan)' }} aria-hidden="true" />
          <h3 className="sms-standards-dossier__title">Normative Security Standards & RFC Baseline</h3>
        </div>
        <span className="sms-muted sms-mono sms-text-xs">
          {items.length} Authorities Cited
        </span>
      </div>

      <div className="sms-standards-dossier__body">
        <div className="sms-standards-grid">
          {items.map((s) => (
            <div key={s.standard} className="sms-standard-item">
              <div className="sms-standard-item__top">
                <span className="sms-standard-item__name sms-mono">{s.standard}</span>
              </div>
              {s.sections?.length > 0 && (
                <div className="sms-standard-item__sections">
                  {s.sections.map((sec) => (
                    <span key={sec} className="sms-badge sms-badge--standard">
                      {sec}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>

        {unmapped.length > 0 && (
          <details className="sms-standards-unmapped">
            <summary className="sms-muted sms-text-xs" style={{ cursor: 'pointer' }}>
              {unmapped.length} unmapped citations in forensic report
            </summary>
            <ul className="sms-list sms-list--bulleted" style={{ marginTop: '4px' }}>
              {unmapped.map((c) => (
                <li key={c} className="sms-mono sms-text-xs">{c}</li>
              ))}
            </ul>
          </details>
        )}
      </div>
    </div>
  );
};
