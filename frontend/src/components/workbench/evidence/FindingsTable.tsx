import React from 'react';
import type { FindingRow } from '../../../api/types';
import { SeverityDot } from '../../common/SeverityBadge';
import { CertaintyBadge, FindingStatusBadge } from '../../common/VocabularyBadges';

interface FindingsTableProps {
  findings: FindingRow[];
  selected: FindingRow | null;
  onSelect: (f: FindingRow) => void;
}

const isSame = (a: FindingRow | null, b: FindingRow) => !!a && a.rank === b.rank && a.title === b.title;

export const FindingsTable: React.FC<FindingsTableProps> = ({ findings, selected, onSelect }) => (
  <div style={{ overflowX: 'auto' }}>
    <table className="sms-table" aria-label="Findings">
      <thead>
        <tr>
          <th style={{ width: 28 }}><span className="sms-visually-hidden">Severity</span></th>
          <th>Rule</th>
          <th>Title</th>
          <th>Status</th>
          <th>Certainty</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f) => {
          const active = isSame(selected, f);
          return (
            <tr
              key={`${f.rank}-${f.title}`}
              className={`is-clickable${active ? ' is-selected' : ''}`}
              tabIndex={0}
              aria-selected={active}
              onClick={() => onSelect(f)}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(f); } }}
            >
              <td><SeverityDot severity={f.severity} /></td>
              <td className="sms-mono" style={{ fontSize: 'var(--ds-text-12)', whiteSpace: 'nowrap' }}>{f.source_rule_ids?.join(', ') || '—'}</td>
              <td className="sms-cell-title">{f.title}</td>
              <td><FindingStatusBadge status={f.status} /></td>
              <td><CertaintyBadge certainty={f.certainty} /></td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);
