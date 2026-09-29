import React from 'react';
import type { FindingRow, ScoreComponentRow } from '../../../api/types';
import { getSeverityTokens } from '../../../utils/severity';
import { SeverityBadge } from '../../common/SeverityBadge';
import { CertaintyBadge } from '../../common/VocabularyBadges';

interface FindingCardProps {
  finding: FindingRow;
  component?: ScoreComponentRow;
  onOpen: () => void;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding, component, onOpen }) => {
  const sev = getSeverityTokens(finding.severity);
  const citation = finding.citations?.[0];
  const standard = citation ? [citation.standard, citation.section].filter(Boolean).join(' ') : null;

  return (
    <button
      type="button"
      className="sms-finding-card"
      style={{ borderLeftColor: sev ? sev.rule : 'var(--ds-border-strong)' }}
      onClick={onOpen}
      aria-label={`${finding.severity ?? 'Unrated'} finding: ${finding.title}. Open evidence.`}
    >
      <div className="sms-finding-card__head">
        <SeverityBadge severity={finding.severity} />
        <span className="sms-finding-card__title">{finding.title}</span>
        {finding.certainty && <CertaintyBadge certainty={finding.certainty} />}
      </div>

      {finding.conclusion && <p className="sms-prose sms-clamp-3" style={{ lineHeight: 'var(--ds-leading-body)' }}>{finding.conclusion}</p>}

      <div className="sms-finding-card__foot">
        <span>
          {finding.source_rule_ids?.join(', ')}
          {standard && <span> · {standard}</span>}
        </span>
        <span style={{ display: 'inline-flex', gap: 'var(--ds-space-12)' }}>
          {(finding.affected_sessions ?? 0) > 0 && <span>{finding.affected_sessions} session{finding.affected_sessions === 1 ? '' : 's'}</span>}
          {finding.frames?.length > 0 && <span>frame {finding.frames_text || finding.frames.join(', ')}</span>}
          {component?.penalty != null && <span className="sms-finding-card__penalty">−{component.penalty.toFixed(1)} pts</span>}
        </span>
      </div>
    </button>
  );
};
