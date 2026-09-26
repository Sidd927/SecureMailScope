import React from 'react';
import type { FindingRow } from '../../../api/types';
import type { FindingSource } from '../../../utils/findingEvidence';
import { SeverityBadge } from '../../common/SeverityBadge';

// Deviation vocabulary (crosssession/model.py). Kept visually separate from severity:
// only SUSPICIOUS_DEVIATION uses the warning tint, and never alarm red.
const DEVIATION_STYLE: Record<string, React.CSSProperties> = {
  SUSPICIOUS_DEVIATION: { color: 'var(--ds-amber-ink)', background: 'var(--ds-amber-soft)', borderColor: 'var(--ds-amber-border)' },
  DEVIATION: { color: 'var(--ds-ink-primary)', background: 'var(--ds-bg-subtle)', borderColor: 'var(--ds-border-medium)' },
  NONE: { color: 'var(--ds-ink-secondary)' },
  NOT_ASSESSED: { color: 'var(--ds-ink-muted)', borderStyle: 'dotted' },
};

interface Props {
  finding: FindingRow;
  source: FindingSource & { deviation?: string | null; stream_key?: string | null };
}

export const DeviationPanel: React.FC<Props> = ({ finding, source }) => (
  <div className="sms-stack sms-stack--tight">
    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--ds-space-8)', flexWrap: 'wrap' }}>
      {source.deviation && (
        <span className="sms-badge" style={DEVIATION_STYLE[source.deviation]}>{source.deviation.replace(/_/g, ' ')}</span>
      )}
      <SeverityBadge severity={finding.severity} />
      <span className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>
        {source.rule_id}
        {finding.tcp_stream_id != null && ` · subject stream #${finding.tcp_stream_id}`}
        {source.frames?.length ? ` · frame ${source.frames.join(', ')}` : ''}
      </span>
    </div>
    <p style={{ fontSize: 'var(--ds-text-14)', fontWeight: 500, color: 'var(--ds-ink-primary)' }}>{finding.conclusion || finding.title}</p>
    {finding.explanation && <p className="sms-prose">{finding.explanation}</p>}
    {source.standards?.length > 0 && (
      <p className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>{source.standards.join(' · ')}</p>
    )}
  </div>
);
