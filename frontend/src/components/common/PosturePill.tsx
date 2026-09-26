import React from 'react';
import type { PostureBand } from '../../api/types';

interface PosturePillProps {
  band: PostureBand | string | null | undefined;
  score?: number | null;
  withheld?: boolean;
  size?: 'sm' | 'md' | 'lg';
  onClick?: () => void;
}

const BANDS: Record<string, { label: string; token: string }> = {
  STRONG: { label: 'STRONG', token: 'strong' },
  ADEQUATE: { label: 'ADEQUATE', token: 'adequate' },
  WEAK: { label: 'WEAK', token: 'weak' },
  CRITICAL: { label: 'CRITICAL', token: 'critical' },
  INSUFFICIENT_EVIDENCE: { label: 'INSUFFICIENT EVIDENCE', token: 'insufficient' },
};

export const PosturePill: React.FC<PosturePillProps> = ({ band, score, withheld = false, size = 'md', onClick }) => {
  const meta = band ? BANDS[band.toUpperCase()] : undefined;
  const isLg = size === 'lg';
  const isSm = size === 'sm';
  const text = meta ? `var(--ds-posture-${meta.token}-text)` : 'var(--ds-ink-muted)';
  const rule = meta ? `var(--ds-posture-${meta.token}-rule)` : 'var(--ds-border-medium)';

  return (
    <span
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(); } } : undefined}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: isLg ? 'var(--ds-space-8)' : 'var(--ds-space-4)',
        padding: isLg ? 'var(--ds-space-4) var(--ds-space-12)' : isSm ? '1px 6px' : '2px var(--ds-space-8)',
        borderRadius: 'var(--ds-radius-sm)',
        backgroundColor: meta ? `var(--ds-posture-${meta.token}-bg)` : 'transparent',
        border: `1px solid ${rule}`,
        color: text,
        fontFamily: 'var(--ds-font-mono)',
        fontSize: isLg ? 'var(--ds-text-13)' : isSm ? 'var(--ds-text-12)' : 'var(--ds-text-12)',
        fontWeight: 600,
        letterSpacing: '0.04em',
        whiteSpace: 'nowrap',
        cursor: onClick ? 'pointer' : 'default',
        userSelect: 'none',
      }}
    >
      {meta && <span aria-hidden="true" style={{ width: isLg ? 8 : 6, height: isLg ? 8 : 6, borderRadius: '50%', backgroundColor: rule, flexShrink: 0 }} />}
      <span>{withheld ? 'POSTURE WITHHELD' : meta ? meta.label : '—'}</span>
      {score !== undefined && score !== null && !withheld && (
        <span style={{ paddingLeft: 'var(--ds-space-4)', borderLeft: `1px solid ${rule}`, color: 'var(--ds-ink-primary)', fontFeatureSettings: '"tnum" 1' }}>
          {score.toFixed(1)}
          <span style={{ color: 'var(--ds-ink-muted)' }}>/100</span>
        </span>
      )}
    </span>
  );
};
