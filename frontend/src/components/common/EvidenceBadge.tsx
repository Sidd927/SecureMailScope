import React from 'react';
import { Eye, GitBranch, HelpCircle, Split, Scissors, EyeOff } from 'lucide-react';
import { evidenceStateMeta } from '../../utils/evidence';

interface EvidenceBadgeProps {
  state: string | null | undefined;
  size?: 'sm' | 'md';
  count?: number;
  /** Sentence-case pill with a status dot. Same state, label, and count as the default badge. */
  variant?: 'default' | 'pill';
}

const ICONS: Record<string, React.ElementType> = {
  OBSERVED: Eye,
  INFERRED: GitBranch,
  UNKNOWN: HelpCircle,
  AMBIGUOUS: Split,
  INCOMPLETE: Scissors,
  NOT_OBSERVABLE: EyeOff,
};

export const EvidenceBadge: React.FC<EvidenceBadgeProps> = ({ state, size = 'md', count, variant = 'default' }) => {
  const meta = evidenceStateMeta(state);
  if (!meta) {
    return <span style={{ fontFamily: 'var(--ds-font-mono)', fontSize: 'var(--ds-text-12)', color: 'var(--ds-ink-muted)' }}>—</span>;
  }
  if (variant === 'pill') {
    return (
      <span className={`sms-ev-pill sms-ev-pill--${meta.token}`} title={`Evidence state: ${meta.label}`}>
        <span className="sms-ev-pill__dot" aria-hidden="true" />
        <span>{meta.label}</span>
        {count !== undefined && <span className="sms-ev-pill__count">{count}</span>}
      </span>
    );
  }
  const Icon = ICONS[meta.state];
  const isSm = size === 'sm';

  return (
    <span
      title={`Evidence state: ${meta.label}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--ds-space-4)',
        padding: isSm ? '1px 6px' : '2px 8px',
        fontFamily: 'var(--ds-font-mono)',
        fontSize: isSm ? 'var(--ds-text-12)' : 'var(--ds-text-12)',
        fontWeight: 600,
        letterSpacing: '0.02em',
        whiteSpace: 'nowrap',
        lineHeight: 'var(--ds-leading-tight)',
        borderRadius: 'var(--ds-radius-sm)',
        borderWidth: '1px',
        borderStyle: meta.borderStyle,
        color: `var(--ds-ev-${meta.token}-text)`,
        backgroundColor: `var(--ds-ev-${meta.token}-bg)`,
        borderColor: `var(--ds-ev-${meta.token}-border)`,
      }}
    >
      <Icon size={isSm ? 10 : 11} aria-hidden="true" />
      <span>{meta.state.replace('_', ' ')}</span>
      {count !== undefined && <span style={{ fontFeatureSettings: '"tnum" 1', opacity: 0.8 }}>{count}</span>}
    </span>
  );
};
