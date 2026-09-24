import React from 'react';
import type { PostureBand } from '../../api/types';

interface PosturePillProps {
  band: PostureBand | string;
  score?: number | null;
  withheld?: boolean;
  size?: 'sm' | 'md' | 'lg';
  onClick?: () => void;
}

const POSTURE_THEME: Record<
  string,
  { label: string; color: string; bg: string; border: string }
> = {
  STRONG: {
    label: 'STRONG',
    color: '#2d6a36',
    bg: '#edf7ee',
    border: '#bcdbbd',
  },
  ADEQUATE: {
    label: 'ADEQUATE',
    color: '#1f3a5f',
    bg: '#eef3f8',
    border: '#bcd0e6',
  },
  WEAK: {
    label: 'WEAK',
    color: '#a8480f',
    bg: '#fdf2eb',
    border: '#f5cdb5',
  },
  CRITICAL: {
    label: 'CRITICAL',
    color: '#8d1f1f',
    bg: '#fdf0f0',
    border: '#f0c0c0',
  },
  INSUFFICIENT_EVIDENCE: {
    label: 'INSUFFICIENT EVIDENCE',
    color: '#5c6672',
    bg: '#f2f0eb',
    border: '#d4cebe',
  },
};

export const PosturePill: React.FC<PosturePillProps> = ({
  band,
  score,
  withheld = false,
  size = 'md',
  onClick,
}) => {
  const normBand = (band || 'INSUFFICIENT_EVIDENCE').toUpperCase();
  const theme = POSTURE_THEME[normBand] || POSTURE_THEME.INSUFFICIENT_EVIDENCE;

  const isLg = size === 'lg';
  const isSm = size === 'sm';

  return (
    <div
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: isLg ? '10px' : isSm ? '4px' : '6px',
        padding: isLg ? '5px 12px' : isSm ? '2px 6px' : '3px 10px',
        borderRadius: 'var(--radius-sm)',
        backgroundColor: theme.bg,
        border: `1px solid ${theme.border}`,
        color: theme.color,
        fontFamily: 'var(--font-sans)',
        cursor: onClick ? 'pointer' : 'default',
        transition: 'all var(--transition-fast)',
        userSelect: 'none',
      }}
    >
      <span
        style={{
          width: isLg ? '8px' : '6px',
          height: isLg ? '8px' : '6px',
          borderRadius: '50%',
          backgroundColor: theme.color,
          flexShrink: 0,
        }}
      />
      <span
        style={{
          fontSize: isLg ? 'var(--text-sm)' : isSm ? 'var(--text-2xs)' : 'var(--text-xs)',
          fontWeight: 700,
          letterSpacing: '0.04em',
        }}
      >
        {withheld ? 'POSTURE WITHHELD' : theme.label}
      </span>

      {score !== undefined && score !== null && !withheld && (
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: isLg ? 'var(--text-md)' : isSm ? 'var(--text-2xs)' : 'var(--text-xs)',
            fontWeight: 700,
            paddingLeft: '4px',
            borderLeft: `1px solid ${theme.border}`,
            color: 'var(--color-ink)',
          }}
        >
          {score.toFixed(1)}
          <span style={{ fontSize: '0.85em', opacity: 0.6, fontWeight: 500 }}>/100</span>
        </span>
      )}
    </div>
  );
};
