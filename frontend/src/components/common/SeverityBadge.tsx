import React from 'react';

interface SeverityBadgeProps {
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string | null;
  size?: 'sm' | 'md';
}

const SEVERITY_CONFIG: Record<
  string,
  { label: string; color: string; bg: string; border: string; marker: string }
> = {
  CRITICAL: {
    label: 'CRITICAL',
    color: 'var(--color-sev-critical)',
    bg: 'var(--color-sev-critical-bg)',
    border: 'var(--color-sev-critical-border)',
    marker: '■',
  },
  HIGH: {
    label: 'HIGH',
    color: 'var(--color-sev-high)',
    bg: 'var(--color-sev-high-bg)',
    border: 'var(--color-sev-high-border)',
    marker: '▲',
  },
  MEDIUM: {
    label: 'MEDIUM',
    color: 'var(--color-sev-medium)',
    bg: 'var(--color-sev-medium-bg)',
    border: 'var(--color-sev-medium-border)',
    marker: '◆',
  },
  LOW: {
    label: 'LOW',
    color: 'var(--color-sev-low)',
    bg: 'var(--color-sev-low-bg)',
    border: 'var(--color-sev-low-border)',
    marker: '▼',
  },
  INFO: {
    label: 'INFO',
    color: 'var(--color-sev-info)',
    bg: 'var(--color-sev-info-bg)',
    border: 'var(--color-sev-info-border)',
    marker: '●',
  },
};

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const norm = (severity || 'INFO').toUpperCase();
  const config = SEVERITY_CONFIG[norm] || SEVERITY_CONFIG.INFO;
  const isSm = size === 'sm';

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: isSm ? '4px' : '6px',
        padding: isSm ? '1px 6px' : '2px 8px',
        fontSize: isSm ? 'var(--text-2xs)' : 'var(--text-xs)',
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
        letterSpacing: '0.05em',
        borderRadius: 'var(--radius-xs)',
        backgroundColor: config.bg,
        color: config.color,
        border: `1px solid ${config.border}`,
        borderLeft: `3px solid ${config.color}`,
        lineHeight: 1.25,
        userSelect: 'none',
        whiteSpace: 'nowrap',
      }}
    >
      <span style={{ fontSize: isSm ? '8px' : '9px', opacity: 0.9 }}>{config.marker}</span>
      <span>{config.label}</span>
    </span>
  );
};
