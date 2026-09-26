import React from 'react';
import { getSeverityTokens } from '../../utils/severity';

interface SeverityBadgeProps {
  severity: string | null | undefined;
  size?: 'sm' | 'md';
}

/** Severity is the only vocabulary allowed to use alarm hue (DESIGN.md §1.8 B). A missing severity renders a neutral dash, never a guess. */
export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const t = getSeverityTokens(severity);
  if (!t) {
    return <span className="sms-badge sms-badge--muted" title="Severity not reported">—</span>;
  }
  return (
    <span
      className="sms-badge"
      title={`Severity: ${t.level}`}
      style={{
        color: t.text,
        background: t.bg,
        borderColor: t.border,
        fontSize: size === 'sm' ? 'var(--ds-text-12)' : undefined,
      }}
    >
      <span className="sms-dot" style={{ width: 6, height: 6, background: t.rule }} aria-hidden="true" />
      {t.level}
    </span>
  );
};

export const SeverityDot: React.FC<{ severity: string | null | undefined; size?: number }> = ({ severity, size = 10 }) => {
  const t = getSeverityTokens(severity);
  return (
    <span
      className="sms-dot"
      role="img"
      aria-label={t ? `Severity ${t.level}` : 'Severity not reported'}
      title={t ? t.level : 'Severity not reported'}
      style={{ width: size, height: size, background: t ? t.rule : 'transparent', border: t ? undefined : '1px solid var(--ds-border-strong)' }}
    />
  );
};
