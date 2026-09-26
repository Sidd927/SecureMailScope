import React, { useState } from 'react';
import { Check, Copy } from 'lucide-react';

interface ForensicHashProps {
  value: string | null | undefined;
  length?: number;
  label?: string;
}

export const ForensicHash: React.FC<ForensicHashProps> = ({ value, length = 12, label }) => {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="sms-muted sms-mono">—</span>;
  const display = value.length > length ? `${value.slice(0, length)}…` : value;

  const copy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--ds-space-4)', fontSize: 'var(--ds-text-12)' }} title={value}>
      {label && <span className="sms-muted">{label}</span>}
      <span className="sms-mono" style={{ color: 'var(--ds-ink-secondary)' }}>{display}</span>
      <button
        type="button"
        onClick={copy}
        className="sms-btn sms-btn--ghost"
        style={{ height: 22, padding: '0 var(--ds-space-4)', color: copied ? 'var(--ds-emerald-ink)' : 'var(--ds-ink-muted)' }}
        aria-label={copied ? 'Copied' : `Copy ${label || 'hash'}`}
      >
        {copied ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
      </button>
    </span>
  );
};
