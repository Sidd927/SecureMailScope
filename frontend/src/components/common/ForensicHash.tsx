import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface ForensicHashProps {
  value: string;
  length?: number;
  label?: string;
  mono?: boolean;
}

export const ForensicHash: React.FC<ForensicHashProps> = ({
  value,
  length = 12,
  label,
  mono = true,
}) => {
  const [copied, setCopied] = useState(false);

  const display =
    value && value.length > length ? `${value.slice(0, length)}…` : value || '—';

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!value) return;
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        fontSize: 'var(--text-xs)',
        color: 'var(--color-ink-muted)',
      }}
      title={value}
    >
      {label && <span style={{ color: 'var(--color-ink-faint)', marginRight: '2px' }}>{label}:</span>}
      <span
        style={{
          fontFamily: mono ? 'var(--font-mono)' : 'inherit',
          color: 'var(--color-ink)',
          letterSpacing: mono ? '0.02em' : 'normal',
        }}
      >
        {display}
      </span>
      {value && (
        <button
          onClick={handleCopy}
          type="button"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '2px',
            color: copied ? 'var(--color-sev-low)' : 'var(--color-ink-faint)',
            borderRadius: 'var(--radius-xs)',
            transition: 'color var(--transition-fast)',
          }}
          title={copied ? 'Copied full hash' : 'Copy full hash'}
        >
          {copied ? <Check size={11} /> : <Copy size={11} />}
        </button>
      )}
    </span>
  );
};
