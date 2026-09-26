import React from 'react';
import { AlertTriangle, Inbox, RotateCw } from 'lucide-react';

interface EmptyStateProps {
  title: string;
  detail?: string;
  icon?: React.ReactNode;
  inline?: boolean;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ title, detail, icon, inline }) => (
  <div className={inline ? 'sms-empty sms-empty--inline' : 'sms-empty'} role="status">
    {!inline && (icon ?? <Inbox size={20} aria-hidden="true" />)}
    <p className="sms-empty__title">{title}</p>
    {detail && <p>{detail}</p>}
  </div>
);

interface ErrorStateProps {
  title: string;
  detail?: string | null;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({ title, detail, onRetry }) => (
  <div className="sms-error" role="alert">
    <AlertTriangle size={20} aria-hidden="true" style={{ color: 'var(--ds-crimson-ink)' }} />
    <p className="sms-error__title">{title}</p>
    {detail && <p className="sms-mono" style={{ fontSize: 'var(--ds-text-12)' }}>{detail}</p>}
    {onRetry && (
      <button type="button" className="sms-btn sms-btn--sm" onClick={onRetry}>
        <RotateCw size={13} aria-hidden="true" />
        Retry
      </button>
    )}
  </div>
);

interface SkeletonRowsProps {
  rows?: number;
  height?: number;
  gap?: string;
}

export const SkeletonRows: React.FC<SkeletonRowsProps> = ({ rows = 6, height = 36, gap = 'var(--ds-space-4)' }) => (
  <div aria-busy="true" aria-label="Loading" style={{ display: 'flex', flexDirection: 'column', gap }}>
    {Array.from({ length: rows }, (_, i) => (
      <div key={i} className="ds-skeleton" style={{ height, opacity: 1 - i * (0.6 / rows) }} />
    ))}
  </div>
);
