import React from 'react';
import { AlertTriangle } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';

export const OfflineBanner: React.FC = () => {
  const { isUsingFixtures } = useInvestigation();

  if (!isUsingFixtures) return null;

  return (
    <div
      role="alert"
      aria-live="polite"
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 'var(--ds-space-12)',
        padding: 'var(--ds-space-12) var(--ds-space-24)',
        backgroundColor: 'var(--ds-amber-soft)',
        borderBottom: '1px solid var(--ds-amber-border)',
        color: 'var(--ds-amber-ink)',
        fontFamily: 'var(--ds-font-sans)',
        fontSize: 'var(--ds-text-13)',
        lineHeight: 'var(--ds-leading-body)',
      }}
    >
      <AlertTriangle size={16} aria-hidden="true" style={{ flexShrink: 0, marginTop: '1px' }} />
      <div>
        <p style={{ fontWeight: 600 }}>
          Demo data: <span style={{ fontFamily: 'var(--ds-font-mono)' }}>backend unavailable</span>
        </p>
        <p>The results shown are pre-loaded demonstration data, not from your uploaded capture file.</p>
      </div>
    </div>
  );
};
