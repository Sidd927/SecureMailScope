import React from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import type { EvidenceState } from '../../api/types';

const STATES: Array<{ state: EvidenceState; token: string; label: string }> = [
  { state: 'OBSERVED', token: 'observed', label: 'Observed' },
  { state: 'INFERRED', token: 'inferred', label: 'Inferred' },
  { state: 'UNKNOWN', token: 'unknown', label: 'Unknown' },
  { state: 'AMBIGUOUS', token: 'ambiguous', label: 'Ambiguous' },
  { state: 'INCOMPLETE', token: 'incomplete', label: 'Incomplete' },
  { state: 'NOT_OBSERVABLE', token: 'not-observable', label: 'Not observable' },
];

const monoSmall: React.CSSProperties = {
  fontFamily: 'var(--ds-font-mono)',
  fontSize: 'var(--ds-text-12)',
  fontFeatureSettings: '"tnum" 1',
};

export const CoverageLanes: React.FC = () => {
  const { dashboard, isLoading } = useInvestigation();
  const coverage = dashboard?.coverage;

  if (isLoading && !coverage) {
    return (
      <div aria-busy="true" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--ds-space-8)' }}>
        {[0, 1, 2].map((i) => (
          <div key={i} className="ds-skeleton" style={{ height: 'var(--ds-space-24)' }} />
        ))}
      </div>
    );
  }

  const lanes = STATES.map((s) => ({
    ...s,
    fraction: coverage?.observation_fractions?.[s.state] ?? 0,
    count: coverage?.observation_counts?.[s.state] ?? 0,
  })).filter((l) => l.fraction > 0);

  if (!coverage || !coverage.present || lanes.length === 0) {
    return (
      <p style={{ fontSize: 'var(--ds-text-13)', color: 'var(--ds-ink-muted)' }}>
        No coverage data returned for this capture.
      </p>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--ds-space-12)' }}>
      <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 'var(--ds-space-8)' }}>
        {lanes.map((lane) => (
          <li key={lane.state} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--ds-space-4)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 'var(--ds-space-8)' }}>
              <span style={{ fontSize: 'var(--ds-text-12)', color: `var(--ds-ev-${lane.token}-text)`, fontWeight: 500 }}>
                {lane.label}
              </span>
              <span style={{ ...monoSmall, color: 'var(--ds-ink-secondary)' }}>
                {lane.count} <span style={{ color: 'var(--ds-ink-muted)' }}>· {(lane.fraction * 100).toFixed(1)}%</span>
              </span>
            </div>
            <div style={{ height: 'var(--ds-space-4)', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: 'var(--ds-radius-sm)' }}>
              <div
                style={{
                  width: `${lane.fraction * 100}%`,
                  height: '100%',
                  backgroundColor: `var(--ds-ev-${lane.token}-text)`,
                  borderRadius: 'var(--ds-radius-sm)',
                }}
              />
            </div>
          </li>
        ))}
      </ul>
      {coverage.summary_text && (
        <p style={{ ...monoSmall, color: 'var(--ds-ink-muted)' }}>{coverage.summary_text}</p>
      )}
    </div>
  );
};
