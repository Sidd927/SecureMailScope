import React, { useMemo } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { getSeverityTokens, severityRank } from '../../../utils/severity';
import { CoverageLanes } from '../../common/CoverageLanes';
import { Panel } from '../../common/Panel';
import { EmptyState, ErrorState, SkeletonRows } from '../../common/StateViews';
import { sessionLabel } from '../../../utils/session';

export const SummarySidePanel: React.FC = () => {
  const { dashboard, sessions, isLoading, sectionErrors, selectRun, activeRunId, selectSession, setActiveTab } = useInvestigation();
  const findings = dashboard?.findings ?? [];

  // Derived view: the most severe finding whose affected_stream_keys include each stream.
  // The API has no per-session posture band, so this is labelled as a join, not a grade.
  const worstByStream = useMemo(() => {
    const worst = new Map<string, string>();
    for (const f of findings) {
      for (const key of f.affected_stream_keys ?? []) {
        const current = worst.get(key);
        if (!current || severityRank(f.severity) < severityRank(current)) worst.set(key, f.severity ?? '');
      }
    }
    return worst;
  }, [findings]);

  const standards = dashboard?.standards?.standards ?? [];
  const unmapped = dashboard?.standards?.unmapped_citations ?? [];

  return (
    <aside className="sms-stack" aria-label="Coverage and sessions">
      <Panel title="Evidence coverage">
        <CoverageLanes />
      </Panel>

      <Panel title="Sessions" meta={sessions.length ? String(sessions.length) : undefined}>
        {isLoading && sessions.length === 0 ? (
          <SkeletonRows rows={4} height={20} />
        ) : sectionErrors.sessions ? (
          <ErrorState title="Sessions failed to load" detail={sectionErrors.sessions} onRetry={activeRunId ? () => selectRun(activeRunId) : undefined} />
        ) : sessions.length === 0 ? (
          <EmptyState inline title="No sessions returned for this capture." />
        ) : (
          <div className="sms-stack sms-stack--tight">
            <ul className="sms-list" style={{ maxHeight: 280, overflowY: 'auto' }}>
              {sessions.map((s) => {
                const sev = worstByStream.get(s.stream_key);
                const t = getSeverityTokens(sev);
                return (
                  <li key={s.stream_key}>
                    <button
                      type="button"
                      className="sms-session-row sms-btn--ghost"
                      style={{ width: '100%', padding: 'var(--ds-space-4) 0', textAlign: 'left' }}
                      onClick={() => { selectSession(s.stream_key); setActiveTab('evidence'); }}
                      title={sessionLabel(s)}
                    >
                      <span className="sms-dot" aria-label={t ? `Most severe finding: ${t.level}` : 'No findings'} style={{ background: t ? t.rule : 'transparent', border: t ? undefined : '1px solid var(--ds-border-strong)' }} />
                      <span style={{ color: 'var(--ds-ink-primary)' }}>#{s.tcp_stream_id}</span>
                      <span className="sms-session-row__peer">{s.client.ip ?? 'client not recorded'}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
            <p className="sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>Dot shows the most severe finding affecting each stream.</p>
          </div>
        )}
      </Panel>

      {standards.length > 0 && (
        <Panel title="Standards cited">
          <ul className="sms-list">
            {standards.map((s) => (
              <li key={s.standard} className="sms-mono" style={{ fontSize: 'var(--ds-text-12)', color: 'var(--ds-ink-secondary)' }}>
                {s.standard}
                {s.sections?.length > 0 && <span className="sms-muted"> {s.sections.join(', ')}</span>}
              </li>
            ))}
          </ul>
          {unmapped.length > 0 && (
            <details style={{ marginTop: 'var(--ds-space-12)' }}>
              <summary className="sms-muted" style={{ fontSize: 'var(--ds-text-12)', cursor: 'pointer' }}>
                {unmapped.length} citations not yet in the standards registry
              </summary>
              <ul className="sms-list sms-list--bulleted" style={{ marginTop: 'var(--ds-space-8)' }}>
                {unmapped.map((c) => <li key={c}>{c}</li>)}
              </ul>
            </details>
          )}
        </Panel>
      )}
    </aside>
  );
};
