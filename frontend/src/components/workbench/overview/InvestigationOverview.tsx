import React, { useMemo } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { severityRank } from '../../../utils/severity';
import { ForensicHash } from '../../common/ForensicHash';
import { Panel } from '../../common/Panel';
import { EmptyState } from '../../common/StateViews';
import { FindingCard } from './FindingCard';
import { PosturePanel } from './PosturePanel';
import { SummarySidePanel } from './SummarySidePanel';

export const InvestigationOverview: React.FC = () => {
  const { activeRun, dashboard, sessions, selectFinding, setActiveTab } = useInvestigation();

  const findings = useMemo(
    () => [...(dashboard?.findings ?? [])].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || (a.rank ?? 0) - (b.rank ?? 0)),
    [dashboard],
  );

  if (!dashboard || !activeRun) return null;
  const componentFor = (issueClass: string | null) => dashboard.posture.components.find((c) => c.issue_class === issueClass);
  const generated = dashboard.identity?.generated_at;

  return (
    <div className="sms-page">
      <header className="sms-page-head">
        <div style={{ minWidth: 0 }}>
          <h1 className="sms-page-title">{activeRun.source_filename}</h1>
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--ds-space-16)', marginTop: 'var(--ds-space-8)', fontSize: 'var(--ds-text-12)' }}>
            <ForensicHash value={dashboard.identity?.capture_id || activeRun.capture_id} length={16} label="SHA-256" />
            <span className="sms-muted">
              <span className="sms-mono" style={{ color: 'var(--ds-ink-secondary)' }}>{sessions.length}</span> TCP session{sessions.length === 1 ? '' : 's'}
            </span>
            <span className="sms-muted">
              <span className="sms-mono" style={{ color: 'var(--ds-ink-secondary)' }}>{dashboard.findings.length}</span> finding{dashboard.findings.length === 1 ? '' : 's'}
            </span>
            {dashboard.identity?.posture_engine_version && (
              <span className="sms-muted">engine <span className="sms-mono">{dashboard.identity.posture_engine_version}</span></span>
            )}
            {generated && <span className="sms-muted">analysed <span className="sms-mono">{generated.replace('T', ' ').replace('Z', ' UTC')}</span></span>}
          </div>
        </div>
      </header>

      <div className="sms-summary">
        <PosturePanel dashboard={dashboard} />

        <Panel title="Findings" meta={findings.length ? `${findings.length} ranked by severity` : undefined} aria-label="Findings">
          {findings.length === 0 ? (
            <EmptyState title="No findings for this capture" detail={dashboard.posture.basis || undefined} />
          ) : (
            <div className="sms-stack sms-stack--tight">
              {findings.map((f) => (
                <FindingCard
                  key={`${f.rank}-${f.title}`}
                  finding={f}
                  component={componentFor(f.issue_class)}
                  onOpen={() => { selectFinding(f); setActiveTab('evidence'); }}
                />
              ))}
            </div>
          )}
        </Panel>

        <SummarySidePanel />
      </div>
    </div>
  );
};
