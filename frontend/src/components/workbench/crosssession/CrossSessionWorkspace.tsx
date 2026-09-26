import React, { useMemo } from 'react';
import { Layers } from 'lucide-react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { sourcesForFinding } from '../../../utils/findingEvidence';
import { Panel } from '../../common/Panel';
import { EmptyState, ErrorState, SkeletonRows } from '../../common/StateViews';
import { DeviationPanel } from './DeviationPanel';
import { SessionMatrix } from './SessionMatrix';

export const CrossSessionWorkspace: React.FC = () => {
  const { sessions, dashboard, assessment, isLoading, sectionErrors, selectRun, activeRunId } = useInvestigation();

  const deviations = useMemo(() => {
    return (dashboard?.findings ?? []).flatMap((f) => {
      const src = sourcesForFinding(assessment, f).find((s) => s.lane === 'CROSS_SESSION' || (s.rule_id ?? '').startsWith('CS-'));
      return src ? [{ finding: f, source: src }] : [];
    });
  }, [dashboard, assessment]);

  const subjects = useMemo(() => new Set(deviations.map((d) => d.finding.stream_key).filter((k): k is string => Boolean(k))), [deviations]);

  let body: React.ReactNode;
  if (isLoading && sessions.length === 0) {
    body = <Panel><SkeletonRows rows={10} height={30} gap="2px" /></Panel>;
  } else if (sectionErrors.sessions) {
    body = <Panel><ErrorState title="Failed to load session data" detail={sectionErrors.sessions} onRetry={activeRunId ? () => selectRun(activeRunId) : undefined} /></Panel>;
  } else if (sessions.length < 2) {
    body = (
      <Panel>
        <EmptyState
          icon={<Layers size={20} aria-hidden="true" />}
          title="Single-session capture"
          detail="Cross-session comparison requires multiple TCP streams to the same service."
        />
      </Panel>
    );
  } else {
    body = (
      <>
        <Panel title="Engine determinations" meta={deviations.length ? String(deviations.length) : undefined}>
          {sectionErrors.assessment ? (
            <p className="sms-prose" style={{ color: 'var(--ds-crimson-ink)' }}>Assessment failed to load: {sectionErrors.assessment}</p>
          ) : deviations.length === 0 ? (
            <p className="sms-prose">The engine reported no cross-session deviation for this capture.</p>
          ) : (
            <div className="sms-stack">
              {deviations.map((d) => <DeviationPanel key={d.finding.title} finding={d.finding} source={d.source} />)}
            </div>
          )}
        </Panel>

        <Panel title="Evidence by session" meta={`${sessions.length} streams`}>
          <SessionMatrix sessions={sessions} subjectStreamKeys={subjects} />
          <p className="sms-muted" style={{ marginTop: 'var(--ds-space-12)', fontSize: 'var(--ds-text-12)' }}>
            Cells show each stream's reported value, tinted by evidence state. Rows marked "varies" differ between streams; a difference is not by itself an attack.
          </p>
        </Panel>
      </>
    );
  }

  return (
    <div className="sms-page">
      <header className="sms-page-head">
        <div>
          <h1 className="sms-page-title">Cross-session comparison</h1>
          <p className="sms-page-sub">How each TCP stream in this capture compares, field by field. Determinations come from the engine's baseline and control-endpoint reasoning, not from this view.</p>
        </div>
      </header>
      {body}
    </div>
  );
};
