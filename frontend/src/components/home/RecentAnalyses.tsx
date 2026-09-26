import React from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import { relativeTime } from '../../utils/time';
import { PosturePill } from '../common/PosturePill';
import { SkeletonRows } from '../common/StateViews';

const MAX_ROWS = 5;

export const RecentAnalyses: React.FC = () => {
  const { runs, runsLoaded, selectRun, setActiveTab, setActiveView } = useInvestigation();

  // Only completed runs have a dashboard to open. Cancelled or failed runs are counted
  // below the list rather than shown as rows that lead nowhere.
  const completed = runs
    .filter((r) => r.state === 'COMPLETED')
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  const rows = completed.slice(0, MAX_ROWS);
  const incomplete = runs.length - completed.length;

  const open = (runId: string) => {
    setActiveTab('overview');
    setActiveView('workbench');
    selectRun(runId);
  };

  return (
    <section className="sms-recent" aria-labelledby="sms-recent-label">
      <h2 id="sms-recent-label" className="sms-label">Recent analyses</h2>
      {!runsLoaded ? (
        <SkeletonRows rows={3} height={44} gap="var(--ds-space-4)" />
      ) : rows.length === 0 ? (
        <p className="sms-recent__note" style={{ fontSize: 'var(--ds-text-13)' }}>No previous analyses</p>
      ) : (
        <ul className="sms-recent__list">
          {rows.map((r) => (
            <li key={r.run_id}>
              <button type="button" className="sms-recent__row" onClick={() => open(r.run_id)} aria-label={`Open analysis of ${r.source_filename}`}>
                <span className="sms-recent__file" title={r.source_filename}>{r.source_filename}</span>
                <span><PosturePill band={r.overall_posture} size="sm" /></span>
                <span className="sms-recent__score">{r.score_value != null ? r.score_value.toFixed(2) : '—'}</span>
                <time className="sms-recent__time" dateTime={r.created_at} title={r.created_at}>{relativeTime(r.created_at)}</time>
              </button>
            </li>
          ))}
        </ul>
      )}
      {runsLoaded && incomplete > 0 && (
        <p className="sms-recent__note">
          {incomplete} run{incomplete === 1 ? '' : 's'} that did not complete {incomplete === 1 ? 'is' : 'are'} not listed.
        </p>
      )}
    </section>
  );
};
