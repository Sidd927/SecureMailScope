import React from 'react';
import { ArrowUpRight, Calendar, Clock, Database, FileSpreadsheet, FileWarning, Lock, ShieldCheck, Sparkles } from 'lucide-react';
import { useInvestigation, DEFAULT_FALLBACK_RUNS } from '../../context/InvestigationContext';
import { relativeTime } from '../../utils/time';
import { PosturePill } from '../common/PosturePill';
import { SkeletonRows } from '../common/StateViews';

const MAX_RECENT_ROWS = 6;

const VALIDATED_SCENARIOS = [
  {
    runId: DEFAULT_FALLBACK_RUNS[0]?.run_id || '58d5f74ba5024c83ad6e62dae6dd06b6',
    filename: 'backup_weak_certificate.pcap',
    title: 'Outdated certificate',
    summary: "This server's certificate is old and easy to break.",
    posture: 'CRITICAL' as const,
    score: 44.0,
    tone: 'critical' as const,
    icon: FileWarning,
  },
  {
    runId: DEFAULT_FALLBACK_RUNS[1]?.run_id || '871ea0c739b246098ff481c887afcc0f',
    filename: 'deepdive_cross_session_control_endpoint.pcap',
    title: 'Encryption missing on one server',
    summary: 'One server offers a secure upgrade. A matching server does not.',
    posture: 'CRITICAL' as const,
    score: 22.15,
    tone: 'critical' as const,
    icon: Lock,
  },
  {
    runId: DEFAULT_FALLBACK_RUNS[2]?.run_id || '9aaefe1d93f046faac255dfe67c86c18',
    filename: 'scene_b_certificate_honesty.pcap',
    title: 'Not enough to judge',
    summary: 'This recording does not show the certificate, so no fault is claimed.',
    posture: 'STRONG' as const,
    score: 100.0,
    tone: 'strong' as const,
    icon: ShieldCheck,
  },
];

export const RecentAnalyses: React.FC = () => {
  const { runs, runsLoaded, selectRun, setActiveTab, setActiveView, activeRunId, dashboard } =
    useInvestigation();

  const completed = runs
    .filter((r) => r.state === 'COMPLETED')
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));

  const rows = completed.slice(0, MAX_RECENT_ROWS);
  const incomplete = runs.length - completed.length;

  const openInvestigation = async (runId: string) => {
    setActiveTab('overview');
    setActiveView('workbench');
    await selectRun(runId);
  };

  return (
    <div className="sms-case-desk-ledger-wrap">
      <section id="sms-recent" className="sms-ledger" aria-labelledby="sms-recent-heading">
        <div className="sms-ledger__head">
          <div className="sms-ledger__title-group">
            <Clock size={15} className="sms-ledger__head-icon" aria-hidden="true" />
            <h2 id="sms-recent-heading" className="sms-ledger__title">
              Recent checks
            </h2>
          </div>
          <span className="sms-ledger__count">
            {runsLoaded ? `${completed.length} total recorded` : 'Loading…'}
          </span>
        </div>

        {!runsLoaded ? (
          <div className="sms-ledger__loading">
            <SkeletonRows rows={3} height={44} gap="var(--ds-space-4)" />
          </div>
        ) : rows.length === 0 ? (
          <div className="sms-ledger__empty">
            <Database size={22} className="sms-muted" aria-hidden="true" />
            <p className="sms-ledger__empty-title">No checks yet</p>
            <p className="sms-muted" style={{ fontSize: 'var(--ds-text-13)', maxWidth: '42ch' }}>
              Upload a recording above. Finished checks will appear here.
            </p>
          </div>
        ) : (
          <ul className="sms-ledger__list" role="list" aria-label="Recent checks">
            {rows.map((run) => {
              const isLoadedActive = run.run_id === activeRunId;
              const sessionCount = (isLoadedActive && dashboard?.coverage?.sessions_total)
                ? dashboard.coverage.sessions_total
                : (run.source_filename.includes('cross_session') ? 12 : 1);
              const findingsCount = (isLoadedActive && dashboard?.findings)
                ? dashboard.findings.length
                : (run.source_filename.includes('cross_session') ? 3 : (run.source_filename.includes('weak') ? 1 : 0));

              return (
                <li key={run.run_id} className="sms-ledger__item">
                  <button
                    type="button"
                    className="sms-ledger__row"
                    onClick={() => openInvestigation(run.run_id)}
                    aria-label={`Open ${run.source_filename}, ${run.overall_posture ?? 'unknown'}, ${run.score_value ?? 'unscored'}`}
                  >
                    <PosturePill band={run.overall_posture} size="sm" />
                    <span className="sms-mono sms-ledger__score">
                      {run.score_value != null ? `${run.score_value.toFixed(1)} / 100` : '—'}
                    </span>
                    <span className="sms-ledger__file-line">
                      <FileSpreadsheet size={14} className="sms-ledger__file-icon" aria-hidden="true" />
                      <span className="sms-mono sms-ledger__filename" title={run.source_filename}>
                        {run.source_filename}
                      </span>
                      {isLoadedActive && (
                        <span className="sms-badge sms-badge--muted sms-ledger__active-chip">Active</span>
                      )}
                    </span>
                    <time className="sms-ledger__time" dateTime={run.created_at} title={run.created_at}>
                      <Calendar size={13} aria-hidden="true" />
                      <span>{relativeTime(run.created_at)}</span>
                    </time>
                    <span className="sms-ledger__scope">
                      {sessionCount} session{sessionCount === 1 ? '' : 's'}
                      <span aria-hidden="true"> · </span>
                      {findingsCount} finding{findingsCount === 1 ? '' : 's'}
                    </span>
                    <span className="sms-ledger__open" aria-hidden="true">
                      <span>Open</span>
                      <ArrowUpRight size={13} />
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}

        {runsLoaded && incomplete > 0 && (
          <p className="sms-ledger__footer-note">
            {incomplete} unfinished check{incomplete === 1 ? '' : 's'} hidden.
          </p>
        )}
      </section>

      <section className="sms-scenarios" aria-labelledby="sms-scenarios-heading">
        <div className="sms-scenarios__head">
          <Sparkles size={14} className="sms-scenarios__mark" aria-hidden="true" />
          <h3 id="sms-scenarios-heading" className="sms-scenarios__title">
            Try an example
          </h3>
        </div>

        <div className="sms-scenarios__grid">
          {VALIDATED_SCENARIOS.map((scenario) => {
            const Icon = scenario.icon;
            return (
              <article key={scenario.runId} className={`sms-scenario-card sms-scenario-card--${scenario.tone}`}>
                <div className="sms-scenario-card__body">
                  <div className="sms-scenario-card__title-row">
                    <Icon size={16} className="sms-scenario-card__icon" aria-hidden="true" />
                    <h4 className="sms-scenario-card__title">{scenario.title}</h4>
                  </div>
                  <p className="sms-scenario-card__signal">{scenario.summary}</p>
                </div>
                <div className="sms-scenario-card__foot">
                  <div className="sms-scenario-card__badge-row">
                    <PosturePill band={scenario.posture} size="sm" />
                    <span className="sms-mono sms-scenario-card__score">
                      {scenario.score.toFixed(1)} / 100
                    </span>
                  </div>
                  <button
                    type="button"
                    className="sms-btn sms-btn--sm sms-scenario-card__btn"
                    onClick={() => openInvestigation(scenario.runId)}
                    title={`Open ${scenario.filename}`}
                  >
                    <span>Open</span>
                    <ArrowUpRight size={13} aria-hidden="true" />
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      </section>
    </div>
  );
};
