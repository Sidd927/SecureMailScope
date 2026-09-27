import React from 'react';
import { ArrowUpRight, Clock, Database, FileSpreadsheet, ShieldAlert, Sparkles } from 'lucide-react';
import { useInvestigation, DEFAULT_FALLBACK_RUNS } from '../../context/InvestigationContext';
import { relativeTime } from '../../utils/time';
import { PosturePill } from '../common/PosturePill';
import { SkeletonRows } from '../common/StateViews';

const MAX_RECENT_ROWS = 6;

// Validated scenarios for demo & engine verification
const VALIDATED_SCENARIOS = [
  {
    runId: DEFAULT_FALLBACK_RUNS[0]?.run_id || '58d5f74ba5024c83ad6e62dae6dd06b6',
    filename: 'backup_weak_certificate.pcap',
    posture: 'CRITICAL' as const,
    score: 44.0,
    findingSignal: 'Weak Certificate: RSA-1024 public key & SHA-1 signature algorithm',
    scope: '1 TCP session · SMTPS :465',
    standards: 'NIST SP 800-57 · RFC 9155',
  },
  {
    runId: DEFAULT_FALLBACK_RUNS[1]?.run_id || '871ea0c739b246098ff481c887afcc0f',
    filename: 'deepdive_cross_session_control_endpoint.pcap',
    posture: 'CRITICAL' as const,
    score: 22.15,
    findingSignal: 'Cross-Session Deviation: Subject 10.0.0.6 lacks STARTTLS vs Control 10.0.0.7',
    scope: '12 TCP sessions · Multi-endpoint',
    standards: 'RFC 3207 §6 · RFC 8314 §3',
  },
  {
    runId: DEFAULT_FALLBACK_RUNS[2]?.run_id || '9aaefe1d93f046faac255dfe67c86c18',
    filename: 'scene_b_certificate_honesty.pcap',
    posture: 'STRONG' as const,
    score: 100.0,
    findingSignal: 'Clean TLS Handshake: Certificate content honestly identified as NOT_OBSERVABLE',
    scope: '1 TCP session · Observability Boundary',
    standards: 'RFC 8446 §4.4.2',
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
      {/* SECTION 1: RECENT INVESTIGATIONS (EDITORIAL LEDGER) */}
      <section className="sms-ledger" aria-labelledby="sms-recent-heading">
        <div className="sms-ledger__head">
          <div className="sms-ledger__title-group">
            <h2 id="sms-recent-heading" className="sms-ledger__title">
              Recent Investigations
            </h2>
            <span className="sms-badge sms-badge--muted">
              {runsLoaded ? `${completed.length} total recorded` : 'Loading…'}
            </span>
          </div>
          <span className="sms-ledger__sub">
            Passive cryptographic postures recorded by the local engine
          </span>
        </div>

        {!runsLoaded ? (
          <div className="sms-ledger__loading">
            <SkeletonRows rows={4} height={52} gap="var(--ds-space-4)" />
          </div>
        ) : rows.length === 0 ? (
          <div className="sms-ledger__empty">
            <Database size={24} className="sms-muted" aria-hidden="true" />
            <p className="sms-ledger__empty-title">No Previous Investigations</p>
            <p className="sms-muted" style={{ fontSize: 'var(--ds-text-13)', maxWidth: '48ch' }}>
              No packet captures have been analyzed in this environment yet. Use the intake bay above to submit your first PCAP file.
            </p>
          </div>
        ) : (
          <ul className="sms-ledger__list" role="list" aria-label="Recent investigations">
            {rows.map((run) => {
              const isLoadedActive = run.run_id === activeRunId;
              const primaryFinding = isLoadedActive && dashboard?.findings?.[0]?.title;

              return (
                <li key={run.run_id} className="sms-ledger__item">
                  <button
                    type="button"
                    className="sms-ledger__row"
                    onClick={() => openInvestigation(run.run_id)}
                    aria-label={`Open investigation for ${run.source_filename} with posture ${run.overall_posture ?? 'unknown'} and score ${run.score_value ?? 'unscored'}`}
                  >
                    {/* Posture & Score Badge */}
                    <div className="sms-ledger__col-posture">
                      <PosturePill band={run.overall_posture} size="sm" />
                      <span className="sms-mono sms-ledger__score">
                        {run.score_value != null ? `${run.score_value.toFixed(1)} / 100` : '—'}
                      </span>
                    </div>

                    {/* Capture Filename & Technical Metadata */}
                    <div className="sms-ledger__col-file">
                      <div className="sms-ledger__file-line">
                        <FileSpreadsheet size={14} className="sms-ledger__file-icon" aria-hidden="true" />
                        <span className="sms-mono sms-ledger__filename" title={run.source_filename}>
                          {run.source_filename}
                        </span>
                        {isLoadedActive && (
                          <span className="sms-badge sms-badge--muted sms-ledger__active-chip">Active</span>
                        )}
                      </div>

                      <div className="sms-ledger__meta-line">
                        {primaryFinding ? (
                          <span className="sms-ledger__primary-signal" title={primaryFinding}>
                            <ShieldAlert size={11} aria-hidden="true" />
                            {primaryFinding}
                          </span>
                        ) : (
                          <span className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-11)' }}>
                            SHA-256: {run.capture_id.slice(0, 12)}…
                          </span>
                        )}
                        <span className="sms-header__sep" aria-hidden="true">•</span>
                        <span className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-11)' }}>
                          {run.duration_ms != null ? `${run.duration_ms}ms analysis` : 'Dissected'}
                        </span>
                        {run.formula_id && (
                          <>
                            <span className="sms-header__sep" aria-hidden="true">•</span>
                            <span className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-11)' }}>
                              {run.formula_id}
                            </span>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Time & Action Pivot */}
                    <div className="sms-ledger__col-action">
                      <time
                        className="sms-ledger__time"
                        dateTime={run.created_at}
                        title={run.created_at}
                      >
                        <Clock size={11} aria-hidden="true" />
                        <span>{relativeTime(run.created_at)}</span>
                      </time>
                      <span className="sms-ledger__open-link" aria-hidden="true">
                        <span>Open</span>
                        <ArrowUpRight size={13} />
                      </span>
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        )}

        {runsLoaded && incomplete > 0 && (
          <p className="sms-ledger__footer-note">
            {incomplete} run{incomplete === 1 ? '' : 's'} with errors or incomplete ingest {incomplete === 1 ? 'is' : 'are'} withheld from the ledger.
          </p>
        )}
      </section>

      {/* SECTION 2: EXPLORE VALIDATED SCENARIOS (SECONDARY BENCHMARKS) */}
      <section className="sms-scenarios" aria-labelledby="sms-scenarios-heading">
        <div className="sms-scenarios__head">
          <div className="sms-scenarios__title-group">
            <Sparkles size={14} className="sms-brand-cyan" aria-hidden="true" />
            <h3 id="sms-scenarios-heading" className="sms-scenarios__title">
              Explore Validated Scenarios
            </h3>
          </div>
          <p className="sms-scenarios__desc">
            Pre-computed passive captures demonstrating specific cryptographic postures, cross-session deviations, and observability boundaries.
          </p>
        </div>

        <div className="sms-scenarios__grid">
          {VALIDATED_SCENARIOS.map((scenario) => (
            <div key={scenario.runId} className="sms-scenario-card">
              <div className="sms-scenario-card__head">
                <div className="sms-scenario-card__badge-row">
                  <PosturePill band={scenario.posture} size="sm" />
                  <span className="sms-mono sms-scenario-card__score">
                    {scenario.score.toFixed(1)} / 100
                  </span>
                </div>
                <span className="sms-mono sms-scenario-card__standards" title={scenario.standards}>
                  {scenario.standards}
                </span>
              </div>

              <div className="sms-scenario-card__body">
                <span className="sms-mono sms-scenario-card__file" title={scenario.filename}>
                  {scenario.filename}
                </span>
                <p className="sms-scenario-card__signal">{scenario.findingSignal}</p>
                <span className="sms-mono sms-scenario-card__scope">{scenario.scope}</span>
              </div>

              <div className="sms-scenario-card__foot">
                <button
                  type="button"
                  className="sms-btn sms-btn--sm sms-scenario-card__btn"
                  onClick={() => openInvestigation(scenario.runId)}
                  title={`Inspect validated scenario: ${scenario.filename}`}
                >
                  <span>Inspect Scenario</span>
                  <ArrowUpRight size={13} aria-hidden="true" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};
