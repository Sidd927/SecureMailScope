import React, { useMemo, useState } from 'react';
import { Layers, AlertTriangle, Table, ChevronDown, ChevronUp } from 'lucide-react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { sourcesForFinding } from '../../../utils/findingEvidence';
import { Panel } from '../../common/Panel';
import { EmptyState, ErrorState, SkeletonRows } from '../../common/StateViews';
import { presentBasis } from '../evidence/plainEvidence';
import { DeviationPanel } from './DeviationPanel';
import { SessionMatrix } from './SessionMatrix';
import type { SessionEvidence } from '../../../api/types';

function sideFacts(list: SessionEvidence[]) {
  const starttls = list.filter((s) => s.evidence?.starttls_advertised?.value === true).length;
  const tls = list.filter((s) => {
    const state = (s.tls_state || '').toUpperCase();
    return state !== '' && state !== 'NONE' && state !== 'UNKNOWN';
  }).length;
  const plaintextAuth = list.filter((s) => s.evidence?.auth_activity?.value === true && s.evidence?.starttls_advertised?.value !== true && ((s.tls_state || '').toUpperCase() === 'NONE' || !s.tls_state)).length;
  return {
    starttls: starttls > 0 ? `OBSERVED (${starttls})` : `NOT OBSERVED (${list.length})`,
    tls: tls > 0 ? `ESTABLISHED (${tls})` : 'CLEAR',
    auth: plaintextAuth > 0 ? `PLAINTEXT (${plaintextAuth})` : 'NONE RECORDED',
    starttlsOn: starttls > 0,
    tlsOn: tls > 0,
    authPlain: plaintextAuth > 0,
  };
}

export const CrossSessionWorkspace: React.FC = () => {
  const { sessions, dashboard, assessment, isLoading, sectionErrors, selectRun, activeRunId } = useInvestigation();
  const [showFullMatrix, setShowFullMatrix] = useState(false);

  const deviations = useMemo(() => {
    return (dashboard?.findings ?? []).flatMap((f) => {
      const src = sourcesForFinding(assessment, f).find((s) => s.lane === 'CROSS_SESSION' || (s.rule_id ?? '').startsWith('CS-'));
      return src ? [{ finding: f, source: src }] : [];
    });
  }, [dashboard, assessment]);

  const subjects = useMemo(() => new Set(deviations.map((d) => d.finding.stream_key).filter((k): k is string => Boolean(k))), [deviations]);

  // Derive Subject and Control groups
  const { subjectEndpoint, controlEndpoint, subjectSessions, controlSessions } = useMemo(() => {
    if (sessions.length < 2) {
      return { subjectEndpoint: null, controlEndpoint: null, subjectSessions: [], controlSessions: [] };
    }
    const subList = sessions.filter((s) => subjects.has(s.stream_key));
    const subEp = subList[0]?.client?.ip ?? sessions.find((s) => s.client?.ip)?.client.ip ?? 'not recorded';
    const other = sessions.find((s) => s.client?.ip && s.client.ip !== subEp);
    const ctrlEp = other?.client?.ip ?? 'not recorded';
    return {
      subjectEndpoint: subEp,
      controlEndpoint: ctrlEp,
      subjectSessions: sessions.filter((s) => s.client?.ip === subEp),
      controlSessions: ctrlEp === 'not recorded' ? [] : sessions.filter((s) => s.client?.ip === ctrlEp),
    };
  }, [sessions, subjects]);

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
    const subjectFacts = sideFacts(subjectSessions);
    const controlFacts = sideFacts(controlSessions);
    const diverge = (a: string, b: string) => a.split(' ')[0] !== b.split(' ')[0];
    const lead = deviations[0];
    body = (
      <div className="sms-stack">
        {/* 1. FIRST: SUBJECT VS CONTROL COMPARISON (SECTION 16) */}
        <section className="sms-cross-session-summary-card" aria-label="Subject vs Control baseline comparison">
          <header className="sms-cross-session-summary__header">
            <span className="sms-label">Subject and control</span>
            <span className="sms-mono sms-text-xs sms-muted">{sessions.length} total streams evaluated</span>
          </header>

          <div className="sms-subject-control-grid">
            {/* SUBJECT CARD */}
            <div className="sms-endpoint-card sms-endpoint-card--subject">
              <div className="sms-endpoint-card__tag">
                <span className="sms-dot sms-dot--crimson" aria-hidden="true" />
                <span>SUBJECT ENDPOINT</span>
              </div>
              <h3 className="sms-endpoint-card__ip sms-mono">{subjectEndpoint}</h3>
              <div className="sms-endpoint-facts">
                <div className="sms-endpoint-fact-row">
                  <span className="sms-endpoint-fact-label">STARTTLS</span>
                  <span className={`sms-endpoint-fact-val ${subjectFacts.starttlsOn ? 'sms-endpoint-fact-val--good' : 'sms-endpoint-fact-val--bad'}`}>{subjectFacts.starttls}</span>
                </div>
                <div className="sms-endpoint-fact-row">
                  <span className="sms-endpoint-fact-label">TLS</span>
                  <span className={`sms-endpoint-fact-val ${subjectFacts.tlsOn ? 'sms-endpoint-fact-val--good' : 'sms-endpoint-fact-val--bad'}`}>{subjectFacts.tls}</span>
                </div>
                <div className="sms-endpoint-fact-row">
                  <span className="sms-endpoint-fact-label">AUTH</span>
                  <span className={`sms-endpoint-fact-val ${subjectFacts.authPlain ? 'sms-endpoint-fact-val--bad' : 'sms-endpoint-fact-val--good'}`}>{subjectFacts.auth}</span>
                </div>
              </div>
            </div>

            {/* VS DIVIDER */}
            <div className="sms-subject-control-vs" aria-hidden="true">
              <span>VS</span>
            </div>

            {/* CONTROL CARD */}
            <div className="sms-endpoint-card sms-endpoint-card--control">
              <div className="sms-endpoint-card__tag">
                <span className="sms-dot sms-dot--emerald" aria-hidden="true" />
                <span>CONTROL BASELINE</span>
              </div>
              <h3 className="sms-endpoint-card__ip sms-mono">{controlEndpoint}</h3>
              <div className="sms-endpoint-facts">
                <div className="sms-endpoint-fact-row">
                  <span className="sms-endpoint-fact-label">STARTTLS</span>
                  <span className={`sms-endpoint-fact-val ${controlFacts.starttlsOn ? 'sms-endpoint-fact-val--good' : 'sms-endpoint-fact-val--bad'}`}>{controlSessions.length ? controlFacts.starttls : 'not recorded'}</span>
                </div>
                <div className="sms-endpoint-fact-row">
                  <span className="sms-endpoint-fact-label">TLS</span>
                  <span className={`sms-endpoint-fact-val ${controlFacts.tlsOn ? 'sms-endpoint-fact-val--good' : 'sms-endpoint-fact-val--bad'}`}>{controlSessions.length ? controlFacts.tls : 'not recorded'}</span>
                </div>
                <div className="sms-endpoint-fact-row">
                  <span className="sms-endpoint-fact-label">AUTH</span>
                  <span className={`sms-endpoint-fact-val ${controlFacts.authPlain ? 'sms-endpoint-fact-val--bad' : 'sms-endpoint-fact-val--good'}`}>{controlSessions.length ? controlFacts.auth : 'not recorded'}</span>
                </div>
              </div>
            </div>
          </div>

          {/* VISUAL DIFFERENCE MATRIX */}
          <div className="sms-key-comparison-table-wrap">
            <table className="sms-key-comparison-table" aria-label="Key cross-session comparison rows">
              <thead>
                <tr>
                  <th scope="col">Dimension</th>
                  <th scope="col">Subject: {subjectEndpoint}</th>
                  <th scope="col">Control: {controlEndpoint}</th>
                  <th scope="col">Divergence</th>
                </tr>
              </thead>
              <tbody>
                {[
                  ['STARTTLS', subjectFacts.starttls, controlSessions.length ? controlFacts.starttls : 'not recorded'],
                  ['TLS', subjectFacts.tls, controlSessions.length ? controlFacts.tls : 'not recorded'],
                  ['AUTH', subjectFacts.auth, controlSessions.length ? controlFacts.auth : 'not recorded'],
                ].map(([dim, left, right]) => (
                  <tr key={dim}>
                    <th scope="row">{dim}</th>
                    <td className="sms-mono">{left}</td>
                    <td className="sms-mono">{right}</td>
                    <td><span className={`sms-badge ${diverge(left, right) ? 'sms-badge--critical' : ''}`}>{diverge(left, right) ? 'Divergent' : 'Aligned'}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* SUPPORTED DEVIATION CALLOUT */}
          {lead && (
            <div className="sms-deviation-callout">
              <div className="sms-deviation-callout__head">
                <AlertTriangle size={15} className="sms-amber-icon" aria-hidden="true" />
                <h4 className="sms-deviation-callout__title">{lead.source.rule_id || 'Deviation'} · {lead.finding.title}</h4>
              </div>
              <blockquote className="sms-deviation-callout__quote">
                {presentBasis(lead.finding.conclusion || lead.finding.explanation || lead.finding.title, 180).show}
              </blockquote>
              <p className="sms-forensic-caveat-text">Compared with the other endpoint in this capture. Not an attacker identity.</p>
            </div>
          )}

          <div className="sms-cross-session-actions">
            <button
              type="button"
              className="sms-btn sms-btn--sm"
              onClick={() => setShowFullMatrix(!showFullMatrix)}
              aria-expanded={showFullMatrix}
            >
              <Table size={13} aria-hidden="true" />
              <span>{showFullMatrix ? 'Collapse session matrix' : `Open full ${sessions.length}-session matrix`}</span>
              {showFullMatrix ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
            </button>
          </div>
        </section>

        {/* 2. ENGINE DETERMINATIONS */}
        {deviations.length > 0 && (
          <Panel title="Engine determinations" meta={String(deviations.length)}>
            <div className="sms-stack">
              {deviations.map((d) => <DeviationPanel key={d.finding.title} finding={d.finding} source={d.source} />)}
            </div>
          </Panel>
        )}

        {/* 3. FULL MATRIX (PROGRESSIVELY DISCLOSED) */}
        {showFullMatrix && (
          <Panel title="Full evidence matrix by session" meta={`${sessions.length} streams`}>
            <SessionMatrix sessions={sessions} subjectStreamKeys={subjects} />
            <p className="sms-muted" style={{ marginTop: 'var(--ds-space-12)', fontSize: 'var(--ds-text-12)' }}>
              Cells show each stream's reported value, tinted by evidence state. Rows marked "varies" differ between streams; a difference is evaluated under the engine's deterministic baseline rules.
            </p>
          </Panel>
        )}
      </div>
    );
  }

  return (
    <div className="sms-page sms-stage">
      <header className="sms-page-head">
        <div>
          <h1 className="sms-page-title">Cross-session</h1>
          <p className="sms-page-sub">Subject endpoint against the control endpoints.</p>
        </div>
      </header>
      {body}
    </div>
  );
};
