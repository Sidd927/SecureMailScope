import React from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { Panel } from '../../common/Panel';
import { EmptyState, ErrorState, SkeletonRows } from '../../common/StateViews';
import { JourneyTimeline } from './JourneyTimeline';
import { endpointLabel, sessionLabel } from '../../../utils/session';

const humanize = (s: string | null | undefined) => (s ? s.replace(/_/g, ' ').toLowerCase() : '—');

export const ProtocolJourney: React.FC = () => {
  const { sessions, selectedSession, selectSession, selectedEventFrame, isLoading, sectionErrors, selectRun, activeRunId } = useInvestigation();
  const session = selectedSession;

  let body: React.ReactNode;
  if (isLoading && sessions.length === 0) {
    body = <SkeletonRows rows={9} height={44} gap="var(--ds-space-8)" />;
  } else if (sectionErrors.sessions) {
    body = <ErrorState title="Failed to load protocol data" detail={sectionErrors.sessions} onRetry={activeRunId ? () => selectRun(activeRunId) : undefined} />;
  } else if (!session) {
    body = <EmptyState title="No protocol events in this capture" />;
  } else if ((session.events?.length ?? 0) + (session.transitions?.length ?? 0) === 0) {
    body = <EmptyState title="No protocol events in this capture" detail={`Stream #${session.tcp_stream_id} carried no dissected protocol messages or state transitions.`} />;
  } else {
    body = <JourneyTimeline session={session} focusFrame={selectedEventFrame} />;
  }

  const duration = session?.timing && session.timing.end_epoch != null && session.timing.start_epoch != null
    ? `${((session.timing.end_epoch - session.timing.start_epoch) * 1000).toFixed(1)} ms`
    : null;

  return (
    <div className="sms-page">
      <header className="sms-page-head">
        <div>
          <h1 className="sms-page-title">Protocol journey</h1>
          <p className="sms-page-sub">Wire events and state-machine transitions for one TCP stream, in frame order. Transition rows are coloured by the evidence state the engine assigned.</p>
        </div>
        {sessions.length > 1 && (
          <label className="sms-muted" style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--ds-space-8)', fontSize: 'var(--ds-text-12)' }}>
            Stream
            <select className="sms-btn sms-btn--sm sms-mono" value={session?.stream_key ?? ''} onChange={(e) => selectSession(e.target.value)}>
              {sessions.map((s) => (
                <option key={s.stream_key} value={s.stream_key}>{sessionLabel(s)}</option>
              ))}
            </select>
          </label>
        )}
      </header>

      {session && (
        <div className="sms-meta-strip" aria-label="Session facts">
          <span>client <b>{endpointLabel(session.client) ?? 'not recorded'}</b></span>
          <span>server <b>{endpointLabel(session.server) ?? 'not recorded'}</b></span>
          <span>protocol <b>{session.protocol ?? 'not identified'}</b></span>
          <span>application <b>{humanize(session.app_state)}</b></span>
          <span>TLS <b>{humanize(session.tls_state)}</b></span>
          <span>capture <b>{humanize(session.completeness)}</b></span>
          {session.timing?.packet_count != null && <span>packets <b>{session.timing.packet_count}</b></span>}
          {session.timing && <span>frames <b>#{session.timing.first_frame} to #{session.timing.last_frame}</b></span>}
          {duration && <span>duration <b>{duration}</b></span>}
        </div>
      )}

      <Panel title="Timeline" meta={session ? `stream #${session.tcp_stream_id}` : undefined} flush>
        {body}
      </Panel>
    </div>
  );
};
