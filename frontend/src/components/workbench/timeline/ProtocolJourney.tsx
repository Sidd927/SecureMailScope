import React from 'react';
import { Clock, FileCode, Hash, Lock, Monitor, Server, Shield, UserRound, Waypoints } from 'lucide-react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { EmptyState, ErrorState, SkeletonRows } from '../../common/StateViews';
import { JourneyTimeline } from './JourneyTimeline';
import { ProtocolStateMachineStory } from './ProtocolStateMachineStory';
import { endpointLabel, sessionRoute } from '../../../utils/session';

const humanize = (s: string | null | undefined) => (s ? s.replace(/_/g, ' ').toLowerCase() : '—');

export const ProtocolJourney: React.FC = () => {
  const {
    sessions,
    selectedSession,
    selectSession,
    selectedEventFrame,
    selectEventFrame,
    isLoading,
    sectionErrors,
    selectRun,
    activeRunId,
  } = useInvestigation();
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

  const hasFlow = session && ((session.events?.length ?? 0) > 0 || (session.transitions?.length ?? 0) > 0);
  const selector = sessions.length > 1 && (
    <label className="sms-proto-select sms-muted">
      Stream
      <select className="sms-btn sms-btn--sm sms-mono" value={session?.stream_key ?? ''} onChange={(e) => selectSession(e.target.value)}>
        {sessions.map((s) => (
          <option key={s.stream_key} value={s.stream_key}>#{s.tcp_stream_id} {s.protocol ?? ''} {sessionRoute(s)}</option>
        ))}
      </select>
    </label>
  );

  const metrics = session ? [
    { icon: UserRound, label: 'Client', value: endpointLabel(session.client) ?? 'not recorded' },
    { icon: Server, label: 'Server', value: endpointLabel(session.server) ?? 'not recorded' },
    { icon: Waypoints, label: 'Protocol', value: session.protocol ?? 'not identified' },
    { icon: Monitor, label: 'Application', value: humanize(session.app_state) },
    { icon: Lock, label: 'TLS', value: humanize(session.tls_state) },
    { icon: Shield, label: 'Capture', value: humanize(session.completeness) },
    { icon: Hash, label: 'Packets', value: session.timing?.packet_count != null ? String(session.timing.packet_count) : '—' },
    { icon: FileCode, label: 'Frames', value: session.timing ? `#${session.timing.first_frame} to #${session.timing.last_frame}` : '—' },
    { icon: Clock, label: 'Duration', value: duration ?? '—' },
  ] : [];

  return (
    <div className="sms-page sms-protocol-page">
      <header className="sms-page-head sms-protocol-hero">
        <div>
          <h1 className="sms-page-title">Protocol journey</h1>
          <p className="sms-page-sub">One TCP stream, in frame order.</p>
        </div>
        <figure className="sms-context-visual sms-context-visual--handshake">
          <img
            src="/visuals/handshake.jpg"
            alt="A connection between two endpoints."
            width={736}
            height={414}
          />
        </figure>
      </header>

      {session && (
        <section className="sms-stream-card" aria-label="Session facts">
          <header className="sms-stream-card__bar">
            <h2 className="sms-stream-card__id">
              <Waypoints size={15} aria-hidden="true" />
              <span>Stream #{session.tcp_stream_id}</span>
              {session.protocol && <span className="sms-session-proto">{session.protocol.toUpperCase()}</span>}
              <span className="sms-mono sms-stream-card__route">{sessionRoute(session)}</span>
            </h2>
            {selector}
          </header>
          <dl className="sms-stream-metrics">
            {metrics.map((item) => {
              const Icon = item.icon;
              return (
                <div key={item.label} className="sms-stream-metric">
                  <dt>
                    <Icon size={14} aria-hidden="true" />
                    {item.label}
                  </dt>
                  <dd className="sms-mono">{item.value}</dd>
                </div>
              );
            })}
          </dl>
        </section>
      )}

      {hasFlow && session && (
        <ProtocolStateMachineStory
          session={session}
          focusFrame={selectedEventFrame}
          onSelectFrame={selectEventFrame}
        />
      )}

      <section className="sms-raw-card" aria-label="Raw event timeline">
        <header className="sms-raw-card__head">
          <div>
            <h2>Raw event timeline</h2>
            <p>Frame, time, direction, and evidence.</p>
          </div>
          {session && <span className="sms-mono sms-raw-card__meta">stream #{session.tcp_stream_id}</span>}
        </header>
        {body}
      </section>
    </div>
  );
};
