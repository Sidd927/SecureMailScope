import React from 'react';
import { Layers } from 'lucide-react';
import type { SessionEvidence } from '../../../api/types';
import { getSeverityTokens } from '../../../utils/severity';
import { sessionLabel } from '../../../utils/session';

interface AssessedSessionsCardProps {
  sessions: SessionEvidence[];
  worstByStream: Map<string, string>;
  selectedStreamKey: string | null;
  onSelectSession: (streamKey: string) => void;
  onOpenJourney: (frame?: number, streamKey?: string) => void;
}

export const AssessedSessionsCard: React.FC<AssessedSessionsCardProps> = ({
  sessions,
  worstByStream,
  selectedStreamKey,
  onSelectSession,
  onOpenJourney,
}) => {
  return (
    <div className="sms-context-card" aria-label="Assessed TCP Sessions">
      <div className="sms-context-card__head">
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Layers size={13} style={{ color: 'var(--sms-brand-cyan)' }} aria-hidden="true" />
          <span className="sms-label">Assessed Sessions</span>
        </div>
        <span className="sms-mono sms-badge sms-badge--muted">{sessions.length} Streams</span>
      </div>

      <div className="sms-context-card__body">
        <ul className="sms-stream-list" role="list">
          {sessions.map((s) => {
            const worstSev = worstByStream.get(s.stream_key);
            const sev = getSeverityTokens(worstSev);
            const isSelected = selectedStreamKey === s.stream_key;

            return (
              <li key={s.stream_key}>
                <button
                  type="button"
                  className={`sms-stream-row ${isSelected ? 'sms-stream-row--active' : ''}`}
                  onClick={() => {
                    onSelectSession(s.stream_key);
                    onOpenJourney(s.timing?.first_frame ?? 1, s.stream_key);
                  }}
                  title={`${sessionLabel(s)} — Click to inspect in Protocol Journey`}
                >
                  <span
                    className="sms-dot"
                    style={{
                      backgroundColor: sev ? sev.rule : 'transparent',
                      border: sev ? 'none' : '1px solid var(--sms-border-strong)',
                    }}
                    aria-label={worstSev ? `Highest finding: ${worstSev}` : 'No finding'}
                  />
                  <span className="sms-mono sms-stream-row__id">#{s.tcp_stream_id}</span>
                  <span className="sms-stream-row__ip sms-mono">
                    {s.client.ip || 'unknown'}
                  </span>
                  <span className="sms-stream-row__proto sms-badge sms-badge--muted">
                    {s.protocol || 'TCP'}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
        <span className="sms-muted sms-text-xs" style={{ display: 'block', marginTop: '6px' }}>
          Color dot denotes the most severe finding affecting that stream.
        </span>
      </div>
    </div>
  );
};
