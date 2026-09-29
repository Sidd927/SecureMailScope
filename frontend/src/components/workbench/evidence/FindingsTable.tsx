import React from 'react';
import { Radio, GitFork, Search } from 'lucide-react';
import type { FindingRow } from '../../../api/types';

interface FindingsTableProps {
  findings: FindingRow[];
  selected: FindingRow | null;
  onSelect: (f: FindingRow) => void;
  onOpenFrame?: (frame: number, streamKey?: string) => void;
  onTrace?: (f: FindingRow) => void;
}

const isSame = (a: FindingRow | null, b: FindingRow) => !!a && a.rank === b.rank && a.title === b.title;

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  selected,
  onSelect,
  onOpenFrame,
  onTrace,
}) => {
  return (
    <div className="sms-finding-queue" role="list" aria-label="Investigation findings queue">
      {findings.map((f) => {
        const active = isSame(selected, f);
        const primaryFrame = f.frames && f.frames.length > 0 ? f.frames[0] : null;
        const sevClass = f.severity ? f.severity.toLowerCase() : 'info';

        return (
          <article
            key={`${f.rank}-${f.title}`}
            role="listitem"
            className={`sms-queue-row${active ? ' is-selected' : ''}`}
            tabIndex={0}
            aria-selected={active}
            onClick={() => onSelect(f)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onSelect(f);
              }
            }}
          >
            <div className="sms-queue-row__main">
              {/* Top: Status / Certainty eyebrow */}
              <div className="sms-queue-row__status-line">
                <span className={`sms-queue-row__sev sms-queue-row__sev--${sevClass}`}>
                  {f.severity || 'INFO'}
                </span>
              </div>

              <h3 className="sms-queue-row__title">{f.title}</h3>

              <div className="sms-queue-row__meta">
                {f.affected_sessions != null && (
                  <span>{f.affected_sessions} session{f.affected_sessions === 1 ? '' : 's'}</span>
                )}
                {f.tcp_stream_id != null && (
                  <>
                    <span className="sms-queue-row__sep" aria-hidden="true">·</span>
                    <span className="sms-mono">Stream #{f.tcp_stream_id}</span>
                  </>
                )}
                {primaryFrame != null && (
                  <>
                    <span className="sms-queue-row__sep" aria-hidden="true">·</span>
                    <span className="sms-mono">Frame #{primaryFrame}</span>
                  </>
                )}
              </div>
            </div>

            {/* Action Pivot */}
            <div className="sms-queue-row__actions" onClick={(e) => e.stopPropagation()}>
              <button
                type="button"
                className={`sms-btn sms-btn--sm sms-queue-iconbtn${active ? ' sms-btn--primary' : ''}`}
                onClick={() => onSelect(f)}
                title="Inspect evidence details"
                aria-label="Inspect evidence details"
              >
                <Search size={13} aria-hidden="true" />
              </button>

              {primaryFrame != null && onOpenFrame && (
                <button
                  type="button"
                  className="sms-btn sms-btn--sm sms-btn--ghost sms-queue-iconbtn"
                  onClick={() => onOpenFrame(primaryFrame, f.stream_key ?? undefined)}
                  title={`Open Frame #${primaryFrame} in Protocol Journey`}
                  aria-label={`Open Frame #${primaryFrame}`}
                >
                  <Radio size={13} aria-hidden="true" />
                </button>
              )}

              {onTrace && (
                <button
                  type="button"
                  className="sms-btn sms-btn--sm sms-btn--ghost sms-queue-iconbtn"
                  onClick={() => onTrace(f)}
                  title="Trace analytical provenance"
                  aria-label="Trace provenance"
                >
                  <GitFork size={13} aria-hidden="true" />
                </button>
              )}
            </div>
          </article>
        );
      })}
    </div>
  );
};

