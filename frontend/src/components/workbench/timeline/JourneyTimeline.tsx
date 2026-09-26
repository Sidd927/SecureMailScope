import React, { useEffect, useMemo, useRef } from 'react';
import type { SessionEvidence } from '../../../api/types';
import { EVIDENCE_FIELD_GROUPS, evidenceStateMeta, formatEvidenceValue } from '../../../utils/evidence';
import { EvidenceBadge } from '../../common/EvidenceBadge';

interface Step {
  key: string;
  frame: number | null;
  frames: number[];
  kind: 'event' | 'evidence' | 'transition';
  direction: string | null;
  title: string;
  detail: string | null;
  state: string | null;
  time: number | null;
}

const DIRECTION: Record<string, string> = { CLIENT_TO_SERVER: 'C→S', SERVER_TO_CLIENT: 'S→C' };
const humanize = (s: string) => s.replace(/_/g, ' ').toLowerCase();
const FIELD_LABELS = new Map(EVIDENCE_FIELD_GROUPS.flatMap((g) => g.fields.map((f) => [f.key, f.label] as const)));
const ORDER = { event: 0, evidence: 1, transition: 2 } as const;

function buildSteps(session: SessionEvidence): Step[] {
  const steps: Step[] = [];
  (session.events ?? []).forEach((ev, i) => {
    steps.push({
      key: `e${i}`,
      frame: ev.frame ?? null,
      frames: ev.frame != null ? [ev.frame] : [],
      kind: 'event',
      direction: ev.direction ?? null,
      title: humanize(ev.kind),
      detail: ev.detail || null,
      state: null,
      time: null,
    });
  });
  Object.entries(session.evidence ?? {}).forEach(([key, field]) => {
    if (!field?.frames?.length) return;
    const value = formatEvidenceValue(field.value);
    steps.push({
      key: `f-${key}`,
      frame: field.frames[0],
      frames: field.frames,
      kind: 'evidence',
      direction: null,
      title: FIELD_LABELS.get(key) ?? humanize(key),
      detail: [value, field.basis].filter(Boolean).join(': ') || null,
      state: field.state,
      time: null,
    });
  });
  (session.transitions ?? []).forEach((t, i) => {
    steps.push({
      key: `t${i}`,
      frame: t.evidence_frames?.[0] ?? null,
      frames: t.evidence_frames ?? [],
      kind: 'transition',
      direction: null,
      title: `${humanize(t.from_state)} → ${humanize(t.to_state)}`,
      detail: [humanize(t.event), t.basis].filter(Boolean).join(': ') || null,
      state: t.evidence_state ?? null,
      time: t.timestamp_epoch ?? null,
    });
  });
  // Frame order; within a frame: wire event, then the evidence it yielded, then the state change.
  return steps.sort((a, b) => (a.frame ?? Infinity) - (b.frame ?? Infinity) || ORDER[a.kind] - ORDER[b.kind]);
}

export const JourneyTimeline: React.FC<{ session: SessionEvidence; focusFrame: number | null }> = ({ session, focusFrame }) => {
  const steps = useMemo(() => buildSteps(session), [session]);
  const start = session.timing?.start_epoch ?? null;
  const focusRef = useRef<HTMLLIElement | null>(null);

  useEffect(() => {
    focusRef.current?.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }, [focusFrame, session.stream_key]);

  let focusAssigned = false;
  return (
    <ol className="sms-timeline" aria-label={`Protocol steps for stream ${session.tcp_stream_id}`}>
      {steps.map((s) => {
        const meta = evidenceStateMeta(s.state);
        const isFocus = focusFrame != null && s.frames.includes(focusFrame);
        const ref = isFocus && !focusAssigned ? (focusAssigned = true, focusRef) : undefined;
        const bar = s.kind !== 'event' && meta ? `var(--ds-ev-${meta.token}-text)` : 'var(--ds-border-light)';
        const rel = s.time != null && start != null ? `+${((s.time - start) * 1000).toFixed(1)} ms` : null;
        return (
          <li
            key={s.key}
            ref={ref}
            className={`sms-step${s.kind === 'transition' ? ' sms-step--transition' : ''}${isFocus ? ' is-focus' : ''}`}
            style={{ borderLeftColor: bar }}
          >
            <span className="sms-step__frame">{s.frames.length ? `#${s.frames.join(', #')}` : '—'}</span>
            <span className="sms-step__dir">{s.direction ? DIRECTION[s.direction] ?? s.direction : ''}</span>
            <div style={{ minWidth: 0 }}>
              <p className="sms-step__title">{s.kind === 'evidence' && <span className="sms-label" style={{ marginRight: 'var(--ds-space-8)' }}>evidence</span>}{s.title}</p>
              {s.detail && <p className="sms-step__detail sms-mono">{s.detail}</p>}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 'var(--ds-space-4)' }}>
              {s.kind !== 'event' && <EvidenceBadge state={s.state} size="sm" />}
              {rel && <span className="sms-step__time">{rel}</span>}
            </div>
          </li>
        );
      })}
    </ol>
  );
};
