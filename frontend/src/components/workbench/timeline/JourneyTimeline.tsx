import React, { useEffect, useMemo, useRef } from 'react';
import type { SessionEvidence } from '../../../api/types';
import { EVIDENCE_FIELD_GROUPS, formatEvidenceValue } from '../../../utils/evidence';
import { presentBasis } from '../evidence/plainEvidence';
import { EvidenceBadge } from '../../common/EvidenceBadge';

interface Step {
  key: string;
  frame: number | null;
  frames: number[];
  kind: 'event' | 'evidence' | 'transition';
  direction: string | null;
  title: string;
  detail: string | null;
  full: string | null;
  state: string | null;
  time: number | null;
}

const DIRECTION: Record<string, string> = { CLIENT_TO_SERVER: 'C → S', SERVER_TO_CLIENT: 'S → C' };
const EVENT_STATE: Record<string, string> = {
  connected: 'CONNECTED',
  greeting: 'GREETING',
  capability_request: 'EHLO',
  capability_response: 'CAPABILITIES',
  auth_command: 'AUTH',
  auth_plain: 'AUTH',
  auth_login: 'AUTH',
  starttls_advertised: 'STARTTLS',
  starttls_command: 'STARTTLS',
  starttls_accepted: 'STARTTLS',
};
const EVENT_HINT: Record<string, string> = {
  connected: 'Connection established',
  greeting: 'Server greeting',
  capability_request: 'Client EHLO command',
  capability_response: 'Server capabilities',
  auth_command: 'Authentication command',
  auth_plain: 'Authentication command',
  auth_login: 'Authentication command',
  starttls_advertised: 'STARTTLS advertised',
  starttls_command: 'STARTTLS requested',
  starttls_accepted: 'STARTTLS accepted',
};
const humanize = (s: string) => s.replace(/_/g, ' ').toLowerCase();
function frameLabel(frames: number[]): string {
  if (!frames.length) return '—';
  const sorted = [...frames].sort((a, b) => a - b);
  if (sorted.length === 1) return `#${sorted[0]}`;
  const contiguous = sorted.every((n, i) => i === 0 || n === sorted[i - 1] + 1);
  if (contiguous) return `#${sorted[0]}–#${sorted[sorted.length - 1]}`;
  return `#${sorted[0]} +${sorted.length - 1}`;
}
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
      full: ev.detail || null,
      state: null,
      time: null,
    });
  });
  Object.entries(session.evidence ?? {}).forEach(([key, field]) => {
    if (!field?.frames?.length) return;
    const value = formatEvidenceValue(field.value);
    const gloss = field.basis ? presentBasis(field.basis, 96).show : null;
    const detail = value && gloss && !gloss.toLowerCase().includes(String(value).toLowerCase())
      ? `${value}. ${gloss}`
      : gloss || value || null;
    steps.push({
      key: `f-${key}`,
      frame: field.frames[0],
      frames: field.frames,
      kind: 'evidence',
      direction: null,
      title: FIELD_LABELS.get(key) ?? humanize(key),
      detail,
      full: [value, field.basis].filter(Boolean).join(': ') || null,
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
      detail: t.basis ? presentBasis(t.basis, 96).show : humanize(t.event),
      full: [humanize(t.event), t.basis].filter(Boolean).join(': ') || null,
      state: t.evidence_state ?? null,
      time: t.timestamp_epoch ?? null,
    });
  });
  // Frame order; within a frame: wire event, then the evidence it yielded, then the state change.
  return steps.sort((a, b) => (a.frame ?? Infinity) - (b.frame ?? Infinity) || ORDER[a.kind] - ORDER[b.kind]);
}

export const JourneyTimeline: React.FC<{ session: SessionEvidence; focusFrame: number | null }> = ({ session, focusFrame }) => {
  const steps = useMemo(() => {
    const built = buildSteps(session);
    const eventFrames = new Set(built.filter((s) => s.kind === 'event' && s.frame != null).map((s) => s.frame));
    const timeByFrame = new Map<number, number>();
    for (const s of built) {
      if (s.kind === 'transition' && s.frame != null && s.time != null && !timeByFrame.has(s.frame)) timeByFrame.set(s.frame, s.time);
    }
    const visible = built
      .filter((s) => !(s.kind === 'transition' && s.frame != null && eventFrames.has(s.frame)))
      .map((s) => (s.kind === 'event' && s.time == null && s.frame != null && timeByFrame.has(s.frame) ? { ...s, time: timeByFrame.get(s.frame)! } : s));
    const first = session.timing?.first_frame ?? null;
    if (first != null && !visible.some((s) => s.kind === 'event' && s.frame === first)) {
      visible.unshift({
        key: 'connected',
        frame: first,
        frames: [first],
        kind: 'event',
        direction: null,
        title: 'connected',
        detail: 'TCP session up',
        full: null,
        state: null,
        time: session.timing?.start_epoch ?? null,
      });
    }
    return visible;
  }, [session]);
  const start = session.timing?.start_epoch ?? null;
  const focusRef = useRef<HTMLLIElement | null>(null);

  useEffect(() => {
    focusRef.current?.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }, [focusFrame, session.stream_key]);

  let focusAssigned = false;
  return (
    <ol className="sms-timeline" aria-label={`Protocol steps for stream ${session.tcp_stream_id}`}>
      {steps.map((s) => {
        const isFocus = focusFrame != null && s.frames.includes(focusFrame);
        const ref = isFocus && !focusAssigned ? (focusAssigned = true, focusRef) : undefined;
        const rel = s.time != null && start != null ? `${((s.time - start) * 1000).toFixed(1)} ms` : null;
        const eventKey = s.kind === 'event' ? s.title.replace(/ /g, '_') : '';
        const eventState = eventKey ? EVENT_STATE[eventKey] : null;
        const eventHint = eventKey ? EVENT_HINT[eventKey] : null;
        const tone = s.state === 'OBSERVED' || !s.state ? 'neutral' : s.state === 'AMBIGUOUS' || s.state === 'INCOMPLETE' ? 'warning' : 'muted';
        return (
          <li
            key={s.key}
            ref={ref}
            className={`sms-step sms-step--${tone}${s.kind === 'transition' ? ' sms-step--transition' : ''}${isFocus ? ' is-focus' : ''}`}
          >
            <span className="sms-step__rail" aria-hidden="true"><span className={`sms-step__dot sms-step__dot--${tone}`} /></span>
            <span className="sms-step__frame" title={s.frames.length ? s.frames.map((f) => `#${f}`).join(', ') : undefined}>{frameLabel(s.frames)}</span>
            <span className="sms-step__time">{rel ?? ''}</span>
            {s.direction ? (
              <span className={`sms-step__dir sms-step__dir--${s.direction === 'SERVER_TO_CLIENT' ? 's' : 'c'}`}>
                {DIRECTION[s.direction] ?? s.direction}
              </span>
            ) : <span className="sms-step__dir" />}
            <div className="sms-step__copy">
              <p className="sms-step__title">{s.kind === 'event' && s.detail ? s.detail : s.title}</p>
              {s.kind === 'event' && eventHint && <p className="sms-step__detail">{eventHint}</p>}
              {s.kind !== 'event' && s.detail && <p className="sms-step__detail" title={s.full && s.full !== s.detail ? s.full : undefined}>{s.detail}</p>}
            </div>
            <div className="sms-step__aside">
              {eventState && <span className={`sms-progress-state sms-progress-state--${tone === 'warning' ? 'warning' : 'neutral'}`}>{eventState}</span>}
              {s.kind !== 'event' && <EvidenceBadge state={s.state} size="sm" variant="pill" />}
            </div>
          </li>
        );
      })}
    </ol>
  );
};
