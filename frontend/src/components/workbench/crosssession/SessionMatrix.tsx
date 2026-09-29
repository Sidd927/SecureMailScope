import React, { useMemo } from 'react';
import { Crosshair } from 'lucide-react';
import type { EvidenceField, SessionEvidence } from '../../../api/types';
import { EVIDENCE_FIELD_GROUPS, evidenceStateMeta, formatEvidenceValue } from '../../../utils/evidence';
import { sessionRoute } from '../../../utils/session';

interface Props {
  sessions: SessionEvidence[];
  subjectStreamKeys: Set<string>;
}

const FIELDS = EVIDENCE_FIELD_GROUPS.flatMap((g) => g.fields);
const signature = (f: EvidenceField | undefined) => (f ? `${f.state}|${formatEvidenceValue(f.value) ?? ''}` : 'missing');

export const SessionMatrix: React.FC<Props> = ({ sessions, subjectStreamKeys }) => {
  // Columns grouped by client → server endpoint, the comparison unit the cross-session engine uses.
  const groups = useMemo(() => {
    const map = new Map<string, SessionEvidence[]>();
    for (const s of sessions) {
      const key = [sessionRoute({ client: { ip: s.client.ip, port: null }, server: s.server }), s.protocol].filter(Boolean).join(' ');
      map.set(key, [...(map.get(key) ?? []), s]);
    }
    return [...map.entries()];
  }, [sessions]);
  const ordered = groups.flatMap(([, list]) => list);

  const rows = FIELDS.map((f) => {
    const cells = ordered.map((s) => (s.evidence as unknown as Record<string, EvidenceField | undefined>)[f.key]);
    const counts = new Map<string, number>();
    cells.forEach((c) => counts.set(signature(c), (counts.get(signature(c)) ?? 0) + 1));
    // A strict majority defines "usual"; cells that differ from it are highlighted. With no
    // strict majority (e.g. a 6/6 split) the row is only marked as varying, nothing is singled out.
    const [top, topCount] = [...counts.entries()].sort((a, b) => b[1] - a[1])[0] ?? ['', 0];
    const majority = topCount > cells.length / 2 ? top : null;
    return { ...f, cells, varies: counts.size > 1, majority };
  }).filter((r) => r.cells.some(Boolean));

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="sms-matrix" aria-label="Evidence by session">
        <thead>
          <tr>
            <th />
            {groups.map(([label, list]) => (
              <th key={label} colSpan={list.length} className="sms-matrix__group">{label} · {list.length}</th>
            ))}
          </tr>
          <tr>
            <th className="sms-matrix__row-head">Field</th>
            {ordered.map((s) => (
              <th key={s.stream_key} scope="col" title={sessionRoute(s)}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--ds-space-4)' }}>#{s.tcp_stream_id}{subjectStreamKeys.has(s.stream_key) && <Crosshair size={10} aria-label="subject of a cross-session finding" style={{ color: 'var(--ds-amber)' }} />}</span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key}>
              <th scope="row" className="sms-matrix__row-head">
                {r.label}
                {r.varies && <span className="sms-mono sms-muted" style={{ marginLeft: 'var(--ds-space-8)', fontSize: 'var(--ds-text-12)' }}>varies</span>}
              </th>
              {r.cells.map((c, i) => {
                const meta = evidenceStateMeta(c?.state);
                const divergent = r.majority !== null && signature(c) !== r.majority;
                return (
                  <td
                    key={ordered[i].stream_key}
                    className={`sms-matrix__cell${divergent ? ' is-divergent' : ''}`}
                    title={c ? `${formatEvidenceValue(c.value) ?? 'no value'} (${c.state})${c.basis ? `: ${c.basis}` : ''}` : 'Not reported'}
                    style={{
                      color: meta ? `var(--ds-ev-${meta.token}-text)` : 'var(--ds-ink-faint)',
                      backgroundColor: meta ? `var(--ds-ev-${meta.token}-bg)` : 'transparent',
                      borderColor: meta ? `var(--ds-ev-${meta.token}-border)` : 'var(--ds-border-subtle)',
                      borderStyle: meta?.borderStyle ?? 'solid',
                    }}
                  >
                    {formatEvidenceValue(c?.value) ?? '·'}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
