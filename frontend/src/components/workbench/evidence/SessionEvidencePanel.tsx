import React, { useMemo } from 'react';
import { Radio } from 'lucide-react';
import { useInvestigation } from '../../../context/InvestigationContext';
import type { EvidenceField } from '../../../api/types';
import { EVIDENCE_FIELD_GROUPS, formatEvidenceValue, framesLabel } from '../../../utils/evidence';
import { EvidenceBadge } from '../../common/EvidenceBadge';
import { Panel } from '../../common/Panel';
import { EmptyState, ErrorState, SkeletonRows } from '../../common/StateViews';
import { sessionLabel } from '../../../utils/session';

export const SessionEvidencePanel: React.FC = () => {
  const { sessions, selectedSession, selectSession, sectionErrors, isLoading, selectRun, activeRunId, pivotToJourney, selectEventFrame } = useInvestigation();

  const groups = useMemo(() => {
    const ev = (selectedSession?.evidence ?? {}) as Record<string, EvidenceField | undefined>;
    return EVIDENCE_FIELD_GROUPS.map((g) => ({
      ...g,
      rows: g.fields.map((f) => ({ ...f, field: ev[f.key] })).filter((r): r is typeof r & { field: EvidenceField } => Boolean(r.field)),
    })).filter((g) => g.rows.length > 0);
  }, [selectedSession]);

  const selector = sessions.length > 1 && (
    <label style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--ds-space-8)', fontSize: 'var(--ds-text-12)' }} className="sms-muted">
      Stream
      <select
        className="sms-btn sms-btn--sm sms-mono"
        value={selectedSession?.stream_key ?? ''}
        onChange={(e) => selectSession(e.target.value)}
      >
        {sessions.map((s) => (
          <option key={s.stream_key} value={s.stream_key}>{sessionLabel(s)}</option>
        ))}
      </select>
    </label>
  );

  let body: React.ReactNode;
  if (isLoading && sessions.length === 0) body = <SkeletonRows rows={8} />;
  else if (sectionErrors.sessions) body = <ErrorState title="Session evidence failed to load" detail={sectionErrors.sessions} onRetry={activeRunId ? () => selectRun(activeRunId) : undefined} />;
  else if (!selectedSession || groups.length === 0) body = <EmptyState title="No evidence recorded for this capture" />;
  else body = (
    <div style={{ overflowX: 'auto' }}>
      <table className="sms-table" aria-label="Session evidence fields">
        <thead>
          <tr><th>Field</th><th>Value</th><th>State</th><th>Basis</th><th>Proof</th></tr>
        </thead>
        {groups.map((g) => (
          <tbody key={g.id}>
            <tr><td colSpan={5} style={{ background: 'var(--ds-bg-app)' }}><span className="sms-label">{g.title}</span></td></tr>
            {g.rows.map((row) => {
              const value = formatEvidenceValue(row.field.value);
              const proof = framesLabel(row.field.frames);
              return (
                <tr key={row.key}>
                  <td className="sms-cell-title" style={{ whiteSpace: 'nowrap' }}>{row.label}</td>
                  <td className="sms-mono" style={{ fontSize: 'var(--ds-text-12)', color: value ? 'var(--ds-ink-primary)' : undefined }}>{value ?? '—'}</td>
                  <td><EvidenceBadge state={row.field.state} size="sm" /></td>
                  <td style={{ fontSize: 'var(--ds-text-12)', lineHeight: 'var(--ds-leading-body)', padding: 'var(--ds-space-8) var(--ds-space-12)' }}>{row.field.basis}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {proof && (
                      <button
                        type="button"
                        className="sms-link"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--ds-space-4)' }}
                        onClick={() => { pivotToJourney(row.field.frames[0], selectedSession.stream_key); selectEventFrame(row.field.frames[0]); }}
                      >
                        <Radio size={11} aria-hidden="true" />{proof}
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        ))}
      </table>
    </div>
  );

  return (
    <Panel title="Session evidence" meta={selectedSession ? `stream #${selectedSession.tcp_stream_id}` : undefined} actions={selector || undefined} flush>
      {body}
    </Panel>
  );
};
