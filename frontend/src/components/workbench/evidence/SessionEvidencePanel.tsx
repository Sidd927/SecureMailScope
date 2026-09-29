import React, { useMemo, useState } from 'react';
import { ArrowLeftRight, ArrowRight, ChevronUp, Database, Info, Radio, Server, Settings2, Shield, UserRound } from 'lucide-react';
import { useInvestigation } from '../../../context/InvestigationContext';
import type { EvidenceField } from '../../../api/types';
import { EVIDENCE_FIELD_GROUPS, formatEvidenceValue, framesLabel } from '../../../utils/evidence';
import { EvidenceBadge } from '../../common/EvidenceBadge';
import { EmptyState, ErrorState, SkeletonRows } from '../../common/StateViews';
import { endpointLabel, sessionLabel } from '../../../utils/session';
import { presentBasis } from './plainEvidence';

const BasisLine: React.FC<{ text: string }> = ({ text }) => {
  const [open, setOpen] = useState(false);
  const { show, full } = presentBasis(text);
  if (!full) return <>{show}</>;
  return (
    <>
      {open ? full : show}{' '}
      <button type="button" className="sms-link" onClick={() => setOpen((v) => !v)}>
        {open ? 'Less' : 'More'}
      </button>
    </>
  );
};

const GROUP_ICONS: Record<string, React.ElementType> = {
  upgrade: ArrowLeftRight,
  parameters: Settings2,
  certificate: Shield,
  authentication: UserRound,
};

export const SessionEvidencePanel: React.FC = () => {
  const { sessions, selectedSession, selectSession, sectionErrors, isLoading, selectRun, activeRunId, pivotToJourney, selectEventFrame } = useInvestigation();
  const [open, setOpen] = useState(false);

  const groups = useMemo(() => {
    const ev = (selectedSession?.evidence ?? {}) as Record<string, EvidenceField | undefined>;
    return EVIDENCE_FIELD_GROUPS.map((g) => ({
      ...g,
      rows: g.fields.map((f) => ({ ...f, field: ev[f.key] })).filter((r): r is typeof r & { field: EvidenceField } => Boolean(r.field)),
    })).filter((g) => g.rows.length > 0);
  }, [selectedSession]);

  const selector = sessions.length > 1 && (
    <label className="sms-session-select sms-muted">
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

  const client = selectedSession ? endpointLabel(selectedSession.client) : null;
  const server = selectedSession ? endpointLabel(selectedSession.server) : null;

  let body: React.ReactNode;
  if (isLoading && sessions.length === 0) body = <SkeletonRows rows={8} />;
  else if (sectionErrors.sessions) body = <ErrorState title="Session evidence failed to load" detail={sectionErrors.sessions} onRetry={activeRunId ? () => selectRun(activeRunId) : undefined} />;
  else if (!selectedSession || groups.length === 0) body = <EmptyState title="No evidence recorded for this capture" />;
  else body = (
    <>
      <div className="sms-session-meta">
        <div className="sms-session-stream">
          <span className="sms-mono sms-session-stream__id">Stream #{selectedSession.tcp_stream_id}</span>
          {selectedSession.protocol && <span className="sms-session-proto">{selectedSession.protocol.toUpperCase()}</span>}
          <span className="sms-session-dir">client → server</span>
        </div>
        {selector}
      </div>

      <div className="sms-session-endpoints">
        <div className="sms-session-endpoint">
          <span className="sms-session-endpoint__icon" aria-hidden="true"><UserRound size={16} /></span>
          <span>
            <span className="sms-session-endpoint__role">Client</span>
            <span className="sms-mono sms-session-endpoint__value">{client ?? 'not recorded'}</span>
          </span>
        </div>
        <ArrowRight size={14} className="sms-session-endpoints__arrow" aria-hidden="true" />
        <div className="sms-session-endpoint">
          <span className="sms-session-endpoint__icon" aria-hidden="true"><Server size={16} /></span>
          <span>
            <span className="sms-session-endpoint__role">Server</span>
            <span className="sms-mono sms-session-endpoint__value">{server ?? 'not recorded'}</span>
          </span>
        </div>
        {(!client || !server) && (
          <p className="sms-session-endpoints__note">
            <Info size={14} aria-hidden="true" />
            <span>{!client && !server ? 'Endpoints not recorded.' : 'Missing side shown as not recorded.'}</span>
          </p>
        )}
      </div>

      <div className="sms-session-table-wrap">
        <table className="sms-table sms-evidence-table" aria-label="Session evidence fields">
          <thead>
            <tr><th>Label</th><th>Value</th><th>Status</th><th>Explanation</th><th>Frame</th></tr>
          </thead>
          {groups.map((g) => {
            const Icon = GROUP_ICONS[g.id] ?? Database;
            return (
              <tbody key={g.id}>
                <tr className="sms-evidence-group">
                  <td colSpan={5}>
                    <span className="sms-evidence-group__label">
                      <Icon size={13} aria-hidden="true" />
                      {g.title}
                    </span>
                  </td>
                </tr>
                {g.rows.map((row) => {
                  const value = formatEvidenceValue(row.field.value);
                  const proof = framesLabel(row.field.frames);
                  return (
                    <tr key={row.key}>
                      <td className="sms-cell-title">{row.label}</td>
                      <td className="sms-mono sms-evidence-value">{value ?? '—'}</td>
                      <td><EvidenceBadge state={row.field.state} size="sm" variant="pill" /></td>
                      <td className="sms-evidence-basis">{row.field.basis ? <BasisLine text={row.field.basis} /> : '—'}</td>
                      <td className="sms-evidence-proof">
                        {proof ? (
                          <button
                            type="button"
                            className="sms-link sms-evidence-proof__btn"
                            onClick={() => { pivotToJourney(row.field.frames[0], selectedSession.stream_key); selectEventFrame(row.field.frames[0]); }}
                          >
                            <Radio size={11} aria-hidden="true" />{proof}
                          </button>
                        ) : '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            );
          })}
        </table>
      </div>
    </>
  );

  return (
    <section className="sms-panel sms-session-panel" aria-label="Session evidence">
      <header className="sms-session-panel__head">
        <h3 className="sms-session-panel__title">
          <Database size={16} aria-hidden="true" />
          Session evidence
        </h3>
        <button
          type="button"
          className="sms-session-panel__toggle"
          aria-expanded={open}
          aria-label={open ? 'Collapse session evidence' : 'Expand session evidence'}
          onClick={() => setOpen((v) => !v)}
        >
          <ChevronUp size={16} aria-hidden="true" style={{ transform: open ? undefined : 'rotate(180deg)' }} />
        </button>
      </header>
      {open && <div className="sms-session-panel__body">{body}</div>}
    </section>
  );
};
