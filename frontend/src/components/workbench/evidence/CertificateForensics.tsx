import React, { useMemo } from 'react';
import { KeyRound } from 'lucide-react';
import { useInvestigation } from '../../../context/InvestigationContext';
import type { FindingRow } from '../../../api/types';
import { formatEvidenceValue, framesLabel } from '../../../utils/evidence';
import { EvidenceBadge } from '../../common/EvidenceBadge';
import { Panel } from '../../common/Panel';
import { SeverityBadge } from '../../common/SeverityBadge';
import { EmptyState, ErrorState, SkeletonRows } from '../../common/StateViews';
import { CertificateCard } from './CertificateCard';
import { endpointLabel } from '../../../utils/session';

const affects = (f: FindingRow, streamKey: string) => f.affected_stream_keys?.includes(streamKey) || f.stream_key === streamKey;

export const CertificateForensics: React.FC = () => {
  const { sessions, selectedSession, selectSession, dashboard, isLoading, sectionErrors, selectRun, activeRunId } = useInvestigation();
  const withCerts = sessions.filter((s) => s.certificates?.length > 0);
  const session = selectedSession && selectedSession.certificates?.length ? selectedSession : withCerts[0] ?? selectedSession;

  const certFindings = useMemo(
    () => (session ? (dashboard?.findings ?? []).filter((f) => (f.issue_class ?? '').startsWith('CERTIFICATE') && affects(f, session.stream_key)) : []),
    [dashboard, session],
  );
  const keyFinding = certFindings.find((f) => /KEY/.test(f.issue_class ?? '')) ?? null;
  const validityFinding = certFindings.find((f) => /EXPIR|VALIDITY|NOT_YET/.test(f.issue_class ?? '')) ?? null;
  const chain = session?.evidence?.tls_certificate_chain;

  let body: React.ReactNode;
  if (isLoading && sessions.length === 0) {
    body = <SkeletonRows rows={6} height={40} />;
  } else if (sectionErrors.sessions) {
    body = <ErrorState title="Failed to load certificate data" detail={sectionErrors.sessions} onRetry={activeRunId ? () => selectRun(activeRunId) : undefined} />;
  } else if (!session) {
    body = <EmptyState title="No sessions in this capture" />;
  } else {
    body = (
      <div className="sms-stack">
        {chain && (
          <Panel title="Certificate chain evidence">
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--ds-space-12)', flexWrap: 'wrap' }}>
              <EvidenceBadge state={chain.state} />
              <div className="sms-stack sms-stack--tight" style={{ flex: 1, minWidth: 240 }}>
                {formatEvidenceValue(chain.value) && <p className="sms-mono" style={{ fontSize: 'var(--ds-text-13)', color: 'var(--ds-ink-primary)' }}>{formatEvidenceValue(chain.value)} certificate(s) in chain</p>}
                {chain.basis && <p className="sms-prose">{chain.basis}</p>}
                {framesLabel(chain.frames) && <p className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>{framesLabel(chain.frames)}</p>}
              </div>
            </div>
          </Panel>
        )}

        {session.certificates?.length ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: 'var(--ds-space-16)' }}>
            {session.certificates.map((c) => (
              <CertificateCard key={c.index} cert={c} keyFinding={c.index === 0 ? keyFinding : null} validityFinding={c.index === 0 ? validityFinding : null} />
            ))}
          </div>
        ) : (
          <Panel>
            <EmptyState icon={<KeyRound size={20} aria-hidden="true" />} title="No certificates were extracted from this stream" detail={chain ? undefined : "The engine reported no certificate evidence for this stream."} />
          </Panel>
        )}

        {certFindings.length > 0 && (
          <Panel title="Certificate findings" meta={String(certFindings.length)}>
            <div className="sms-stack sms-stack--tight">
              {certFindings.map((f) => (
                <div key={f.title} style={{ display: 'flex', gap: 'var(--ds-space-12)', alignItems: 'baseline' }}>
                  <SeverityBadge severity={f.severity} />
                  <div>
                    <p style={{ fontSize: 'var(--ds-text-14)', fontWeight: 500, color: 'var(--ds-ink-primary)' }}>{f.title}</p>
                    {f.conclusion && <p className="sms-prose">{f.conclusion}</p>}
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        )}

        {session.certificate_notes?.length > 0 && (
          <Panel title="Not attributable from this capture">
            <ul className="sms-list sms-list--bulleted">{session.certificate_notes.map((n) => <li key={n}>{n}</li>)}</ul>
          </Panel>
        )}
      </div>
    );
  }

  return (
    <div className="sms-page">
      <header className="sms-page-head">
        <div>
          <h1 className="sms-page-title">Certificates</h1>
          <p className="sms-page-sub">X.509 certificates parsed from cleartext handshake records. Trust anchors and revocation are not observable from a passive capture.</p>
        </div>
        {sessions.length > 1 && (
          <label className="sms-muted" style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--ds-space-8)', fontSize: 'var(--ds-text-12)' }}>
            Stream
            <select className="sms-btn sms-btn--sm sms-mono" value={session?.stream_key ?? ''} onChange={(e) => selectSession(e.target.value)}>
              {sessions.map((s) => (
                <option key={s.stream_key} value={s.stream_key}>#{s.tcp_stream_id} {s.certificates?.length ? `${s.certificates.length} cert` : 'no certs'} · {endpointLabel(s.server) ?? 'server not recorded'}</option>
              ))}
            </select>
          </label>
        )}
      </header>
      {body}
    </div>
  );
};
