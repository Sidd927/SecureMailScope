import React, { useMemo, useState } from 'react';
import { AlertTriangle, ShieldCheck, Radio, ChevronDown, ChevronUp } from 'lucide-react';
import { useInvestigation } from '../../../context/InvestigationContext';
import type { FindingRow } from '../../../api/types';
import { formatEvidenceValue, framesLabel } from '../../../utils/evidence';
import { EvidenceBadge } from '../../common/EvidenceBadge';
import { Panel } from '../../common/Panel';
import { SeverityBadge } from '../../common/SeverityBadge';
import { EmptyState, ErrorState, SkeletonRows } from '../../common/StateViews';
import { CertificateCard } from './CertificateCard';
import { endpointLabel } from '../../../utils/session';
import { presentBasis } from './plainEvidence';

const affects = (f: FindingRow, streamKey: string) => f.affected_stream_keys?.includes(streamKey) || f.stream_key === streamKey;

export const CertificateForensics: React.FC = () => {
  const {
    sessions,
    selectedSession,
    selectSession,
    dashboard,
    isLoading,
    sectionErrors,
    selectRun,
    activeRunId,
    pivotToJourney,
    selectEventFrame,
  } = useInvestigation();

  const [showDetails, setShowDetails] = useState(false);

  const withCerts = sessions.filter((s) => s.certificates?.length > 0);
  const session = selectedSession && selectedSession.certificates?.length ? selectedSession : withCerts[0] ?? selectedSession;

  const certFindings = useMemo(
    () => (session ? (dashboard?.findings ?? []).filter((f) => (f.issue_class ?? '').startsWith('CERTIFICATE') && affects(f, session.stream_key)) : []),
    [dashboard, session],
  );
  const keyFinding = certFindings.find((f) => /KEY/.test(f.issue_class ?? '')) ?? null;
  const validityFinding = certFindings.find((f) => /EXPIR|VALIDITY|NOT_YET/.test(f.issue_class ?? '')) ?? null;
  const chain = session?.evidence?.tls_certificate_chain;

  const openFrame = (frame: number) => {
    pivotToJourney(frame, session?.stream_key ?? undefined);
    selectEventFrame(frame);
  };

  const primaryCert = session?.certificates?.[0] ?? null;
  const certFrame = keyFinding?.frames?.[0] ?? chain?.frames?.[0] ?? session?.timing?.first_frame ?? null;
  const keyLine = primaryCert
    ? [primaryCert.public_key_algorithm, primaryCert.key_bits != null ? `${primaryCert.key_bits}-bit` : null].filter(Boolean).join(' ') || 'Key not recorded'
    : 'Not in cleartext';
  const negotiated = formatEvidenceValue(session?.evidence?.tls_negotiated_version?.value);
  const tls13 = Boolean(negotiated && /1\.3|0x0304/i.test(negotiated));

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
        {/* 1. CONCLUSION FIRST: CRYPTOGRAPHIC WEAKNESS */}
        {certFindings.length > 0 && (
          <div className="sms-cert-conclusion-card sms-cert-conclusion-card--critical" role="region" aria-label="Cryptographic weakness determination">
            <div className="sms-cert-conclusion__head">
              <div className="sms-cert-conclusion__title-wrap">
                <AlertTriangle size={18} className="sms-crimson-icon" aria-hidden="true" />
                <h2 className="sms-cert-conclusion__title">CRYPTOGRAPHIC WEAKNESS</h2>
              </div>
              <SeverityBadge severity={keyFinding?.severity ?? certFindings[0]?.severity ?? 'HIGH'} />
            </div>

            <div className="sms-cert-specs-grid">
              <div className="sms-cert-spec-item">
                <span className="sms-cert-spec-label">Public key</span>
                <span className="sms-cert-spec-val sms-mono">{keyLine}</span>
              </div>
              <div className="sms-cert-spec-item">
                <span className="sms-cert-spec-label">Validity</span>
                <span className="sms-cert-spec-val sms-mono">{primaryCert ? `${primaryCert.not_before || '—'} to ${primaryCert.not_after || '—'}` : 'Not recorded'}</span>
              </div>
              <div className="sms-cert-spec-item">
                <span className="sms-cert-spec-label">Identity</span>
                <span className="sms-cert-spec-val sms-mono">{primaryCert?.san_dns_names?.length ? primaryCert.san_dns_names.join(', ') : primaryCert?.self_signed ? 'Self-signed' : 'Not recorded'}</span>
              </div>
              <div className="sms-cert-spec-item">
                <span className="sms-cert-spec-label">Issuer link</span>
                <span className="sms-cert-spec-val sms-mono">{primaryCert?.authority_key_id || (primaryCert?.self_signed ? 'Same as subject key' : '—')}</span>
              </div>
              <div className="sms-cert-spec-item">
                <span className="sms-cert-spec-label">TLS</span>
                <span className="sms-cert-spec-val sms-mono">{negotiated || 'Not recorded'}</span>
              </div>
              <div className="sms-cert-spec-item">
                <span className="sms-cert-spec-label">Evidence frame</span>
                <span className="sms-cert-spec-val sms-mono">{certFrame != null ? `#${certFrame}` : '—'}</span>
              </div>
            </div>

            <div className="sms-cert-why">
              <span className="sms-label">Why it matters</span>
              <p className="sms-prose">
                {presentBasis(keyFinding?.explanation || keyFinding?.conclusion || certFindings[0]?.explanation || certFindings[0]?.conclusion || 'The engine flagged this certificate. Open the technical details for the recorded fields.', 160).show}
              </p>
            </div>

            <div className="sms-cert-conclusion__actions">
              {certFrame != null && (
              <button
                type="button"
                className="sms-btn sms-btn--primary"
                onClick={() => openFrame(certFrame)}
              >
                <Radio size={13} aria-hidden="true" />
                Open frame #{certFrame}
              </button>
              )}

              <button
                type="button"
                className="sms-btn sms-btn--ghost"
                onClick={() => setShowDetails(!showDetails)}
                aria-expanded={showDetails}
              >
                {showDetails ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                <span>{showDetails ? 'Hide details' : 'Technical details'}</span>
              </button>
            </div>
          </div>
        )}

        {/* 2. CONCLUSION FIRST: TLS 1.3 / NOT OBSERVABLE */}
        {!session.certificates?.length && tls13 && (
          <div className="sms-cert-conclusion-card sms-cert-conclusion-card--neutral" role="region" aria-label="Certificate observability determination">
            <div className="sms-cert-conclusion__head">
              <div className="sms-cert-conclusion__title-wrap">
                <ShieldCheck size={18} className="sms-brand-icon" aria-hidden="true" />
                <h2 className="sms-cert-conclusion__title">CERTIFICATE CONTENT: NOT OBSERVABLE</h2>
              </div>
              <span className="sms-badge sms-badge--muted">RFC 8446 Encrypted Handshake</span>
            </div>

            <p className="sms-prose sms-cert-lead">
              TLS 1.3 encrypts the certificate. This passive capture cannot read the X.509 payload.
            </p>

            {/* EXPLICIT OBSERVABILITY BREAKDOWN */}
            <div className="sms-observability-comparison-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--ds-space-16)', marginBottom: 'var(--ds-space-16)' }}>
              <div className="sms-observability-col sms-observability-col--established">
                <div className="sms-observability-col__head">
                  <span className="sms-dot sms-dot--emerald" aria-hidden="true" />
                  <span className="sms-label">Observable on wire</span>
                </div>
                <ul className="sms-list sms-list--bulleted" style={{ fontSize: 'var(--ds-text-12)', marginTop: '8px' }}>
                  <li>TLS mode and version negotiation (TLS 1.3 negotiated)</li>
                  <li>Handshake structure and record sequencing (ClientHello, ServerHello)</li>
                  <li>Available wire metadata, cipher suite ID, and key exchange group</li>
                </ul>
              </div>

              <div className="sms-observability-col sms-observability-col--unobservable">
                <div className="sms-observability-col__head">
                  <span className="sms-dot sms-dot--crimson" aria-hidden="true" />
                  <span className="sms-label">Not observable from capture</span>
                </div>
                <ul className="sms-list sms-list--bulleted" style={{ fontSize: 'var(--ds-text-12)', marginTop: '8px' }}>
                  <li>Certificate payload and X.509 public key modulus (encrypted in flight)</li>
                  <li>Intermediate chain hierarchy and authority key identifiers</li>
                  <li>Local trust store validation and revocation status (OCSP/CRL)</li>
                </ul>
              </div>
            </div>

            <details className="sms-cert-honesty-note">
              <summary>Why this is not a missing certificate</summary>
              <p>The payload stays encrypted under handshake keys. Trust anchors and revocation are not in a passive capture, so they are reported as not observable.</p>
            </details>

            {session.timing?.first_frame != null && (
              <div style={{ marginTop: 'var(--ds-space-12)' }}>
                <button
                  type="button"
                  className="sms-btn sms-btn--sm sms-btn--primary"
                  onClick={() => openFrame(session.timing?.first_frame ?? 1)}
                >
                  <Radio size={12} aria-hidden="true" />
                  <span>Open Handshake in Protocol Journey</span>
                </button>
              </div>
            )}
          </div>
        )}

        {!session.certificates?.length && !tls13 && certFindings.length === 0 && (
          <EmptyState title="No certificate in cleartext" detail="This stream did not expose an X.509 certificate. That is not treated as a TLS 1.3 result unless the negotiated version says so." />
        )}

        {/* 3. CHAIN EVIDENCE */}
        {chain && (
          <Panel title="Certificate chain evidence">
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--ds-space-12)', flexWrap: 'wrap' }}>
              <EvidenceBadge state={chain.state} />
              <div className="sms-stack sms-stack--tight" style={{ flex: 1, minWidth: 240 }}>
                {formatEvidenceValue(chain.value) && (
                  <p className="sms-mono" style={{ fontSize: 'var(--ds-text-13)', color: 'var(--ds-ink-primary)' }}>
                    {formatEvidenceValue(chain.value)} certificate(s) in chain
                  </p>
                )}
                {chain.basis && <p className="sms-prose" title={chain.basis}>{presentBasis(chain.basis).show}</p>}
                {framesLabel(chain.frames) && (
                  <p className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>
                    {framesLabel(chain.frames)}
                  </p>
                )}
              </div>
            </div>
          </Panel>
        )}

        {/* 4. TECHNICAL DETAILS (EXPANDABLE IF FINDINGS EXIST, OR VISIBLE DIRECTLY) */}
        {session.certificates?.length > 0 && (certFindings.length === 0 || showDetails) && (
          <Panel title="Technical certificate details" meta={`${session.certificates.length} certificate(s)`}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 280px), 1fr))', gap: 'var(--ds-space-16)' }}>
              {session.certificates.map((c) => (
                <CertificateCard
                  key={c.index}
                  cert={c}
                  keyFinding={c.index === 0 ? keyFinding : null}
                  validityFinding={c.index === 0 ? validityFinding : null}
                />
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
    <div className="sms-page sms-stage">
      <header className="sms-page-head">
        <div>
          <h1 className="sms-page-title">Certificates</h1>
          <p className="sms-page-sub">X.509 from the handshake. Trust and revocation are outside this capture.</p>
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

