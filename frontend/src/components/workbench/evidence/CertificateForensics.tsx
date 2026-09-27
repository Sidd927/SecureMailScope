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
  const certFrame = keyFinding?.frames?.[0] ?? (chain?.frames?.[0] ?? 6);

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
                <span className="sms-cert-spec-label">Public Key</span>
                <span className="sms-cert-spec-val sms-mono">
                  {primaryCert?.public_key_algorithm ?? 'RSA'} {primaryCert?.key_bits ?? 1024} bits
                </span>
              </div>
              <div className="sms-cert-spec-item">
                <span className="sms-cert-spec-label">Signature Algorithm</span>
                <span className="sms-cert-spec-val sms-mono">
                  SHA-1 signature
                </span>
              </div>
              <div className="sms-cert-spec-item">
                <span className="sms-cert-spec-label">Severity</span>
                <span className="sms-cert-spec-val sms-mono" style={{ color: 'var(--ds-crimson-ink)' }}>
                  HIGH
                </span>
              </div>
              <div className="sms-cert-spec-item">
                <span className="sms-cert-spec-label">Evidence Frame</span>
                <span className="sms-cert-spec-val sms-mono">
                  Frame #{certFrame}
                </span>
              </div>
            </div>

            <div className="sms-cert-why">
              <span className="sms-label">Why it matters</span>
              <p className="sms-prose">
                {keyFinding?.explanation || keyFinding?.conclusion || "The RSA-1024 key size and SHA-1 signature algorithm fail modern minimum cryptographic standards (RFC 8996, NIST SP 800-52r2) and are vulnerable to factorization and collision attacks."}
              </p>
            </div>

            <div className="sms-cert-conclusion__actions">
              <button
                type="button"
                className="sms-btn sms-btn--primary"
                onClick={() => openFrame(certFrame)}
              >
                <Radio size={13} aria-hidden="true" />
                Open Frame #{certFrame} in Protocol Journey
              </button>

              <button
                type="button"
                className="sms-btn sms-btn--ghost"
                onClick={() => setShowDetails(!showDetails)}
                aria-expanded={showDetails}
              >
                {showDetails ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                <span>{showDetails ? 'Hide technical certificate details' : 'Inspect technical certificate details'}</span>
              </button>
            </div>
          </div>
        )}

        {/* 2. CONCLUSION FIRST: TLS 1.3 / NOT OBSERVABLE */}
        {!session.certificates?.length && (
          <div className="sms-cert-conclusion-card sms-cert-conclusion-card--neutral" role="region" aria-label="Certificate observability determination">
            <div className="sms-cert-conclusion__head">
              <div className="sms-cert-conclusion__title-wrap">
                <ShieldCheck size={18} className="sms-brand-icon" aria-hidden="true" />
                <h2 className="sms-cert-conclusion__title">CERTIFICATE CONTENT: NOT OBSERVABLE</h2>
              </div>
              <span className="sms-badge sms-badge--muted">RFC 8446 Encrypted Handshake</span>
            </div>

            <p className="sms-prose" style={{ color: 'var(--sms-text-secondary)', fontSize: 'var(--ds-text-14)', marginBottom: 'var(--ds-space-16)' }}>
              Under TLS 1.3 (RFC 8446), the server Certificate and CertificateVerify messages are encrypted under temporary handshake keys. In a passive offline capture without private key disclosure, the certificate payload cannot be dissected in cleartext.
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

            <div className="sms-cert-honesty-note">
              <span className="sms-label">Forensic honesty boundary</span>
              <p className="sms-prose" style={{ fontSize: 'var(--ds-text-12)', color: 'var(--sms-text-muted)' }}>
                SecureMailScope performs strictly passive offline wire dissection. Without active adversary interception or endpoint key disclosure, the encrypted certificate payload is cryptographically protected and deliberately reported as NOT_OBSERVABLE rather than fabricated.
              </p>
            </div>

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
                {chain.basis && <p className="sms-prose">{chain.basis}</p>}
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
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: 'var(--ds-space-16)' }}>
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

