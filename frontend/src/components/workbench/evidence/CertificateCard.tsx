import React from 'react';
import type { Certificate, FindingRow } from '../../../api/types';
import { getSeverityTokens } from '../../../utils/severity';
import { Panel } from '../../common/Panel';

interface Props {
  cert: Certificate;
  keyFinding: FindingRow | null;
  validityFinding: FindingRow | null;
}

// Values are coloured only when a backend finding flags them for this stream; the
// frontend never judges key size or validity itself.
const flagged = (f: FindingRow | null) => {
  const t = getSeverityTokens(f?.severity);
  return t ? { color: t.text } : undefined;
};

const Row: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <>
    <span className="sms-kv__key">{label}</span>
    <span className="sms-kv__value" style={{ gridColumn: 'span 2' }}>{children}</span>
  </>
);

export const CertificateCard: React.FC<Props> = ({ cert, keyFinding, validityFinding }) => (
  <Panel title={`Certificate ${cert.index}`} meta={cert.index === 0 ? 'leaf' : 'chain'}>
    <div className="sms-kv">
      <Row label="Public key">
        <span style={flagged(keyFinding)}>
          {[cert.public_key_algorithm, cert.key_bits != null ? `${cert.key_bits} bits` : null].filter(Boolean).join(' · ') || '—'}
        </span>
        {keyFinding && <span className="sms-muted" style={{ display: 'block', fontFamily: 'var(--ds-font-sans)' }}>Flagged by finding: {keyFinding.title}</span>}
      </Row>
      <Row label="Valid from"><span style={flagged(validityFinding)}>{cert.not_before || '—'}</span></Row>
      <Row label="Valid until"><span style={flagged(validityFinding)}>{cert.not_after || '—'}</span></Row>
      <Row label="Serial">{cert.serial || '—'}</Row>
      <Row label="X.509 version">{cert.version ?? '—'}</Row>
      <Row label="Subject key ID">{cert.subject_key_id || '—'}</Row>
      <Row label="Authority key ID">{cert.authority_key_id || '—'}</Row>
      <Row label="Self-signed">{cert.self_signed === null || cert.self_signed === undefined ? '—' : String(cert.self_signed)}</Row>
      <Row label="SAN DNS names">{cert.san_dns_names?.length ? cert.san_dns_names.join(', ') : <span className="sms-muted">none reported</span>}</Row>
    </div>
  </Panel>
);
