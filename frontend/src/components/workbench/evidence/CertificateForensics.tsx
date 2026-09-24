import React from 'react';
import type { SessionEvidence } from '../../../api/types';
import { ForensicHash } from '../../common/ForensicHash';
import { Award, AlertCircle } from 'lucide-react';

interface CertificateForensicsProps {
  session: SessionEvidence;
}

export const CertificateForensics: React.FC<CertificateForensicsProps> = ({ session }) => {
  const { certificates = [], certificate_notes = [], evidence } = session;
  const isTls13 = evidence?.tls_negotiated_version?.value === 'TLS1.3';

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '20px',
        padding: '24px',
        maxWidth: '960px',
        margin: '0 auto',
        width: '100%',
      }}
    >
      {/* TLS 1.3 Honesty Notice if applicable */}
      {isTls13 && (
        <div
          style={{
            padding: '16px 20px',
            backgroundColor: 'var(--color-panel-card)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '12px',
          }}
        >
          <AlertCircle size={18} style={{ color: 'var(--color-accent)', flexShrink: 0, marginTop: '2px' }} />
          <div>
            <div style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-ink)' }}>
              TLS 1.3 Encrypted Handshake Limitation (RFC 8446 §2)
            </div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-ink-secondary)', marginTop: '4px', lineHeight: 1.45 }}>
              In TLS 1.3, the server Certificate message is encrypted under handshake keys derived from the ephemeral
              Diffie-Hellman exchange. Consequently, certificate chain structure, key sizes, and validity are
              <strong> NOT PASSIVELY OBSERVABLE</strong> from network bytes without decryption keys.
            </div>
          </div>
        </div>
      )}

      {certificates.length === 0 ? (
        <div
          style={{
            backgroundColor: 'var(--color-surface)',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--color-border)',
            padding: '40px 24px',
            textAlign: 'center',
          }}
        >
          <div style={{ color: 'var(--color-ink-muted)', fontSize: 'var(--text-sm)' }}>
            No X.509 certificates were observed in this session's cleartext handshake.
          </div>
          <div style={{ color: 'var(--color-ink-faint)', fontSize: 'var(--text-xs)', marginTop: '6px' }}>
            {isTls13
              ? 'Handshake encrypted under TLS 1.3.'
              : session.implicit_tls
                ? 'Handshake records did not yield cleartext certificate frames.'
                : 'Session remained in plaintext or did not upgrade to TLS.'}
          </div>
        </div>
      ) : (
        certificates.map((cert, idx) => {
          const isWeakKey = cert.key_bits && cert.key_bits < 2048;
          return (
            <div
              key={idx}
              style={{
                backgroundColor: 'var(--color-surface)',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--color-border)',
                overflow: 'hidden',
                boxShadow: 'var(--shadow-subtle)',
              }}
            >
              {/* Certificate Header */}
              <div
                style={{
                  padding: '14px 20px',
                  borderBottom: '1px solid var(--color-border)',
                  backgroundColor: 'var(--color-panel)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Award size={16} style={{ color: 'var(--color-accent)' }} />
                  <div>
                    <span
                      style={{
                        fontSize: '10px',
                        fontFamily: 'var(--font-mono)',
                        textTransform: 'uppercase',
                        color: 'var(--color-ink-muted)',
                      }}
                    >
                      Certificate [{idx}] in Chain
                    </span>
                    <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-ink)' }}>
                      {cert.public_key_algorithm} {cert.key_bits ? `${cert.key_bits}-bit` : ''} Key
                    </h3>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {cert.self_signed ? (
                    <span
                      style={{
                        fontSize: '10px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        padding: '2px 6px',
                        backgroundColor: 'var(--color-sev-medium-bg)',
                        color: 'var(--color-sev-medium)',
                        border: '1px solid var(--color-sev-medium-border)',
                        borderRadius: 'var(--radius-xs)',
                      }}
                    >
                      SELF-SIGNED
                    </span>
                  ) : (
                    <span
                      style={{
                        fontSize: '10px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        padding: '2px 6px',
                        backgroundColor: 'var(--color-sev-low-bg)',
                        color: 'var(--color-sev-low)',
                        border: '1px solid var(--color-sev-low-border)',
                        borderRadius: 'var(--radius-xs)',
                      }}
                    >
                      CHAIN LINKED
                    </span>
                  )}

                  {isWeakKey && (
                    <span
                      style={{
                        fontSize: '10px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        padding: '2px 6px',
                        backgroundColor: 'var(--color-sev-critical-bg)',
                        color: 'var(--color-sev-critical)',
                        border: '1px solid var(--color-sev-critical-border)',
                        borderRadius: 'var(--radius-xs)',
                      }}
                    >
                      WEAK KEY (&lt;2048)
                    </span>
                  )}
                </div>
              </div>

              {/* Certificate Details Grid */}
              <div
                style={{
                  padding: '20px',
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                  gap: '16px',
                  fontSize: 'var(--text-xs)',
                }}
              >
                <div>
                  <div style={{ color: 'var(--color-ink-muted)', marginBottom: '4px' }}>Serial Number:</div>
                  <ForensicHash value={cert.serial} length={24} />
                </div>

                <div>
                  <div style={{ color: 'var(--color-ink-muted)', marginBottom: '4px' }}>Subject Key ID (SKI):</div>
                  <ForensicHash value={cert.subject_key_id || 'Not present in extensions'} length={24} />
                </div>

                <div>
                  <div style={{ color: 'var(--color-ink-muted)', marginBottom: '4px' }}>Authority Key ID (AKI):</div>
                  <ForensicHash value={cert.authority_key_id || 'Not present in extensions'} length={24} />
                </div>

                <div>
                  <div style={{ color: 'var(--color-ink-muted)', marginBottom: '4px' }}>Validity Window:</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--color-ink)' }}>
                    {cert.not_before} → {cert.not_after}
                  </div>
                </div>

                {cert.san_dns_names && cert.san_dns_names.length > 0 && (
                  <div style={{ gridColumn: '1 / -1' }}>
                    <div style={{ color: 'var(--color-ink-muted)', marginBottom: '4px' }}>
                      Subject Alternative Names (SANs):
                    </div>
                    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                      {cert.san_dns_names.map((name, sIdx) => (
                        <span
                          key={sIdx}
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '11px',
                            padding: '2px 8px',
                            backgroundColor: 'var(--color-panel)',
                            border: '1px solid var(--color-border)',
                            borderRadius: 'var(--radius-xs)',
                          }}
                        >
                          {name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        })
      )}

      {/* Certificate Dissection Notes */}
      {certificate_notes.length > 0 && (
        <div
          style={{
            padding: '14px 18px',
            backgroundColor: 'var(--color-panel)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-sm)',
            fontSize: 'var(--text-xs)',
          }}
        >
          <div style={{ fontWeight: 700, color: 'var(--color-ink)', marginBottom: '6px' }}>
            Dissection Observations:
          </div>
          <ul style={{ paddingLeft: '18px', color: 'var(--color-ink-secondary)', lineHeight: 1.4 }}>
            {certificate_notes.map((note, nIdx) => (
              <li key={nIdx}>{note}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
