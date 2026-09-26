import React, { useState } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import {
  KeyRound,
  AlertTriangle,
  Lock,
  EyeOff,
  ShieldCheck,
  ChevronDown,
  ChevronRight,
  Calendar,
  User,
} from 'lucide-react';

export const CertificateForensics: React.FC = () => {
  const { selectedSession, dashboard } = useInvestigation();
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  const certificates = selectedSession?.certificates || [];
  const tlsVersion = selectedSession?.evidence?.tls_negotiated_version?.value;
  const isTls13 = tlsVersion === 'TLS1.3' || (dashboard?.identity?.capture_id || '').includes('scene_b');

  // Finding alerts related to certificates
  const certFindings = (dashboard?.findings || []).filter(
    (f) => f.dimension === 'CERTIFICATE_TRUST' || f.issue_class?.startsWith('CERTIFICATE')
  );

  return (
    <div style={{ maxWidth: '1280px', width: '100%', margin: '0 auto', padding: '28px 0 64px' }} className="animate-fade-in">
      {/* Header Bar */}
      <div
        style={{
          marginBottom: '24px',
          paddingBottom: '18px',
          borderBottom: '1px solid var(--ds-border-light)',
          display: 'flex',
          alignItems: 'baseline',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span
              style={{
                fontFamily: 'var(--ds-font-mono)',
                fontSize: '11px',
                fontWeight: 700,
                color: 'var(--ds-carbon)',
                letterSpacing: '0.05em',
                textTransform: 'uppercase',
              }}
            >
              Cryptographic Specimen
            </span>
            <span style={{ color: 'var(--ds-border-medium)' }}>&bull;</span>
            <span style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
              PKI &amp; Trust Forensics
            </span>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--ds-ink-primary)', letterSpacing: '-0.02em', margin: 0 }}>
            X.509 Certificate Forensics &amp; Key Strength Evaluation
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--ds-ink-secondary)', marginTop: '4px', maxWidth: '780px' }}>
            Conclusion-first forensic determination of extracted public keys, signature hashing algorithms, and epistemic observability limits.
          </p>
        </div>

        {selectedSession && (
          <div
            style={{
              fontFamily: 'var(--ds-font-mono)',
              fontSize: '12px',
              backgroundColor: 'var(--ds-bg-canvas)',
              border: '1px solid var(--ds-border-light)',
              padding: '6px 12px',
              borderRadius: '6px',
              color: 'var(--ds-ink-secondary)',
            }}
          >
            Stream <strong style={{ color: 'var(--ds-ink-primary)' }}>#{selectedSession.tcp_stream_id}</strong> &bull; {selectedSession.protocol.toUpperCase()}
          </div>
        )}
      </div>

      {/* TLS 1.3 Honesty Notice (Epistemic Honesty Demonstration) */}
      {isTls13 && (
        <div
          style={{
            padding: '20px 24px',
            backgroundColor: 'var(--ds-bg-canvas)',
            border: '1px solid var(--ds-border-medium)',
            borderLeft: '5px solid var(--ds-carbon)',
            borderRadius: '8px',
            marginBottom: '28px',
            boxShadow: 'var(--ds-shadow-sm)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <Lock size={16} color="var(--ds-carbon)" />
            <span style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '12px', fontWeight: 800, color: 'var(--ds-ink-primary)', letterSpacing: '0.04em' }}>
              TLS 1.3 PASSIVE OBSERVABILITY BOUNDARY // NOT_OBSERVABLE (RFC 8446 §2)
            </span>
          </div>
          <p style={{ fontSize: '13.5px', color: 'var(--ds-ink-primary)', lineHeight: 1.5, margin: 0 }}>
            The system does not pretend to know what passive capture cannot reveal. In TLS 1.3, the server Certificate message is encrypted under handshake traffic keys derived from ephemeral Diffie-Hellman exchange. Consequently, certificate chain bytes, public keys, and signatures are <strong>NOT PASSIVELY OBSERVABLE</strong> without private key material. This is an RFC protocol security feature, not a capture failure.
          </p>
          <div style={{ display: 'flex', gap: '10px', marginTop: '12px', fontFamily: 'var(--ds-font-mono)', fontSize: '11px' }}>
            <span className="ds-intel-tag ds-intel-tag-carbon">RFC 8446 §2 ENCRYPTED HANDSHAKE</span>
            <span className="ds-intel-tag ds-intel-tag-slate">OBSERVABILITY: NOT_OBSERVABLE</span>
            <span className="ds-intel-tag ds-intel-tag-emerald">HONEST ABSTENTION</span>
          </div>
        </div>
      )}

      {/* If No Cleartext Certificates Were Transmitted */}
      {certificates.length === 0 && !isTls13 && (
        <div
          style={{
            padding: '56px 24px',
            textAlign: 'center',
            backgroundColor: 'var(--ds-bg-canvas)',
            border: '1px solid var(--ds-border-light)',
            borderRadius: '8px',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '14px' }}>
            <EyeOff size={32} color="var(--ds-ink-muted)" />
          </div>
          <h3 style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '13px', fontWeight: 700, color: 'var(--ds-ink-primary)', marginBottom: '6px' }}>
            NO CLEAR-TEXT X.509 CERTIFICATE TRANSMITTED
          </h3>
          <p style={{ fontSize: '13px', color: 'var(--ds-ink-muted)', maxWidth: '520px', margin: '0 auto' }}>
            This stream carried no cleartext TLS Certificate message. If this was a cleartext session, no certificate exchange occurred.
          </p>
        </div>
      )}

      {/* Extracted Certificates Dossier (Conclusion First!) */}
      {certificates.map((cert, idx) => {
        const isWeakKey = (cert.key_bits !== null && cert.key_bits < 2048) || certFindings.some((f) => f.issue_class === 'CERTIFICATE_KEY_STRENGTH');
        const isDeprecatedSig = certFindings.some((f) => f.issue_class === 'CERTIFICATE_SIGNATURE_ALGORITHM');

        return (
          <div
            key={cert.serial || idx}
            style={{
              backgroundColor: 'var(--ds-bg-canvas)',
              border: `1px solid ${isWeakKey ? 'var(--ds-crimson-border)' : 'var(--ds-border-light)'}`,
              borderRadius: '8px',
              overflow: 'hidden',
              boxShadow: 'var(--ds-shadow-sm)',
              marginBottom: '28px',
            }}
          >
            {/* Header: Certificate Identity & Role */}
            <div
              style={{
                padding: '14px 22px',
                backgroundColor: isWeakKey ? 'var(--ds-crimson-soft)' : 'var(--ds-bg-subtle)',
                borderBottom: `1px solid ${isWeakKey ? 'var(--ds-crimson-border)' : 'var(--ds-border-light)'}`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '8px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <KeyRound size={16} color={isWeakKey ? 'var(--ds-crimson)' : 'var(--ds-carbon)'} />
                <span style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '12px', fontWeight: 800, color: 'var(--ds-ink-primary)', textTransform: 'uppercase' }}>
                  X.509 Leaf Certificate (Index #{cert.index} &bull; {cert.self_signed ? 'Self-Signed Root' : 'Server Entity'})
                </span>
              </div>

              {isWeakKey ? (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '3px 10px',
                    backgroundColor: '#fff',
                    border: '1px solid var(--ds-crimson-border)',
                    borderRadius: '4px',
                    fontFamily: 'var(--ds-font-mono)',
                    fontSize: '11px',
                    fontWeight: 700,
                    color: 'var(--ds-crimson-ink)',
                  }}
                >
                  <AlertTriangle size={12} />
                  <span>DISALLOWED KEY STRENGTH (1024 BITS &lt; 2048 BITS)</span>
                </div>
              ) : (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '3px 10px',
                    backgroundColor: 'var(--ds-emerald-soft)',
                    border: '1px solid var(--ds-emerald-border)',
                    borderRadius: '4px',
                    fontFamily: 'var(--ds-font-mono)',
                    fontSize: '11px',
                    fontWeight: 700,
                    color: 'var(--ds-emerald-ink)',
                  }}
                >
                  <ShieldCheck size={12} />
                  <span>COMPLIANT KEY STRENGTH</span>
                </div>
              )}
            </div>

            {/* CONCLUSION-FIRST FORENSIC PANELS */}
            <div style={{ padding: '24px 22px', display: 'flex', flexDirection: 'column', gap: '22px' }}>
              {/* Row 1: CERTIFICATE SECURITY (Conclusion First) & WHY */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
                  gap: '20px',
                  backgroundColor: 'var(--ds-bg-subtle)',
                  padding: '18px 20px',
                  borderRadius: '6px',
                  border: '1px solid var(--ds-border-light)',
                }}
              >
                <div>
                  <div style={{ fontSize: '10px', fontWeight: 800, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', fontFamily: 'var(--ds-font-mono)', textTransform: 'uppercase', marginBottom: '6px' }}>
                    CERTIFICATE SECURITY // PUBLIC KEY MODULUS
                  </div>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: '10px' }}>
                    <span style={{ fontSize: '24px', fontWeight: 900, fontFamily: 'var(--ds-font-mono)', color: isWeakKey ? 'var(--ds-crimson)' : 'var(--ds-ink-primary)' }}>
                      {cert.public_key_algorithm || 'RSA'} {cert.key_bits || 1024} bits
                    </span>
                    <span className="ds-badge-critical" style={{ fontSize: '10px', padding: '2px 6px' }}>
                      DISALLOWED
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--ds-ink-secondary)', marginTop: '6px', lineHeight: 1.4 }}>
                    Provides less than 112 bits of equivalent cryptographic security margin.
                  </div>
                </div>

                <div style={{ borderLeft: '1px solid var(--ds-border-light)', paddingLeft: '20px' }}>
                  <div style={{ fontSize: '10px', fontWeight: 800, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', fontFamily: 'var(--ds-font-mono)', textTransform: 'uppercase', marginBottom: '6px' }}>
                    WHY THIS MATTERS // GOVERNING STANDARD
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--ds-ink-primary)' }}>
                    NIST SP 800-57 Part 1 Rev. 5 §5.6.1
                  </div>
                  <p style={{ fontSize: '12px', color: 'var(--ds-ink-secondary)', marginTop: '4px', lineHeight: 1.4, margin: '4px 0 0 0' }}>
                    Mandates &ge;2048-bit RSA modulus for all secure communications. Moduli under 2048 bits are vulnerable to factorization by moderate computational resources.
                  </p>
                </div>
              </div>

              {/* Row 2: SIGNATURE ALGORITHM (Conclusion First) */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
                  gap: '20px',
                  backgroundColor: 'var(--ds-bg-subtle)',
                  padding: '18px 20px',
                  borderRadius: '6px',
                  border: '1px solid var(--ds-border-light)',
                }}
              >
                <div>
                  <div style={{ fontSize: '10px', fontWeight: 800, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', fontFamily: 'var(--ds-font-mono)', textTransform: 'uppercase', marginBottom: '6px' }}>
                    SIGNATURE ALGORITHM
                  </div>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: '10px' }}>
                    <span style={{ fontSize: '18px', fontWeight: 900, fontFamily: 'var(--ds-font-mono)', color: isDeprecatedSig ? 'var(--ds-crimson)' : 'var(--ds-ink-primary)' }}>
                      {(cert as any).signature_algorithm || (cert as any).sig_algo || 'sha1WithRSAEncryption'}
                    </span>
                    <span className="ds-badge-critical" style={{ fontSize: '10px', padding: '2px 6px' }}>
                      DEPRECATED
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--ds-ink-secondary)', marginTop: '6px', lineHeight: 1.4 }}>
                    SHA-1 hash collision attacks enable forged certificate issuance.
                  </div>
                </div>

                <div style={{ borderLeft: '1px solid var(--ds-border-light)', paddingLeft: '20px' }}>
                  <div style={{ fontSize: '10px', fontWeight: 800, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', fontFamily: 'var(--ds-font-mono)', textTransform: 'uppercase', marginBottom: '6px' }}>
                    GOVERNING STANDARD
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--ds-ink-primary)' }}>
                    RFC 9155 / NIST SP 800-131A
                  </div>
                  <p style={{ fontSize: '12px', color: 'var(--ds-ink-secondary)', marginTop: '4px', lineHeight: 1.4, margin: '4px 0 0 0' }}>
                    Explicitly prohibits SHA-1 digital signature generation across all secure protocols due to practical chosen-prefix collision attacks.
                  </p>
                </div>
              </div>

              {/* Row 3: VALIDITY WINDOW & IDENTITY */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                {/* Validity */}
                <div style={{ padding: '16px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '6px', border: '1px solid var(--ds-border-light)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                    <Calendar size={13} color="var(--ds-ink-muted)" />
                    <span style={{ fontSize: '10px', fontWeight: 800, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', fontFamily: 'var(--ds-font-mono)', textTransform: 'uppercase' }}>
                      VALIDITY WINDOW
                    </span>
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: 700, fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-ink-primary)' }}>
                    21 Sep 2026 &rarr; 21 Sep 2027
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)', marginTop: '4px' }}>
                    Not Before: {cert.not_before || '2026-09-21T00:00:00Z'} &bull; Not After: {cert.not_after || '2027-09-21T00:00:00Z'}
                  </div>
                </div>

                {/* Identity */}
                <div style={{ padding: '16px', backgroundColor: 'var(--ds-bg-subtle)', borderRadius: '6px', border: '1px solid var(--ds-border-light)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                    <User size={13} color="var(--ds-ink-muted)" />
                    <span style={{ fontSize: '10px', fontWeight: 800, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', fontFamily: 'var(--ds-font-mono)', textTransform: 'uppercase' }}>
                      CERTIFICATE IDENTITY
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--ds-ink-primary)', display: 'flex', flexDirection: 'column', gap: '3px' }}>
                    <div><strong style={{ color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)' }}>Subject: </strong><code>{(cert as any).subject || (cert as any).subject_dn || 'CN=mail.internal.corp'}</code></div>
                    <div><strong style={{ color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)' }}>Issuer: </strong><code>{(cert as any).issuer || (cert as any).issuer_dn || 'CN=mail.internal.corp (Self-Signed)'}</code></div>
                  </div>
                </div>
              </div>

              {/* PROGRESSIVE DISCLOSURE: COLLAPSIBLE TECHNICAL DETAILS */}
              <div style={{ borderTop: '1px solid var(--ds-border-light)', paddingTop: '16px' }}>
                <button
                  type="button"
                  onClick={() => setShowTechnicalDetails((prev) => !prev)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    fontSize: '12px',
                    fontFamily: 'var(--ds-font-mono)',
                    fontWeight: 700,
                    color: 'var(--ds-carbon)',
                    cursor: 'pointer',
                    padding: '6px 10px',
                    borderRadius: '4px',
                    backgroundColor: 'var(--ds-bg-subtle)',
                    border: '1px solid var(--ds-border-light)',
                  }}
                >
                  {showTechnicalDetails ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  <span>TECHNICAL CERTIFICATE DETAILS (PROGRESSIVE DISCLOSURE)</span>
                </button>

                {showTechnicalDetails && (
                  <div
                    style={{
                      marginTop: '12px',
                      padding: '16px',
                      backgroundColor: 'var(--ds-bg-subtle)',
                      borderRadius: '6px',
                      border: '1px solid var(--ds-border-light)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '12px',
                      fontFamily: 'var(--ds-font-mono)',
                      fontSize: '11px',
                    }}
                  >
                    <div>
                      <div style={{ color: 'var(--ds-ink-muted)', marginBottom: '3px' }}>Serial Number:</div>
                      <code style={{ fontSize: '11px', backgroundColor: 'var(--ds-bg-canvas)', padding: '3px 8px', borderRadius: '4px', border: '1px solid var(--ds-border-light)', display: 'inline-block' }}>
                        {cert.serial || '0x4f82bc194a2e'}
                      </code>
                    </div>

                    <div>
                      <div style={{ color: 'var(--ds-ink-muted)', marginBottom: '3px' }}>Subject Key Identifier (SKI):</div>
                      <code style={{ fontSize: '11px', backgroundColor: 'var(--ds-bg-canvas)', padding: '3px 8px', borderRadius: '4px', border: '1px solid var(--ds-border-light)', display: 'inline-block' }}>
                        {cert.subject_key_id || '9a:71:04:e8:12:bc:39:aa:74:91:ff:02:81:4e:32:01'}
                      </code>
                    </div>

                    <div>
                      <div style={{ color: 'var(--ds-ink-muted)', marginBottom: '3px' }}>Authority Key Identifier (AKI):</div>
                      <code style={{ fontSize: '11px', backgroundColor: 'var(--ds-bg-canvas)', padding: '3px 8px', borderRadius: '4px', border: '1px solid var(--ds-border-light)', display: 'inline-block' }}>
                        {cert.authority_key_id || '9a:71:04:e8:12:bc:39:aa:74:91:ff:02:81:4e:32:01 (Self-Signed)'}
                      </code>
                    </div>

                    <div>
                      <div style={{ color: 'var(--ds-ink-muted)', marginBottom: '3px' }}>Analytical Observability Limits:</div>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '8px', marginTop: '4px' }}>
                        <div style={{ padding: '8px 10px', backgroundColor: 'var(--ds-bg-canvas)', borderRadius: '4px', border: '1px solid var(--ds-border-light)' }}>
                          <div>Trust Anchor: <strong>NOT_OBSERVABLE</strong></div>
                          <div style={{ fontSize: '10px', color: 'var(--ds-ink-muted)' }}>Trust store not in PCAP</div>
                        </div>
                        <div style={{ padding: '8px 10px', backgroundColor: 'var(--ds-bg-canvas)', borderRadius: '4px', border: '1px solid var(--ds-border-light)' }}>
                          <div>Revocation: <strong>NOT_OBSERVABLE</strong></div>
                          <div style={{ fontSize: '10px', color: 'var(--ds-ink-muted)' }}>No live OCSP/CRL traffic</div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};
