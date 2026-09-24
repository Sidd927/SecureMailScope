import React from 'react';
import type { SessionEvidence, EvidenceField } from '../../../api/types';
import { EvidenceBadge } from '../../common/EvidenceBadge';
import { ShieldCheck, Key, FileCheck, Lock } from 'lucide-react';

interface EvidenceMatrixProps {
  session: SessionEvidence;
}

interface DimensionGroup {
  id: string;
  title: string;
  description: string;
  icon: React.ElementType;
  fieldKeys: string[];
}

const DIMENSIONS: DimensionGroup[] = [
  {
    id: 'capability',
    title: '1. Capability Advertisement & Transport Upgrade',
    description: 'STARTTLS / STLS capability negotiation and transition from cleartext transport to TLS container.',
    icon: ShieldCheck,
    fieldKeys: [
      'starttls_advertised',
      'starttls_requested',
      'starttls_accepted',
      'tls_transition',
    ],
  },
  {
    id: 'crypto',
    title: '2. Cryptographic Parameters & Key Exchange',
    description: 'Protocol version, cipher suite selection, ephemeral key exchange, and Perfect Forward Secrecy (PFS).',
    icon: Key,
    fieldKeys: [
      'tls_negotiated_version',
      'tls_cipher_suite_name',
      'tls_cipher_suite',
      'tls_key_exchange',
      'tls_named_group',
      'tls_forward_secrecy',
    ],
  },
  {
    id: 'pki',
    title: '3. Public Key Infrastructure & Identity Bindings',
    description: 'Server certificate chain presence and validation.',
    icon: FileCheck,
    fieldKeys: [
      'tls_certificate_chain',
    ],
  },
  {
    id: 'application',
    title: '4. Post-Handshake Security & Authentication Boundary',
    description: 'Cleartext command continuation, credential exposure, and authentication posture.',
    icon: Lock,
    fieldKeys: [
      'plaintext_continuation',
      'auth_activity',
    ],
  },
];

const FIELD_LABELS: Record<string, { label: string; desc: string }> = {
  starttls_advertised: {
    label: 'STARTTLS Advertised',
    desc: 'Server capabilities greeting included the STARTTLS/STLS keyword.',
  },
  starttls_requested: {
    label: 'STARTTLS Requested',
    desc: 'Client issued STARTTLS command to initiate TLS upgrade.',
  },
  starttls_accepted: {
    label: 'STARTTLS Accepted',
    desc: 'Server accepted upgrade request (e.g. 220 Ready for TLS).',
  },
  tls_transition: {
    label: 'TLS Transition',
    desc: 'State machine transition into TLS encrypted mode.',
  },
  tls_negotiated_version: {
    label: 'Negotiated TLS Version',
    desc: 'TLS version selected in ServerHello or inferred from records.',
  },
  tls_cipher_suite_name: {
    label: 'Negotiated Cipher Suite',
    desc: 'IANA standard cipher suite negotiated in handshake.',
  },
  tls_key_exchange: {
    label: 'Key Exchange Mechanism',
    desc: 'Cryptographic mechanism for session secret generation.',
  },
  tls_named_group: {
    label: 'Named Group / Curve',
    desc: 'Diffie-Hellman group or elliptic curve used for key share.',
  },
  tls_forward_secrecy: {
    label: 'Forward Secrecy (PFS)',
    desc: 'Traffic cannot be retroactively decrypted if private key leaks.',
  },
  tls_certificate_chain: {
    label: 'Certificate Chain Present',
    desc: 'Whether server delivered an observable X.509 certificate chain.',
  },
  tls_cipher_suite: {
    label: 'Cipher Suite (Hex Code)',
    desc: 'Two-byte cipher suite ID negotiated in ServerHello.',
  },
  plaintext_continuation: {
    label: 'Plaintext Continuation Post-TLS',
    desc: 'Whether cleartext commands were observed after TLS negotiation.',
  },
  auth_activity: {
    label: 'Authentication Activity Observability',
    desc: 'Whether authentication commands (AUTH PLAIN/LOGIN) were observed.',
  },
};

export const EvidenceMatrix: React.FC<EvidenceMatrixProps> = ({ session }) => {
  const fields = (session.evidence || {}) as Record<string, EvidenceField | undefined>;

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '28px',
        width: '100%',
        maxWidth: '1080px',
        margin: '0 auto',
      }}
    >
      {/* Header Banner */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
          padding: '16px 20px',
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--color-border)',
          boxShadow: 'var(--shadow-subtle)',
        }}
      >
        <div>
          <div
            style={{
              fontSize: '10px',
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              fontWeight: 700,
              color: 'var(--color-accent)',
            }}
          >
            Cryptographic Epistemic Ledger
          </div>
          <h2 style={{ fontSize: 'var(--text-base)', fontWeight: 800, color: 'var(--color-ink)', marginTop: '2px' }}>
            13 Canonical Transport Evidence Dimensions
          </h2>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
          <span style={{ color: 'var(--color-ink-muted)' }}>STREAM #{session.tcp_stream_id}</span>
          <span style={{ color: 'var(--color-border-strong)' }}>•</span>
          <span style={{ color: 'var(--color-ink-muted)' }}>
            EPISTEMIC STATES: <strong style={{ color: 'var(--color-ink)' }}>STRICT BACKEND VERIFIED</strong>
          </span>
        </div>
      </div>

      {/* 4 Dimension Groups */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
        {DIMENSIONS.map((group) => {
          const Icon = group.icon;

          return (
            <div
              key={group.id}
              style={{
                backgroundColor: 'var(--color-surface)',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--color-border)',
                boxShadow: 'var(--shadow-subtle)',
                overflow: 'hidden',
              }}
            >
              {/* Group Header */}
              <div
                style={{
                  padding: '14px 20px',
                  backgroundColor: 'var(--color-panel)',
                  borderBottom: '1px solid var(--color-border)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div
                    style={{
                      width: '28px',
                      height: '28px',
                      borderRadius: 'var(--radius-xs)',
                      backgroundColor: 'var(--color-surface)',
                      border: '1px solid var(--color-border)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: 'var(--color-accent)',
                    }}
                  >
                    <Icon size={15} />
                  </div>

                  <div>
                    <h3
                      style={{
                        fontSize: 'var(--text-sm)',
                        fontWeight: 800,
                        color: 'var(--color-ink)',
                        lineHeight: 1.2,
                      }}
                    >
                      {group.title}
                    </h3>
                    <div style={{ fontSize: '11px', color: 'var(--color-ink-muted)', marginTop: '2px' }}>
                      {group.description}
                    </div>
                  </div>
                </div>
              </div>

              {/* Group Rows */}
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {group.fieldKeys.map((fieldKey, rIdx) => {
                  const field: EvidenceField | undefined = fields[fieldKey];
                  const meta = FIELD_LABELS[fieldKey] || { label: fieldKey, desc: '' };
                  const state = field?.state || 'NOT_OBSERVABLE';
                  const isLast = rIdx === group.fieldKeys.length - 1;

                  return (
                    <div
                      key={fieldKey}
                      style={{
                        display: 'grid',
                        gridTemplateColumns: '280px 140px 1fr',
                        alignItems: 'center',
                        gap: '16px',
                        padding: '14px 20px',
                        borderBottom: isLast ? 'none' : '1px solid var(--color-border-subtle)',
                        backgroundColor: rIdx % 2 === 1 ? 'var(--color-panel-card)' : 'transparent',
                        fontSize: 'var(--text-xs)',
                      }}
                    >
                      {/* Column 1: Field Name & Description */}
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                        <div style={{ fontWeight: 700, color: 'var(--color-ink)' }}>{meta.label}</div>
                        <div style={{ fontSize: '11px', color: 'var(--color-ink-muted)', lineHeight: 1.35 }}>
                          {meta.desc}
                        </div>
                      </div>

                      {/* Column 2: Epistemic State Badge */}
                      <div style={{ display: 'flex', alignItems: 'center' }}>
                        <EvidenceBadge state={state} size="md" />
                      </div>

                      {/* Column 3: Observed Value & Provenance Basis */}
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '12px',
                              fontWeight: 700,
                              color: field?.value !== null && field?.value !== undefined ? 'var(--color-ink)' : 'var(--color-ink-faint)',
                            }}
                          >
                            {field?.value !== null && field?.value !== undefined
                              ? typeof field.value === 'boolean'
                                ? field.value ? 'YES' : 'NO'
                                : String(field.value)
                              : '—'}
                          </span>

                          {field?.frames && field.frames.length > 0 && (
                            <span
                              style={{
                                fontFamily: 'var(--font-mono)',
                                fontSize: '10px',
                                color: 'var(--color-ink-muted)',
                                backgroundColor: 'var(--color-panel)',
                                border: '1px solid var(--color-border)',
                                padding: '1px 5px',
                                borderRadius: 'var(--radius-xs)',
                              }}
                            >
                              Frame(s): {field.frames.join(', ')}
                            </span>
                          )}
                        </div>

                        {field?.provenance && (
                          <div
                            style={{
                              fontSize: '11px',
                              fontFamily: 'var(--font-mono)',
                              color: 'var(--color-ink-secondary)',
                              lineHeight: 1.35,
                            }}
                          >
                            <span style={{ color: 'var(--color-ink-muted)' }}>Basis:</span> {field.provenance}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
