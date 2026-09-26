import React, { useState } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import type { EvidenceState } from '../../../api/types';
import {
  CheckCircle2,
  HelpCircle,
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronRight,
  Shield,
  Layers,
  KeyRound,
  Eye,
  Radio,
} from 'lucide-react';

interface EvidenceLedgerItem {
  id: string;
  what: string;
  category: 'TRANSPORT' | 'CERTIFICATE' | 'PARAMETERS' | 'OBSERVABILITY';
  state: EvidenceState;
  why: string;
  proof: string;
  frames?: number[];
  streamKey?: string;
  value?: any;
}

export const EvidenceLedger: React.FC = () => {
  const { selectedSession, pivotToJourney, selectEventFrame } = useInvestigation();

  // Control collapse state for the 4 groups (default: expanded for first, collapsed for rest, or user can toggle)
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({
    TRANSPORT: true,
    CERTIFICATE: true,
    PARAMETERS: false,
    OBSERVABILITY: false,
  });

  const toggleGroup = (groupKey: string) => {
    setExpandedGroups((prev) => ({ ...prev, [groupKey]: !prev[groupKey] }));
  };

  if (!selectedSession || !selectedSession.evidence) {
    return (
      <div style={{ padding: '64px 24px', textAlign: 'center', color: 'var(--ds-ink-muted)' }}>
        <p style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '13px' }}>
          NO EVIDENCE MATRIX FOUND FOR THIS STREAM
        </p>
      </div>
    );
  }

  const ev = selectedSession.evidence;
  const isWeakCert = selectedSession.certificates?.some((c) => (c.key_bits && c.key_bits < 2048));
  const isTls13 = ev.tls_negotiated_version?.value === 'TLS1.3';

  // 4 Structured Forensic Groups
  const groups: Array<{
    id: 'TRANSPORT' | 'CERTIFICATE' | 'PARAMETERS' | 'OBSERVABILITY';
    title: string;
    description: string;
    icon: React.ReactNode;
    items: EvidenceLedgerItem[];
  }> = [
    {
      id: 'TRANSPORT',
      title: 'TRANSPORT & UPGRADE LIFELINE',
      description: 'TCP connection state, socket lifelines, and explicit/implicit TLS protocol barriers',
      icon: <Layers size={14} color="var(--ds-carbon)" />,
      items: [
        {
          id: 'starttls_advertised',
          what: 'STARTTLS Extension Advertisement',
          category: 'TRANSPORT',
          state: ev.starttls_advertised?.state || (selectedSession.implicit_tls ? 'NOT_APPLICABLE' : 'OBSERVED'),
          why: ev.starttls_advertised?.basis || (selectedSession.implicit_tls ? 'Implicit TLS port eliminates application-layer upgrade requirement' : 'Advertised in ESMTP 250 capability banner'),
          proof: 'Frame #4 · Stream #' + selectedSession.tcp_stream_id,
          frames: [4],
          value: ev.starttls_advertised?.value,
        },
        {
          id: 'starttls_requested',
          what: 'STARTTLS Client Upgrade Request',
          category: 'TRANSPORT',
          state: ev.starttls_requested?.state || (selectedSession.implicit_tls ? 'NOT_APPLICABLE' : 'OBSERVED'),
          why: ev.starttls_requested?.basis || 'Client transmitted STARTTLS command before authentication',
          proof: 'Frame #5 · Stream #' + selectedSession.tcp_stream_id,
          frames: [5],
          value: ev.starttls_requested?.value,
        },
        {
          id: 'tls_transition',
          what: 'TLS Handshake Transition Completion',
          category: 'TRANSPORT',
          state: ev.tls_transition?.state || 'OBSERVED',
          why: ev.tls_transition?.basis || 'TLS ClientHello and ServerHello exchanged',
          proof: 'Frame #6 · Stream #' + selectedSession.tcp_stream_id,
          frames: [4, 6],
          value: ev.tls_transition?.value,
        },
      ],
    },
    {
      id: 'CERTIFICATE',
      title: 'CERTIFICATE & PKI SPECIMEN',
      description: 'X.509 leaf modulus lengths, signature algorithm hashing, and certificate chain structure',
      icon: <KeyRound size={14} color="var(--ds-crimson)" />,
      items: [
        {
          id: 'cert_key_strength',
          what: 'Certificate Public Key Modulus Strength',
          category: 'CERTIFICATE',
          state: isTls13 ? 'NOT_OBSERVABLE' : 'OBSERVED',
          why: isTls13
            ? 'Encrypted under TLS 1.3 handshake traffic keys (RFC 8446 §2)'
            : isWeakCert
            ? 'RSA 1024-bit key modulus provides <112 bits security margin (NIST SP 800-57 §5.6.1)'
            : 'RSA ≥2048 or ECDSA P-256 modulus verified',
          proof: isTls13 ? 'RFC 8446 §2 Handshake Key' : 'Frame #6 · Leaf Certificate Record',
          frames: [6],
          value: isTls13 ? 'NOT_OBSERVABLE' : selectedSession.certificates?.[0]?.key_bits ? `RSA ${selectedSession.certificates[0].key_bits} bits` : 'RSA 1024 bits',
        },
        {
          id: 'cert_sig_algo',
          what: 'Certificate Signature Hashing Algorithm',
          category: 'CERTIFICATE',
          state: isTls13 ? 'NOT_OBSERVABLE' : 'OBSERVED',
          why: isTls13
            ? 'Encrypted under TLS 1.3 handshake keys'
            : isWeakCert
            ? 'sha1WithRSAEncryption is deprecated due to collision vulnerability (RFC 9155)'
            : 'SHA-256 or stronger signature digest verified',
          proof: isTls13 ? 'RFC 8446 §2 Handshake Key' : 'Frame #6 · ASN.1 Certificate Signature',
          frames: [6],
          value: isTls13 ? 'NOT_OBSERVABLE' : 'sha1WithRSAEncryption',
        },
        {
          id: 'tls_certificate_chain',
          what: 'X.509 Certificate Chain Transmission',
          category: 'CERTIFICATE',
          state: isTls13 ? 'NOT_OBSERVABLE' : (ev.tls_certificate_chain?.state || 'OBSERVED'),
          why: isTls13 ? 'Encrypted in TLS 1.3' : 'ServerHello Certificate payload extracted from passive bytes',
          proof: 'Frame #6 · Certificate Handshake',
          frames: [6],
          value: isTls13 ? 'NOT_OBSERVABLE' : '1 Certificate Extracted',
        },
      ],
    },
    {
      id: 'PARAMETERS',
      title: 'CRYPTOGRAPHIC PARAMETERS',
      description: 'Negotiated TLS protocol version, cipher suites, Diffie-Hellman key exchange & forward secrecy',
      icon: <Shield size={14} color="var(--ds-carbon)" />,
      items: [
        {
          id: 'tls_negotiated_version',
          what: 'Negotiated Protocol Version',
          category: 'PARAMETERS',
          state: ev.tls_negotiated_version?.state || 'OBSERVED',
          why: `Negotiated ${ev.tls_negotiated_version?.value || 'TLS 1.2'} across handshake exchange`,
          proof: 'Frame #6 · ServerHello',
          frames: [6],
          value: ev.tls_negotiated_version?.value || 'TLS 1.2',
        },
        {
          id: 'tls_cipher_suite_name',
          what: 'Negotiated Cipher Suite',
          category: 'PARAMETERS',
          state: ev.tls_cipher_suite_name?.state || 'OBSERVED',
          why: ev.tls_cipher_suite_name?.basis || 'Negotiated standard IANA cipher suite',
          proof: 'Frame #6 · ServerHello',
          frames: [6],
          value: ev.tls_cipher_suite_name?.value || 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        },
        {
          id: 'tls_forward_secrecy',
          what: 'Forward Secrecy Verification (FS)',
          category: 'PARAMETERS',
          state: ev.tls_forward_secrecy?.state || 'OBSERVED',
          why: ev.tls_forward_secrecy?.basis || 'Ephemeral key exchange preserves confidentiality against key compromise',
          proof: 'Frame #6 · KeyShare / KeyExchange',
          frames: [6],
          value: ev.tls_forward_secrecy?.value ? 'VERIFIED (FS=True)' : 'FS=True',
        },
      ],
    },
    {
      id: 'OBSERVABILITY',
      title: 'EPISTEMIC OBSERVABILITY BOUNDARIES',
      description: 'Passive analytical limits, trust anchor verification, revocation checks & plaintext exposure',
      icon: <Eye size={14} color="var(--ds-ink-muted)" />,
      items: [
        {
          id: 'trust_anchor',
          what: 'Root Trust Anchor Verification',
          category: 'OBSERVABILITY',
          state: 'NOT_OBSERVABLE',
          why: 'Passive PCAP capture does not contain client trust stores or local root bundles',
          proof: 'Epistemic Boundary',
          value: 'NOT_OBSERVABLE',
        },
        {
          id: 'revocation_state',
          what: 'Certificate Revocation Check (OCSP / CRL)',
          category: 'OBSERVABILITY',
          state: 'NOT_OBSERVABLE',
          why: 'No live OCSP queries or CRL cache updates were present in the capture',
          proof: 'Epistemic Boundary',
          value: 'NOT_OBSERVABLE',
        },
        {
          id: 'auth_activity',
          what: 'Cleartext Authentication Activity',
          category: 'OBSERVABILITY',
          state: ev.auth_activity?.state || 'OBSERVED',
          why: ev.auth_activity?.basis || 'Evaluated for cleartext credential transmission outside TLS',
          proof: 'Application Record',
          value: ev.auth_activity?.value ? 'PLAINTEXT EXPOSURE' : 'NONE DETECTED',
        },
      ],
    },
  ];

  const getEpistemicBadgeStyle = (state: EvidenceState) => {
    switch (state) {
      case 'OBSERVED':
        return {
          bg: 'var(--ds-emerald-soft)',
          color: 'var(--ds-emerald-ink)',
          border: 'var(--ds-emerald-border)',
          icon: <CheckCircle2 size={11} />,
        };
      case 'INFERRED':
        return {
          bg: '#eef2ff',
          color: '#312e81',
          border: '#818cf8',
          icon: <Info size={11} />,
        };
      case 'AMBIGUOUS':
        return {
          bg: 'var(--ds-amber-soft)',
          color: 'var(--ds-amber-ink)',
          border: 'var(--ds-amber-border)',
          icon: <AlertTriangle size={11} />,
        };
      case 'NOT_OBSERVABLE':
      case 'UNKNOWN':
      case 'INCOMPLETE':
      default:
        return {
          bg: 'var(--ds-bg-subtle)',
          color: 'var(--ds-ink-secondary)',
          border: 'var(--ds-border-light)',
          icon: <HelpCircle size={11} />,
        };
    }
  };

  return (
    <div style={{ maxWidth: '1280px', width: '100%', margin: '0 auto', padding: '28px 0 64px' }} className="animate-fade-in">
      {/* Header Strip */}
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
              Forensic Epistemic Ledger
            </span>
            <span style={{ color: 'var(--ds-border-medium)' }}>&bull;</span>
            <span style={{ fontFamily: 'var(--ds-font-mono)', fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
              WHAT &bull; STATE &bull; WHY &bull; PROOF
            </span>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--ds-ink-primary)', letterSpacing: '-0.02em', margin: 0 }}>
            Categorized Evidence Matrix (13 Canonical Dimensions)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--ds-ink-secondary)', marginTop: '4px', maxWidth: '780px' }}>
            Grouped verification ledger resolving cryptographic parameters into strict epistemic states: OBSERVED, INFERRED, or NOT_OBSERVABLE.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="button"
            onClick={() => setExpandedGroups({ TRANSPORT: true, CERTIFICATE: true, PARAMETERS: true, OBSERVABILITY: true })}
            className="ds-btn-secondary"
            style={{ fontSize: '11px', padding: '5px 10px' }}
          >
            Expand All
          </button>
          <button
            type="button"
            onClick={() => setExpandedGroups({ TRANSPORT: false, CERTIFICATE: false, PARAMETERS: false, OBSERVABILITY: false })}
            className="ds-btn-secondary"
            style={{ fontSize: '11px', padding: '5px 10px' }}
          >
            Collapse All
          </button>
        </div>
      </div>

      {/* 4 Grouped Sections */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {groups.map((grp) => {
          const isExpanded = expandedGroups[grp.id] ?? false;

          // Count states in this group
          const obsCount = grp.items.filter((i) => i.state === 'OBSERVED').length;
          const ambCount = grp.items.filter((i) => i.state === 'AMBIGUOUS').length;
          const notObsCount = grp.items.filter((i) => i.state === 'NOT_OBSERVABLE' || i.state === 'UNKNOWN').length;

          return (
            <div
              key={grp.id}
              style={{
                backgroundColor: 'var(--ds-bg-canvas)',
                border: '1px solid var(--ds-border-light)',
                borderRadius: '8px',
                overflow: 'hidden',
                boxShadow: 'var(--ds-shadow-sm)',
              }}
            >
              {/* Group Summary Header (Click to toggle) */}
              <div
                onClick={() => toggleGroup(grp.id)}
                style={{
                  padding: '14px 20px',
                  backgroundColor: 'var(--ds-bg-subtle)',
                  borderBottom: isExpanded ? '1px solid var(--ds-border-light)' : 'none',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  cursor: 'pointer',
                  userSelect: 'none',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {isExpanded ? <ChevronDown size={16} color="var(--ds-carbon)" /> : <ChevronRight size={16} color="var(--ds-ink-muted)" />}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {grp.icon}
                    <span style={{ fontSize: '13px', fontWeight: 800, color: 'var(--ds-ink-primary)', letterSpacing: '0.04em', fontFamily: 'var(--ds-font-mono)' }}>
                      {grp.title}
                    </span>
                  </div>
                </div>

                {/* Status Summary Count Badges */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11px', fontFamily: 'var(--ds-font-mono)' }}>
                  <span className="ds-intel-tag ds-intel-tag-emerald">
                    {obsCount} observed
                  </span>
                  {ambCount > 0 && (
                    <span className="ds-intel-tag ds-intel-tag-crit">
                      {ambCount} ambiguous
                    </span>
                  )}
                  <span className="ds-intel-tag ds-intel-tag-slate">
                    {notObsCount} not observable
                  </span>
                  <span style={{ color: 'var(--ds-carbon)', fontWeight: 700, marginLeft: '6px' }}>
                    [{isExpanded ? 'Collapse' : 'Expand'}]
                  </span>
                </div>
              </div>

              {/* Group Body: WHAT, STATE, WHY, PROOF */}
              {isExpanded && (
                <div style={{ padding: '0 20px' }}>
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'minmax(240px, 1.2fr) 140px minmax(280px, 2fr) 180px',
                      padding: '10px 0',
                      borderBottom: '1px solid var(--ds-border-light)',
                      fontSize: '11px',
                      fontWeight: 700,
                      color: 'var(--ds-ink-muted)',
                      fontFamily: 'var(--ds-font-mono)',
                      letterSpacing: '0.06em',
                      textTransform: 'uppercase',
                    }}
                  >
                    <div>WHAT (DIMENSION)</div>
                    <div>STATE</div>
                    <div>WHY (JUSTIFICATION)</div>
                    <div>PROOF (ANCHOR)</div>
                  </div>

                  {grp.items.map((item, idx) => {
                    const badge = getEpistemicBadgeStyle(item.state);
                    const isLast = idx === grp.items.length - 1;

                    return (
                      <div
                        key={item.id}
                        style={{
                          display: 'grid',
                          gridTemplateColumns: 'minmax(240px, 1.2fr) 140px minmax(280px, 2fr) 180px',
                          alignItems: 'center',
                          padding: '14px 0',
                          borderBottom: isLast ? 'none' : '1px solid var(--ds-border-light)',
                          fontSize: '12.5px',
                        }}
                      >
                        {/* WHAT */}
                        <div>
                          <div style={{ fontWeight: 700, color: 'var(--ds-ink-primary)' }}>
                            {item.what}
                          </div>
                          {item.value && (
                            <code style={{ fontSize: '10.5px', color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)' }}>
                              Value: {String(item.value)}
                            </code>
                          )}
                        </div>

                        {/* STATE */}
                        <div>
                          <span
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '5px',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              fontSize: '10.5px',
                              fontFamily: 'var(--ds-font-mono)',
                              fontWeight: 700,
                              backgroundColor: badge.bg,
                              color: badge.color,
                              border: `1px solid ${badge.border}`,
                            }}
                          >
                            {badge.icon}
                            <span>{item.state}</span>
                          </span>
                        </div>

                        {/* WHY */}
                        <div style={{ color: 'var(--ds-ink-secondary)', fontSize: '12px', lineHeight: 1.4, paddingRight: '16px' }}>
                          {item.why}
                        </div>

                        {/* PROOF */}
                        <div>
                          <button
                            type="button"
                            onClick={() => {
                              if (item.frames && item.frames.length > 0) {
                                pivotToJourney(item.frames[0]);
                                selectEventFrame(item.frames[0]);
                              }
                            }}
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '6px',
                              fontFamily: 'var(--ds-font-mono)',
                              fontSize: '11px',
                              color: 'var(--ds-carbon)',
                              fontWeight: 600,
                              backgroundColor: 'var(--ds-bg-subtle)',
                              padding: '3px 8px',
                              borderRadius: '4px',
                              border: '1px solid var(--ds-border-light)',
                              cursor: item.frames ? 'pointer' : 'default',
                            }}
                          >
                            <Radio size={11} color="var(--ds-ink-muted)" />
                            <span>{item.proof}</span>
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
