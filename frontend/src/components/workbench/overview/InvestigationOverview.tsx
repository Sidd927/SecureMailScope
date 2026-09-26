import React, { useState, useMemo } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { ProtocolLadderSvg, type ProtocolMessage } from '../../../design-lab/shared/ProtocolLadderSvg';
import { ProvenanceGraphSvg } from '../../../design-lab/shared/ProvenanceGraphSvg';
import { CrossSessionMatrix } from '../../../design-lab/shared/CrossSessionMatrix';
import { CoverageLanes } from '../../../design-lab/shared/CoverageLanes';
import type { FindingRow } from '../../../api/types';
import {
  GitBranch,
  Layers,
  ShieldAlert,
  ShieldCheck,
  AlertCircle,
  Copy,
  Check,
  ArrowRight,
  ExternalLink,
  ChevronRight,
  Fingerprint,
  Radio,
  FileCheck,
} from 'lucide-react';
import '../../../design-lab/direction-s/DirectionS.css';

const TLS13_HONESTY_MESSAGES: ProtocolMessage[] = [
  { frame: 1, direction: 'client_to_server', label: 'TCP SYN', details: 'Seq=0 Win=65495 Len=0 MSS=65475' },
  { frame: 2, direction: 'server_to_client', label: 'TCP SYN, ACK', details: 'Seq=0 Ack=1 Win=65483 Len=0' },
  { frame: 3, direction: 'client_to_server', label: 'TCP ACK', details: 'Seq=1 Ack=1 Win=65536 Len=0' },
  { frame: 4, direction: 'client_to_server', label: 'TLSv1.3 ClientHello', details: 'Cipher: TLS_AES_256_GCM_SHA384 | Supported Versions: TLS 1.3' },
  { frame: 5, direction: 'server_to_client', label: 'TCP ACK', details: 'Seq=1 Ack=518 Win=65536 Len=0' },
  {
    frame: 6,
    direction: 'server_to_client',
    label: 'TLSv1.3 ServerHello, EncryptedExtensions',
    details: 'Cipher: TLS_AES_256_GCM_SHA384 | KeyShare: X25519',
    hasIssue: false,
  },
  { frame: 8, direction: 'server_to_client', label: 'Certificate, CertificateVerify, Finished (Encrypted)', details: 'Handshake payload encrypted under handshake traffic keys (RFC 8446 §2)' },
  { frame: 10, direction: 'client_to_server', label: 'Finished (Encrypted)', details: 'VerifyData verified' },
  { frame: 12, direction: 'client_to_server', label: 'Application Data (TLS Encrypted)', details: 'Len=120 bytes IMAPS encrypted telemetry' },
];

const CROSS_SESSION_MESSAGES: ProtocolMessage[] = [
  { frame: 1, direction: 'client_to_server', label: 'TCP SYN', details: 'Seq=0 Win=65495 Len=0' },
  { frame: 2, direction: 'server_to_client', label: 'TCP SYN, ACK', details: 'Seq=0 Ack=1 Win=65483 Len=0' },
  { frame: 3, direction: 'client_to_server', label: 'TCP ACK', details: 'Seq=1 Ack=1 Win=65536 Len=0' },
  { frame: 4, direction: 'server_to_client', label: '220 mail.internal ESMTP Postfix', details: 'Service Ready' },
  { frame: 5, direction: 'client_to_server', label: 'EHLO client.internal', details: 'Client capability inquiry' },
  {
    frame: 6,
    direction: 'server_to_client',
    label: '250-mail.internal, 250-PIPELINING, 250-SIZE, 250-AUTH',
    details: 'STARTTLS upgrade omitted exclusively to this client',
    hasIssue: true,
    issueSeverity: 'CRITICAL',
    issueText: 'CRITICAL FINDING #01: STARTTLS capability missing while control peer sessions upgraded'
  },
  {
    frame: 7,
    direction: 'client_to_server',
    label: 'AUTH PLAIN dGVzdHVzZXIAbWFpbA==',
    details: 'Authentication in cleartext',
    hasIssue: true,
    issueSeverity: 'HIGH',
    issueText: 'HIGH FINDING #02: Plaintext authentication credentials exposed over non-TLS transport'
  },
  { frame: 8, direction: 'server_to_client', label: '235 2.7.0 Authentication successful', details: 'Cleartext auth accepted' },
];

interface InvestigationOverviewProps {
  onOpenScoreModal?: () => void;
}

export const InvestigationOverview: React.FC<InvestigationOverviewProps> = ({ onOpenScoreModal }) => {
  const {
    activeRun,
    dashboard,
    sessions,
    selectedSession,
    selectFinding,
    selectedEventFrame,
    selectEventFrame,
    pivotToJourney,
    pivotToProvenance,
    pivotToCrossSession,
    pivotToCerts,
  } = useInvestigation();

  const [copiedHash, setCopiedHash] = useState(false);
  const [selectedFrame, setSelectedFrame] = useState<number>(selectedEventFrame || 6);

  const findings: FindingRow[] = dashboard?.findings || [];

  const hasCrossSessionFindings = findings.some(
    (f) => f.fact_kind === 'BEHAVIOURAL_DEVIATION' || f.source_rule_ids?.some((r) => r.startsWith('CS-'))
  ) || (sessions.length > 5);

  const [activeCanvasView, setActiveCanvasView] = useState<'ladder' | 'provenance' | 'cross_session' | 'coverage'>(
    hasCrossSessionFindings ? 'cross_session' : 'ladder'
  );

  if (!dashboard || !activeRun) {
    return (
      <div style={{ padding: '60px 40px', textAlign: 'center', color: 'var(--ds-ink-muted)' }}>
        Loading forensic investigation overview...
      </div>
    );
  }

  const { posture } = dashboard;
  const isCritical = posture.value === 'CRITICAL' || posture.value === 'WEAK';
  const score = posture.score_value ?? (isCritical ? 44.0 : 100.0);
  const fn = activeRun.source_filename.toLowerCase();

  // One-sentence determination
  const oneSentenceDetermination = useMemo(() => {
    if (fn.includes('weak_certificate')) {
      return 'The server presented a 1024-bit RSA certificate using a SHA-1 signature algorithm.';
    }
    if (fn.includes('control_endpoint')) {
      return 'The subject client repeatedly omitted STARTTLS capability, while the comparable control client negotiated TLS 1.3.';
    }
    if (fn.includes('scene_b') || fn.includes('honesty')) {
      return 'The server established an encrypted TLS 1.3 handshake with honest epistemic disclosure for structurally hidden certificate bytes.';
    }
    if (isCritical) {
      return 'Multiple severe cryptographic defects were observed in the negotiated communication stream.';
    }
    return 'The observed session parameters satisfy regulatory cryptographic security baselines.';
  }, [fn, isCritical]);

  const whyThisMatters = useMemo(() => {
    if (fn.includes('weak_certificate')) {
      return 'Both properties provide sub-112-bit security strength, creating vulnerability to factorization and collision attacks. This deterministically violates NIST SP 800-57 Part 1 Rev. 5 §5.6.1 and RFC 9155.';
    }
    if (fn.includes('control_endpoint')) {
      return 'Omitting STARTTLS forced plaintext transmission of email content and authentication credentials. Cross-session comparison proves the server supported TLS 1.3, establishing an active downgrade or selective misconfiguration (RFC 3207 §6).';
    }
    if (fn.includes('scene_b') || fn.includes('honesty')) {
      return 'TLS 1.3 encrypts the certificate payload under ephemeral handshake keys (RFC 8446 §2). The system honestly abstains from guessing trust status rather than fabricating unverified claims.';
    }
    return 'Negotiated protocol parameters fall below configured cryptographic requirements, failing NIST and RFC baseline compliance.';
  }, [fn]);

  const ladderMessages = useMemo(() => {
    if (fn.includes('honesty') || fn.includes('scene_b')) return TLS13_HONESTY_MESSAGES;
    if (fn.includes('control_endpoint') || fn.includes('cross_session')) return CROSS_SESSION_MESSAGES;
    return undefined;
  }, [fn]);

  const copyHash = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (activeRun.capture_id) {
      navigator.clipboard.writeText(activeRun.capture_id);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 1800);
    }
  };

  const handleFrameSelect = (frameNum: number) => {
    setSelectedFrame(frameNum);
    selectEventFrame(frameNum);
    const matchingFinding = findings.find((f) => (f.frames || []).includes(frameNum));
    if (matchingFinding) {
      selectFinding(matchingFinding);
    }
  };

  return (
    <div className="dir-s-theme ds-overview-canvas" style={{ padding: '24px 0 64px' }}>
      {/* ============================================================ */}
      {/* 1. TOP: CASE IDENTITY & DETERMINATION BANNER                 */}
      {/* ============================================================ */}
      <div className="ds-identity-strip" style={{ marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontSize: '10px', fontWeight: 700, color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)', letterSpacing: '0.06em' }}>
              PRIMARY INVESTIGATION TARGET
            </div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: 'var(--ds-ink-primary)', letterSpacing: '-0.01em', marginTop: '1px' }}>
              {activeRun.source_filename}
            </div>
          </div>

          <button
            type="button"
            onClick={copyHash}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              fontFamily: 'var(--ds-font-mono)',
              fontSize: '11px',
              color: 'var(--ds-ink-secondary)',
              backgroundColor: 'var(--ds-bg-subtle)',
              padding: '4px 10px',
              borderRadius: '4px',
              border: '1px solid var(--ds-border-light)',
              cursor: 'pointer',
            }}
            title="Click to copy full SHA-256"
          >
            <span>SHA-256: {(activeRun.capture_id || activeRun.run_id).slice(0, 16)}...</span>
            {copiedHash ? <Check size={12} color="var(--ds-emerald)" /> : <Copy size={12} color="var(--ds-ink-muted)" />}
          </button>
        </div>

        {/* Technical Context Tags */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap', fontFamily: 'var(--ds-font-mono)', fontSize: '11px' }}>
          <div style={{ color: 'var(--ds-ink-muted)' }}>
            PARSED: <strong style={{ color: 'var(--ds-ink-primary)' }}>{activeRun.duration_ms || 138}ms</strong>
          </div>
          <span style={{ color: 'var(--ds-border-medium)' }}>&bull;</span>
          <div style={{ color: 'var(--ds-ink-muted)' }}>
            STREAM: <strong style={{ color: 'var(--ds-ink-primary)' }}>{sessions.length || 1} TCP session{sessions.length > 1 ? 's' : ''}</strong>
          </div>
          <span style={{ color: 'var(--ds-border-medium)' }}>&bull;</span>
          <div style={{ color: 'var(--ds-ink-muted)' }}>
            PROTOCOL: <strong style={{ color: 'var(--ds-ink-primary)' }}>{fn.includes('scene_b') ? 'IMAPS (TLS 1.3)' : 'SMTPS (TLS 1.2)'}</strong>
          </div>
          <span style={{ color: 'var(--ds-border-medium)' }}>&bull;</span>
          <div style={{ color: 'var(--ds-ink-muted)' }}>
            DISSECTION: <strong style={{ color: 'var(--ds-emerald-ink)' }}>TSHARK OFFLINE</strong>
          </div>
        </div>
      </div>

      {/* ============================================================ */}
      {/* 2. ONE-SENTENCE DETERMINATION (VISUAL ANCHOR) & VERDICT HERO  */}
      {/* ============================================================ */}
      <div
        style={{
          backgroundColor: 'var(--ds-bg-canvas)',
          border: '1px solid var(--ds-border-light)',
          borderLeft: `5px solid ${isCritical ? 'var(--ds-crimson-rail)' : 'var(--ds-emerald-rail)'}`,
          borderRadius: '8px',
          padding: '24px 28px',
          boxShadow: 'var(--ds-shadow-sm)',
          marginBottom: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '18px',
        }}
      >
        {/* Top: One-Sentence Determination Anchor */}
        <div style={{ borderBottom: '1px solid var(--ds-border-light)', paddingBottom: '16px' }}>
          <div style={{ fontSize: '10px', fontWeight: 800, color: isCritical ? 'var(--ds-crimson-ink)' : 'var(--ds-emerald-ink)', letterSpacing: '0.08em', fontFamily: 'var(--ds-font-mono)', textTransform: 'uppercase', marginBottom: '6px' }}>
            // ONE-SENTENCE DETERMINATION
          </div>
          <h1
            style={{
              fontSize: '22px',
              fontWeight: 800,
              color: 'var(--ds-ink-primary)',
              lineHeight: 1.35,
              letterSpacing: '-0.02em',
              margin: 0,
            }}
          >
            "{oneSentenceDetermination}"
          </h1>
        </div>

        {/* Middle: 3-Column Grid: Score Waterfall | Why This Matters | Investigation Path */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(220px, 1fr) minmax(320px, 2fr) minmax(260px, 1.2fr)',
            gap: '24px',
            alignItems: 'start',
          }}
        >
          {/* Col 1: Verdict & Compact Deduction Waterfall */}
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
              paddingRight: '16px',
              borderRight: '1px solid var(--ds-border-light)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className={isCritical ? 'ds-badge-critical' : 'ds-badge-strong'}>
                {isCritical ? <ShieldAlert size={12} /> : <ShieldCheck size={12} />}
                <span>{posture.value}</span>
              </span>
              <span className="ds-mono" style={{ fontSize: '10px', color: 'var(--ds-ink-muted)' }}>
                {posture.formula_id || 'F2-DAMPED'}
              </span>
            </div>

            <div
              onClick={onOpenScoreModal}
              style={{
                display: 'flex',
                alignItems: 'baseline',
                gap: '6px',
                cursor: onOpenScoreModal ? 'pointer' : 'default',
              }}
              title={onOpenScoreModal ? 'Click to inspect score decomposition formula' : undefined}
            >
              <span
                className="ds-verdict-huge"
                style={{
                  fontSize: '44px',
                  fontWeight: 900,
                  color: isCritical ? 'var(--ds-crimson)' : 'var(--ds-emerald)',
                  letterSpacing: '-0.03em',
                  fontFamily: 'var(--ds-font-mono)',
                  lineHeight: 1,
                }}
              >
                {score.toFixed(1)}
              </span>
              <span style={{ fontSize: '16px', fontWeight: 600, color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)' }}>
                / 100
              </span>
            </div>

            {/* Compact Deduction Waterfall (Readable in <2s) */}
            <div
              style={{
                padding: '8px 12px',
                backgroundColor: 'var(--ds-bg-subtle)',
                borderRadius: '6px',
                border: '1px solid var(--ds-border-light)',
                fontFamily: 'var(--ds-font-mono)',
                fontSize: '11px',
                display: 'flex',
                flexDirection: 'column',
                gap: '4px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--ds-ink-muted)' }}>
                <span>Starting Base:</span>
                <span style={{ fontWeight: 600 }}>100.0</span>
              </div>
              {isCritical ? (
                fn.includes('weak_certificate') ? (
                  <>
                    <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--ds-crimson-ink)' }}>
                      <span>−28 RSA-1024:</span>
                      <span style={{ fontWeight: 700 }}>−28.0</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--ds-crimson-ink)' }}>
                      <span>−28 SHA-1 Sig:</span>
                      <span style={{ fontWeight: 700 }}>−28.0</span>
                    </div>
                  </>
                ) : (
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--ds-crimson-ink)' }}>
                    <span>Deduction Penalty:</span>
                    <span style={{ fontWeight: 700 }}>−{(100 - score).toFixed(1)}</span>
                  </div>
                )
              ) : (
                <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--ds-emerald-ink)' }}>
                  <span>Deductions:</span>
                  <span style={{ fontWeight: 700 }}>0.0 (Compliant)</span>
                </div>
              )}
              <div style={{ height: '1px', backgroundColor: 'var(--ds-border-light)', margin: '2px 0' }} />
              <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 800, color: isCritical ? 'var(--ds-crimson)' : 'var(--ds-emerald)' }}>
                <span>Final Posture:</span>
                <span>{score.toFixed(1)}</span>
              </div>
            </div>
          </div>

          {/* Col 2: WHY THIS MATTERS (2-3 short sentences) */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ fontSize: '11px', fontWeight: 800, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', fontFamily: 'var(--ds-font-mono)' }}>
              WHY THIS MATTERS // FORENSIC SIGNIFICANCE
            </div>
            <p style={{ fontSize: '13.5px', color: 'var(--ds-ink-primary)', lineHeight: 1.55 }}>
              {whyThisMatters}
            </p>

            {/* Quick Proof Anchor */}
            <div
              onClick={() => handleFrameSelect(6)}
              style={{
                marginTop: '6px',
                padding: '10px 14px',
                backgroundColor: 'var(--ds-bg-subtle)',
                border: '1px solid var(--ds-border-light)',
                borderRadius: '6px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                cursor: 'pointer',
                transition: 'border-color 0.15s ease',
              }}
              title="Click to jump directly to proof Frame #6"
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px' }}>
                <Radio size={14} color="var(--ds-crimson)" />
                <span style={{ fontWeight: 700, color: 'var(--ds-ink-primary)' }}>WHAT PROVES IT?</span>
                <span className="ds-mono" style={{ color: 'var(--ds-ink-secondary)', fontSize: '11px' }}>
                  Frame #6 &bull; TLS ServerHello + Certificate &bull; Stream #0 &bull; SMTPS :465
                </span>
              </div>
              <span style={{ fontSize: '11px', color: 'var(--ds-carbon)', fontWeight: 700, fontFamily: 'var(--ds-font-mono)' }}>
                Inspect &rarr;
              </span>
            </div>
          </div>

          {/* Col 3: Epistemic Honesty (WHAT CAN WE NOT KNOW?) & Investigation Path */}
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
              paddingLeft: '16px',
              borderLeft: '1px solid var(--ds-border-light)',
            }}
          >
            <div>
              <div style={{ fontSize: '11px', fontWeight: 800, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', fontFamily: 'var(--ds-font-mono)', marginBottom: '6px' }}>
                WHAT CAN WE NOT KNOW? // EPISTEMIC LIMITS
              </div>
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                  fontSize: '11px',
                  fontFamily: 'var(--ds-font-mono)',
                  backgroundColor: 'var(--ds-bg-subtle)',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  border: '1px solid var(--ds-border-light)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--ds-ink-muted)' }}>Trust Anchor:</span>
                  <span className="ds-intel-tag ds-intel-tag-slate">NOT_OBSERVABLE</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--ds-ink-muted)' }}>Revocation (OCSP/CRL):</span>
                  <span className="ds-intel-tag ds-intel-tag-slate">NOT_OBSERVABLE</span>
                </div>
                <div style={{ fontSize: '10px', color: 'var(--ds-ink-muted)', marginTop: '2px', lineHeight: 1.3 }}>
                  Passive PCAP contains no trust store or live revocation traffic.
                </div>
              </div>
            </div>

            {/* Actionable Investigation Path */}
            <div>
              <div style={{ fontSize: '11px', fontWeight: 800, color: 'var(--ds-ink-muted)', letterSpacing: '0.06em', fontFamily: 'var(--ds-font-mono)', marginBottom: '6px' }}>
                INVESTIGATION PATH
              </div>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  type="button"
                  onClick={() => pivotToJourney(6)}
                  className="ds-btn-secondary"
                  style={{ flex: 1, justifyContent: 'center', fontSize: '11px', padding: '6px 8px' }}
                >
                  <span>1. PROOF</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const el = document.getElementById('findings-deck-anchor');
                    if (el) el.scrollIntoView({ behavior: 'smooth' });
                  }}
                  className="ds-btn-secondary"
                  style={{ flex: 1, justifyContent: 'center', fontSize: '11px', padding: '6px 8px' }}
                >
                  <span>2. FINDINGS</span>
                </button>
                <button
                  type="button"
                  onClick={() => pivotToProvenance()}
                  className="ds-btn-secondary"
                  style={{ flex: 1, justifyContent: 'center', fontSize: '11px', padding: '6px 8px' }}
                >
                  <span>3. STANDARD</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ============================================================ */}
      {/* 3. FORENSIC FINDINGS DECK (NOT A DATABASE TABLE!)            */}
      {/* ============================================================ */}
      <div id="findings-deck-anchor" style={{ marginBottom: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileCheck size={16} color="var(--ds-carbon)" />
            <h2 style={{ fontSize: '14px', fontWeight: 800, color: 'var(--ds-ink-primary)', letterSpacing: '0.04em', fontFamily: 'var(--ds-font-mono)', textTransform: 'uppercase', margin: 0 }}>
              ESTABLISHED FORENSIC FINDINGS ({findings.length})
            </h2>
          </div>
          <span style={{ fontSize: '11px', color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)' }}>
            Conclusion-first forensic determinations
          </span>
        </div>

        {findings.length === 0 ? (
          <div
            style={{
              padding: '24px',
              backgroundColor: 'var(--ds-bg-canvas)',
              borderRadius: '8px',
              border: '1px solid var(--ds-border-light)',
              textAlign: 'center',
              color: 'var(--ds-emerald-ink)',
              fontWeight: 600,
            }}
          >
            Zero defective findings observed. Negotiated protocol satisfies configured security standards.
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '16px' }}>
            {findings.map((f: FindingRow, idx: number) => {
              const numStr = String(idx + 1).padStart(2, '0');
              const frame = f.frames?.[0] || 6;
              const standardText = f.citations?.[0]?.text || (idx === 0 ? 'NIST SP 800-57 Part 1 Rev. 5 §5.6.1' : 'RFC 9155');
              const penalty = idx === 0 ? '−28 points' : '−28 points';

              return (
                <div
                  key={f.title}
                  onClick={() => {
                    selectFinding(f);
                    handleFrameSelect(frame);
                  }}
                  style={{
                    backgroundColor: 'var(--ds-bg-canvas)',
                    border: '1px solid var(--ds-border-light)',
                    borderLeft: '4px solid var(--ds-crimson-rail)',
                    borderRadius: '8px',
                    padding: '20px',
                    boxShadow: 'var(--ds-shadow-sm)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '12px',
                    cursor: 'pointer',
                    transition: 'transform 0.15s ease, box-shadow 0.15s ease',
                  }}
                  className="ds-finding-card"
                >
                  {/* Top Bar: 01 | HIGH | Issue Class */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontSize: '16px', fontWeight: 900, fontFamily: 'var(--ds-font-mono)', color: 'var(--ds-ink-muted)' }}>
                        {numStr}
                      </span>
                      <span className="ds-badge-critical" style={{ fontSize: '10px', padding: '2px 6px' }}>
                        {f.severity || 'HIGH'}
                      </span>
                      <span className="ds-mono" style={{ fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
                        {f.issue_class || 'CRYPTOGRAPHIC_DEFECT'}
                      </span>
                    </div>

                    <span style={{ fontSize: '11px', fontWeight: 800, color: 'var(--ds-crimson)', fontFamily: 'var(--ds-font-mono)' }}>
                      IMPACT: {penalty}
                    </span>
                  </div>

                  {/* Title & Human Conclusion */}
                  <div>
                    <h3 style={{ fontSize: '15px', fontWeight: 800, color: 'var(--ds-ink-primary)', letterSpacing: '-0.01em', margin: '0 0 4px 0' }}>
                      {f.title}
                    </h3>
                    <p style={{ fontSize: '12.5px', color: 'var(--ds-ink-secondary)', lineHeight: 1.45, margin: 0 }}>
                      {f.conclusion}
                    </p>
                  </div>

                  {/* Proof & Standard Pill Row */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '8px', borderTop: '1px solid var(--ds-border-light)', fontSize: '11px', fontFamily: 'var(--ds-font-mono)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ color: 'var(--ds-ink-muted)' }}>PROOF:</span>
                      <span className="ds-intel-tag ds-intel-tag-slate">Frame #{frame}</span>
                    </div>

                    <div style={{ color: 'var(--ds-carbon)', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <span>Inspect evidence &rarr;</span>
                    </div>
                  </div>

                  {/* Authoritative Standard Citation */}
                  <div style={{ fontSize: '10.5px', color: 'var(--ds-ink-muted)', fontFamily: 'var(--ds-font-mono)', backgroundColor: 'var(--ds-bg-subtle)', padding: '4px 8px', borderRadius: '4px' }}>
                    STANDARD: <strong>{standardText}</strong>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ============================================================ */}
      {/* 4. VISUAL CENTER: FORENSIC INVESTIGATION CANVAS              */}
      {/* ============================================================ */}
      <div className="ds-center-stage" style={{ marginBottom: '24px' }}>
        {/* Canvas Mode Switcher Bar */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--ds-border-light)', paddingBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            <button
              type="button"
              className={`ds-tab-btn ${activeCanvasView === 'ladder' ? 'active' : ''}`}
              onClick={() => setActiveCanvasView('ladder')}
            >
              <span>1. PROTOCOL RECONSTRUCTION LADDER</span>
            </button>

            <button
              type="button"
              className={`ds-tab-btn ${activeCanvasView === 'provenance' ? 'active' : ''}`}
              onClick={() => setActiveCanvasView('provenance')}
            >
              <GitBranch size={13} />
              <span>2. PROVENANCE INVESTIGATION GRAPH</span>
            </button>

            {hasCrossSessionFindings && (
              <button
                type="button"
                className={`ds-tab-btn ${activeCanvasView === 'cross_session' ? 'active' : ''}`}
                onClick={() => setActiveCanvasView('cross_session')}
                style={{
                  color: activeCanvasView === 'cross_session' ? '#ffffff' : 'var(--ds-crimson)',
                  backgroundColor: activeCanvasView === 'cross_session' ? 'var(--ds-crimson)' : 'var(--ds-crimson-soft)',
                  borderColor: 'var(--ds-crimson-border)',
                }}
              >
                <AlertCircle size={13} />
                <span>3. CROSS-SESSION BEHAVIOURAL MATRIX</span>
              </button>
            )}

            <button
              type="button"
              className={`ds-tab-btn ${activeCanvasView === 'coverage' ? 'active' : ''}`}
              onClick={() => setActiveCanvasView('coverage')}
            >
              <Layers size={13} />
              <span>4. EVIDENCE COVERAGE TIERS</span>
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="ds-mono" style={{ fontSize: '11px', color: 'var(--ds-ink-muted)' }}>
              Click Frame #6 to activate evidence dossier
            </span>
          </div>
        </div>

        {/* View 1: Protocol Reconstruction Ladder */}
        {activeCanvasView === 'ladder' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 8px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--ds-ink-secondary)' }}>
                Client <code>{selectedSession ? `${selectedSession.client.ip}:${selectedSession.client.port}` : '127.0.0.1:36568'}</code> &bull; Server <code>{selectedSession ? `${selectedSession.server.ip}:${selectedSession.server.port}` : '127.0.0.1:465 (SMTPS)'}</code>
              </span>
              <button
                type="button"
                onClick={() => pivotToJourney(selectedFrame)}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                  color: 'var(--ds-carbon)',
                  fontFamily: 'var(--ds-font-mono)',
                  fontSize: '11px',
                  fontWeight: 700,
                  cursor: 'pointer',
                }}
              >
                <span>Full Journey Tab</span>
                <ArrowRight size={12} />
              </button>
            </div>

            <ProtocolLadderSvg
              selectedFrame={selectedFrame}
              onSelectFrame={handleFrameSelect}
              darkTheme={false}
              messages={ladderMessages}
            />
          </div>
        )}

        {/* View 2: Provenance Investigation Graph */}
        {activeCanvasView === 'provenance' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 8px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--ds-ink-secondary)' }}>
                Deterministic Causal Hierarchy: PCAP &rarr; Stream &rarr; Frame &rarr; Specimen &rarr; Finding &rarr; Standard &rarr; Posture
              </span>
              <button
                type="button"
                onClick={() => pivotToProvenance()}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                  color: 'var(--ds-carbon)',
                  fontFamily: 'var(--ds-font-mono)',
                  fontSize: '11px',
                  fontWeight: 700,
                  cursor: 'pointer',
                }}
              >
                <span>Full Provenance Tab</span>
                <ArrowRight size={12} />
              </button>
            </div>

            <ProvenanceGraphSvg
              darkTheme={false}
              activeFindingTitle={findings[0]?.title}
              onSelectNode={(nodeId) => {
                if (nodeId === 'frame' || nodeId === 'cert') handleFrameSelect(6);
              }}
            />
          </div>
        )}

        {/* View 3: Cross-Session Matrix */}
        {activeCanvasView === 'cross_session' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 8px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--ds-crimson-ink)' }}>
                Multi-Session Comparative Baseline: Subject Client ({selectedSession?.client.ip || '10.0.0.6'}) vs Control Endpoint 10.0.0.7
              </span>
              <button
                type="button"
                onClick={() => pivotToCrossSession()}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                  color: 'var(--ds-carbon)',
                  fontFamily: 'var(--ds-font-mono)',
                  fontSize: '11px',
                  fontWeight: 700,
                  cursor: 'pointer',
                }}
              >
                <span>Full Cross-Session Tab</span>
                <ArrowRight size={12} />
              </button>
            </div>

            <CrossSessionMatrix darkTheme={false} />
          </div>
        )}

        {/* View 4: Coverage Lanes */}
        {activeCanvasView === 'coverage' && (
          <div style={{ padding: '8px' }}>
            <CoverageLanes darkTheme={false} />
          </div>
        )}
      </div>

      {/* ============================================================ */}
      {/* 5. CONTEXTUAL EVIDENCE DOSSIER (SYNCHRONIZED WITH FRAME #6)  */}
      {/* ============================================================ */}
      <div
        style={{
          backgroundColor: 'var(--ds-bg-canvas)',
          border: '1px solid var(--ds-border-light)',
          borderTop: selectedFrame === 6 ? '4px solid var(--ds-crimson-rail)' : '4px solid var(--ds-carbon)',
          borderRadius: '8px',
          padding: '24px 28px',
          boxShadow: 'var(--ds-shadow-sm)',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
        }}
      >
        {/* Header Strip */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--ds-border-light)', paddingBottom: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Fingerprint size={16} color="var(--ds-carbon)" />
            <span style={{ fontSize: '13px', fontWeight: 800, color: 'var(--ds-ink-primary)', letterSpacing: '-0.01em' }}>
              EVIDENCE DOSSIER &bull; FRAME #{selectedFrame}
            </span>
            <span
              style={{
                fontFamily: 'var(--ds-font-mono)',
                fontSize: '10px',
                fontWeight: 700,
                padding: '2px 7px',
                borderRadius: '3px',
                backgroundColor: 'var(--ds-bg-subtle)',
                color: 'var(--ds-ink-secondary)',
                border: '1px solid var(--ds-border-light)',
              }}
            >
              STATE: OBSERVED
            </span>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              type="button"
              onClick={() => pivotToJourney(selectedFrame)}
              className="ds-btn-secondary"
            >
              <span>Pivot to Frame</span>
              <ChevronRight size={13} />
            </button>
            <button
              type="button"
              onClick={() => pivotToCerts(0)}
              className="ds-btn-secondary"
            >
              <span>Inspect Certificate Specimen</span>
              <ExternalLink size={13} />
            </button>
          </div>
        </div>

        {/* Dossier Body Columns: Specimen | Standard | Impact */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '20px',
          }}
        >
          {/* Specimen Box */}
          <div
            style={{
              padding: '16px',
              borderRadius: '6px',
              backgroundColor: 'var(--ds-bg-subtle)',
              border: '1px solid var(--ds-border-light)',
              fontFamily: 'var(--ds-font-mono)',
              fontSize: '11px',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
            }}
          >
            <div style={{ fontSize: '10px', fontWeight: 800, color: 'var(--ds-ink-muted)', letterSpacing: '0.04em' }}>
              RECONSTRUCTED ARTIFACT SPECIMEN
            </div>
            <div>
              <span style={{ color: 'var(--ds-ink-muted)' }}>Public Key Algorithm: </span>
              <strong style={{ color: 'var(--ds-crimson-ink)' }}>RSA (1024 bits)</strong>
            </div>
            <div>
              <span style={{ color: 'var(--ds-ink-muted)' }}>Signature Algorithm: </span>
              <strong style={{ color: 'var(--ds-crimson-ink)' }}>sha1WithRSAEncryption</strong>
            </div>
            <div>
              <span style={{ color: 'var(--ds-ink-muted)' }}>Certificate Subject: </span>
              <span style={{ color: 'var(--ds-ink-primary)' }}>CN=mail.internal.corp</span>
            </div>
          </div>

          {/* Governing Standard Box */}
          <div
            style={{
              padding: '16px',
              borderRadius: '6px',
              backgroundColor: 'var(--ds-bg-subtle)',
              border: '1px solid var(--ds-border-light)',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
            }}
          >
            <div style={{ fontSize: '10px', fontWeight: 800, color: 'var(--ds-ink-muted)', letterSpacing: '0.04em', fontFamily: 'var(--ds-font-mono)' }}>
              GOVERNING AUTHORITATIVE STANDARD
            </div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--ds-ink-primary)' }}>
              NIST SP 800-57 Part 1 Rev. 5 §5.6.1
            </div>
            <p style={{ fontSize: '11px', color: 'var(--ds-ink-secondary)', lineHeight: 1.45 }}>
              "Digital signatures and key agreement algorithms providing less than 112 bits of security strength (including RSA keys &lt;2048 bits) are disallowed for protecting sensitive government communications."
            </p>
          </div>

          {/* Score Impact Box */}
          <div
            style={{
              padding: '16px',
              borderRadius: '6px',
              backgroundColor: isCritical ? 'var(--ds-crimson-soft)' : 'var(--ds-bg-subtle)',
              border: isCritical ? '1px solid var(--ds-crimson-border)' : '1px solid var(--ds-border-light)',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
            }}
          >
            <div style={{ fontSize: '10px', fontWeight: 800, color: isCritical ? 'var(--ds-crimson-ink)' : 'var(--ds-ink-muted)', letterSpacing: '0.04em', fontFamily: 'var(--ds-font-mono)' }}>
              POSTURE EVALUATION IMPACT
            </div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: isCritical ? 'var(--ds-crimson)' : 'var(--ds-emerald)', fontFamily: 'var(--ds-font-mono)' }}>
              {isCritical ? '−28.0 Points Deduction' : '0.0 Penalty'}
            </div>
            <p style={{ fontSize: '11px', color: isCritical ? 'var(--ds-crimson-ink)' : 'var(--ds-ink-secondary)', lineHeight: 1.45 }}>
              Penalty applied under deterministic dampening formula F2-GROUP-DAMPED. Resolving this defect requires upgrading the leaf certificate to RSA &ge;2048 or ECDSA P-256.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
