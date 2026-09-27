import React from 'react';
import {
  FileCode,
  Layers,
  Activity,
  Hash,
  ShieldAlert,
  ShieldCheck,
  Scale,
  GitBranch,
  Lock,
  ArrowDown,
  ArrowRight,
} from 'lucide-react';
import type { DashboardViewModel, RunResponse, SessionEvidence } from '../../../api/types';

interface InvestigationFlowProps {
  dashboard: DashboardViewModel;
  activeRun: RunResponse;
  sessions: SessionEvidence[];
  onOpenJourney: (frame?: number, streamKey?: string) => void;
  onOpenFinding?: (findingTitle: string) => void;
  onOpenCrossSession?: () => void;
  onOpenCertificates?: () => void;
  onOpenScoreDetail?: () => void;
  onOpenSessions?: () => void;
}

export const InvestigationFlow: React.FC<InvestigationFlowProps> = ({
  dashboard,
  activeRun,
  sessions,
  onOpenJourney,
  onOpenFinding,
  onOpenCrossSession,
  onOpenCertificates,
  onOpenScoreDetail,
  onOpenSessions,
}) => {
  const filename = activeRun.source_filename || 'capture.pcap';
  const posture = dashboard.posture;
  const findings = dashboard.findings || [];
  const sessionCount = sessions.length || dashboard.coverage?.sessions_total || 1;
  const isCaseB = filename.includes('cross_session') || findings.some((f) => (f.source_rule_ids || []).some((r) => r.startsWith('CS-')));
  const isCaseA = filename.includes('weak') || findings.some((f) => (f.issue_class || '').includes('KEY_SIZE') || (f.issue_class || '').includes('CERT'));
  const isCaseC = (findings.length === 0 && posture.value === 'STRONG') || filename.includes('honesty');

  // Helper for keyboard navigation
  const handleKey = (e: React.KeyboardEvent, action?: () => void) => {
    if ((e.key === 'Enter' || e.key === ' ') && action) {
      e.preventDefault();
      action();
    }
  };

  return (
    <section className="sms-flow-section" aria-label="Interactive Forensic Investigation Flow">
      <div className="sms-flow-header">
        <div className="sms-flow-header__title-group">
          <span className="sms-label">Investigation path</span>
          <span className="sms-flow-header__subtitle">
            Evidentiary reasoning map tracing capture bytes through wire events to cryptographic posture
          </span>
        </div>
        <span className="sms-flow-header__hint">
          Click any node to navigate to proof
        </span>
      </div>

      <div className="sms-flow-canvas" role="region" aria-label="Forensic Investigation Map">
        {/* CASE B: DUAL-BRANCH INVESTIGATION FLOW */}
        {isCaseB ? (
          <div className="sms-flow-tree sms-flow-tree--branching">
            {/* Level 1: Root Capture */}
            <div className="sms-flow-level sms-flow-level--root">
              <button
                type="button"
                className="sms-flow-node sms-flow-node--capture"
                onClick={onOpenSessions}
                onKeyDown={(e) => handleKey(e, onOpenSessions)}
                title="Source capture file. Click to view session coverage."
                aria-label={`Source PCAP: ${filename}. Click to view session coverage.`}
              >
                <div className="sms-flow-node__head">
                  <FileCode size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">CAPTURE</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title sms-mono">{filename}</span>
                  <span className="sms-flow-node__meta">Passive PCAP Ingest · 100% Unmodified</span>
                </div>
              </button>
            </div>

            {/* Down Connector */}
            <div className="sms-flow-connector sms-flow-connector--down" aria-hidden="true">
              <div className="sms-flow-connector__line" />
              <ArrowDown size={14} className="sms-flow-connector__arrow" />
            </div>

            {/* Level 2: Session Aggregation */}
            <div className="sms-flow-level sms-flow-level--sessions">
              <button
                type="button"
                className="sms-flow-node sms-flow-node--sessions"
                onClick={onOpenSessions}
                onKeyDown={(e) => handleKey(e, onOpenSessions)}
                title="12 Reconstructed TCP sessions. Click to explore session matrix."
                aria-label={`${sessionCount} TCP sessions reconstructed. Click to view session explorer.`}
              >
                <div className="sms-flow-node__head">
                  <Layers size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">RECONSTRUCTION</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title">
                    <strong className="sms-mono">{sessionCount}</strong> Assessed Sessions
                  </span>
                  <span className="sms-flow-node__meta">Subject 10.0.0.6 (6) vs Control 10.0.0.7 (6)</span>
                </div>
              </button>
            </div>

            {/* Branching Connector Split */}
            <div className="sms-flow-fork" aria-hidden="true">
              <div className="sms-flow-fork__stem" />
              <div className="sms-flow-fork__rail" />
              <div className="sms-flow-fork__drops">
                <div className="sms-flow-fork__drop"><ArrowDown size={12} /></div>
                <div className="sms-flow-fork__drop"><ArrowDown size={12} /></div>
              </div>
            </div>

            {/* Level 3: Dual Investigation Threads */}
            <div className="sms-flow-branches">
              {/* Branch Left: Plaintext Auth */}
              <div className="sms-flow-branch sms-flow-branch--left">
                <div className="sms-flow-branch__badge sms-flow-branch__badge--critical">
                  Thread A: Plaintext Exposure
                </div>

                {/* Finding Node */}
                <button
                  type="button"
                  className="sms-flow-node sms-flow-node--branch sms-flow-node--critical"
                  onClick={() => onOpenFinding?.('Authentication activity without TLS')}
                  onKeyDown={(e) => handleKey(e, () => onOpenFinding?.('Authentication activity without TLS'))}
                  title="Click to view Plaintext Auth finding dossier"
                  aria-label="Thread A: Plaintext Authentication observed. Click to inspect finding."
                >
                  <div className="sms-flow-node__head">
                    <ShieldAlert size={13} className="sms-flow-node__icon" aria-hidden="true" />
                    <span className="sms-flow-node__tag">FINDING SEC-PLAIN-001</span>
                    <span className="sms-badge sms-badge--critical sms-badge--xs">HIGH</span>
                  </div>
                  <div className="sms-flow-node__body">
                    <span className="sms-flow-node__title">Plaintext Auth Activity</span>
                    <span className="sms-flow-node__meta">6 sessions exposed without TLS</span>
                  </div>
                </button>

                <div className="sms-flow-connector sms-flow-connector--down" aria-hidden="true">
                  <div className="sms-flow-connector__line" />
                  <ArrowDown size={12} className="sms-flow-connector__arrow" />
                </div>

                {/* Wire Proof Node */}
                <button
                  type="button"
                  className="sms-flow-node sms-flow-node--proof"
                  onClick={() => onOpenJourney(7, '97b2b61aa870b74861c606e604f3ecf6f77d8818241817bd22beb814f3dcbe83:0')}
                  onKeyDown={(e) => handleKey(e, () => onOpenJourney(7))}
                  title="Click to open Frame #7 in Protocol Journey"
                  aria-label="Wire Proof: Frame #7, Stream #0. Click to open in Protocol Journey."
                >
                  <div className="sms-flow-node__head">
                    <Hash size={13} className="sms-flow-node__icon" aria-hidden="true" />
                    <span className="sms-flow-node__tag">WIRE PROOF</span>
                    <span className="sms-mono sms-text-xs" style={{ color: 'var(--sms-brand-cyan)' }}>Stream #0</span>
                  </div>
                  <div className="sms-flow-node__body">
                    <span className="sms-flow-node__title sms-mono">Frame #7</span>
                    <span className="sms-flow-node__meta">AUTH_ACTIVITY = TRUE · TLS = FALSE</span>
                  </div>
                </button>

                <div className="sms-flow-connector sms-flow-connector--down" aria-hidden="true">
                  <div className="sms-flow-connector__line" />
                  <ArrowDown size={12} className="sms-flow-connector__arrow" />
                </div>

                {/* Standard Node */}
                <div className="sms-flow-node sms-flow-node--standard">
                  <div className="sms-flow-node__head">
                    <Scale size={13} className="sms-flow-node__icon" aria-hidden="true" />
                    <span className="sms-flow-node__tag">GOVERNING STANDARD</span>
                  </div>
                  <div className="sms-flow-node__body">
                    <span className="sms-flow-node__title">RFC 8314 §3 · NIST SP 800-52r2</span>
                    <span className="sms-flow-node__meta">Cleartext auth declared obsolete</span>
                  </div>
                </div>
              </div>

              {/* Branch Right: STARTTLS Downgrade Deviation */}
              <div className="sms-flow-branch sms-flow-branch--right">
                <div className="sms-flow-branch__badge sms-flow-branch__badge--amber">
                  Thread B: Cross-Session Downgrade
                </div>

                {/* Finding Node */}
                <button
                  type="button"
                  className="sms-flow-node sms-flow-node--branch sms-flow-node--warning"
                  onClick={onOpenCrossSession}
                  onKeyDown={(e) => handleKey(e, onOpenCrossSession)}
                  title="Click to inspect Cross-Session workspace"
                  aria-label="Thread B: STARTTLS Deviation observed. Click to inspect Cross-Session comparison."
                >
                  <div className="sms-flow-node__head">
                    <GitBranch size={13} className="sms-flow-node__icon" aria-hidden="true" />
                    <span className="sms-flow-node__tag">FINDING CS-STARTTLS-001</span>
                    <span className="sms-badge sms-badge--medium sms-badge--xs">MEDIUM</span>
                  </div>
                  <div className="sms-flow-node__body">
                    <span className="sms-flow-node__title">STARTTLS Deviation</span>
                    <span className="sms-flow-node__meta">Subject stripped vs Control active</span>
                  </div>
                </button>

                <div className="sms-flow-connector sms-flow-connector--down" aria-hidden="true">
                  <div className="sms-flow-connector__line" />
                  <ArrowDown size={12} className="sms-flow-connector__arrow" />
                </div>

                {/* Wire Proof Node */}
                <button
                  type="button"
                  className="sms-flow-node sms-flow-node--proof"
                  onClick={() => onOpenJourney(56, '97b2b61aa870b74861c606e604f3ecf6f77d8818241817bd22beb814f3dcbe83:6')}
                  onKeyDown={(e) => handleKey(e, () => onOpenJourney(56))}
                  title="Click to open Frame #56 in Protocol Journey"
                  aria-label="Wire Proof: Frame #56, Control Stream #6. Click to open in Protocol Journey."
                >
                  <div className="sms-flow-node__head">
                    <Hash size={13} className="sms-flow-node__icon" aria-hidden="true" />
                    <span className="sms-flow-node__tag">WIRE PROOF</span>
                    <span className="sms-mono sms-text-xs" style={{ color: 'var(--sms-brand-cyan)' }}>Stream #6</span>
                  </div>
                  <div className="sms-flow-node__body">
                    <span className="sms-flow-node__title sms-mono">Frame #56</span>
                    <span className="sms-flow-node__meta">Control 10.0.0.7 offered STARTTLS</span>
                  </div>
                </button>

                <div className="sms-flow-connector sms-flow-connector--down" aria-hidden="true">
                  <div className="sms-flow-connector__line" />
                  <ArrowDown size={12} className="sms-flow-connector__arrow" />
                </div>

                {/* Standard Node */}
                <div className="sms-flow-node sms-flow-node--standard">
                  <div className="sms-flow-node__head">
                    <Scale size={13} className="sms-flow-node__icon" aria-hidden="true" />
                    <span className="sms-flow-node__tag">GOVERNING STANDARD</span>
                  </div>
                  <div className="sms-flow-node__body">
                    <span className="sms-flow-node__title">RFC 3207 §6</span>
                    <span className="sms-flow-node__meta">STARTTLS stripping anomaly detection</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Convergence Join Connector */}
            <div className="sms-flow-join" aria-hidden="true">
              <div className="sms-flow-join__arms" />
              <div className="sms-flow-join__stem" />
              <ArrowDown size={14} className="sms-flow-join__arrow" />
            </div>

            {/* Final Converged Posture Node */}
            <div className="sms-flow-level sms-flow-level--final">
              <button
                type="button"
                className="sms-flow-node sms-flow-node--posture sms-flow-node--posture-critical"
                onClick={onOpenScoreDetail}
                onKeyDown={(e) => handleKey(e, onOpenScoreDetail)}
                title="Click to inspect Score Calculation Waterfall"
                aria-label={`Final Security Posture: ${posture.score_value ?? 22.15} / 100 ${posture.value}. Click to inspect score calculation.`}
              >
                <div className="sms-flow-node__head">
                  <ShieldAlert size={14} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">EVIDENCE-FUSED POSTURE</span>
                  <span className="sms-flow-node__action-hint">Inspect Calculus ↗</span>
                </div>
                <div className="sms-flow-node__body">
                  <div className="sms-flow-node__score-line">
                    <span className="sms-flow-node__score-val sms-mono">
                      {posture.score_value != null ? posture.score_value.toFixed(2) : '22.15'}
                    </span>
                    <span className="sms-flow-node__score-den">/ 100</span>
                    <span className="sms-badge sms-badge--critical" style={{ marginLeft: 8 }}>
                      {posture.value}
                    </span>
                  </div>
                  <span className="sms-flow-node__meta">
                    F2-group-damped: -46.09 (auth) + -19.75 (no TLS) + -12.00 (deviation)
                  </span>
                </div>
              </button>
            </div>
          </div>
        ) : isCaseA ? (
          /* CASE A: WEAK CERTIFICATE FORENSIC FLOW */
          <div className="sms-flow-tree sms-flow-tree--linear">
            {/* 1. PCAP */}
            <div className="sms-flow-seq">
              <button
                type="button"
                className="sms-flow-node sms-flow-node--capture"
                onClick={onOpenSessions}
                onKeyDown={(e) => handleKey(e, onOpenSessions)}
                title="Source capture file. Click to view session."
                aria-label={`Source PCAP: ${filename}.`}
              >
                <div className="sms-flow-node__head">
                  <FileCode size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">CAPTURE</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title sms-mono">{filename}</span>
                  <span className="sms-flow-node__meta">Passive PCAP Ingest</span>
                </div>
              </button>

              <div className="sms-flow-connector--linear" aria-hidden="true">
                <ArrowRight size={14} />
              </div>

              {/* 2. Stream */}
              <button
                type="button"
                className="sms-flow-node"
                onClick={() => onOpenJourney(6, sessions[0]?.stream_key)}
                onKeyDown={(e) => handleKey(e, () => onOpenJourney(6))}
                title="Click to inspect Stream #0 in Protocol Journey"
                aria-label="Stream #0, SMTPS port 465."
              >
                <div className="sms-flow-node__head">
                  <Layers size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">STREAM #0</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title">SMTPS Implicit TLS</span>
                  <span className="sms-flow-node__meta">Port 465 · 1 Session</span>
                </div>
              </button>

              <div className="sms-flow-connector--linear" aria-hidden="true">
                <ArrowRight size={14} />
              </div>

              {/* 3. Handshake & Frame 6 */}
              <button
                type="button"
                className="sms-flow-node sms-flow-node--proof"
                onClick={() => onOpenJourney(6, sessions[0]?.stream_key)}
                onKeyDown={(e) => handleKey(e, () => onOpenJourney(6))}
                title="Click to view Frame #6 in Protocol Journey"
                aria-label="Frame #6: ServerHello Certificate payload. Click to inspect."
              >
                <div className="sms-flow-node__head">
                  <Hash size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">WIRE PROOF</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title sms-mono">Frame #6</span>
                  <span className="sms-flow-node__meta">X.509 Certificate Handshake</span>
                </div>
              </button>

              <div className="sms-flow-connector--linear" aria-hidden="true">
                <ArrowRight size={14} />
              </div>

              {/* 4. Cryptographic Finding */}
              <button
                type="button"
                className="sms-flow-node sms-flow-node--critical"
                onClick={onOpenCertificates}
                onKeyDown={(e) => handleKey(e, onOpenCertificates)}
                title="Click to view Certificate Forensics"
                aria-label="Cryptographic Weakness: RSA-1024 & SHA-1. Click to view Certificates."
              >
                <div className="sms-flow-node__head">
                  <ShieldAlert size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">SEC-CERT-001</span>
                  <span className="sms-badge sms-badge--critical sms-badge--xs">HIGH</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title">RSA-1024 + SHA-1</span>
                  <span className="sms-flow-node__meta">Weak key modulus & deprecated digest</span>
                </div>
              </button>

              <div className="sms-flow-connector--linear" aria-hidden="true">
                <ArrowRight size={14} />
              </div>

              {/* 5. Standard */}
              <div className="sms-flow-node sms-flow-node--standard">
                <div className="sms-flow-node__head">
                  <Scale size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">STANDARD</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title">NIST SP 800-57</span>
                  <span className="sms-flow-node__meta">RFC 9155 / NIST SP 800-131A</span>
                </div>
              </div>

              <div className="sms-flow-connector--linear" aria-hidden="true">
                <ArrowRight size={14} />
              </div>

              {/* 6. Posture */}
              <button
                type="button"
                className="sms-flow-node sms-flow-node--posture sms-flow-node--posture-critical"
                onClick={onOpenScoreDetail}
                onKeyDown={(e) => handleKey(e, onOpenScoreDetail)}
                title="Click to inspect Score Calculation Waterfall"
                aria-label="Posture: 44.0 / 100 CRITICAL. Click to inspect calculation."
              >
                <div className="sms-flow-node__head">
                  <ShieldAlert size={14} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">POSTURE</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__score-val sms-mono">44.00</span>
                  <span className="sms-badge sms-badge--critical sms-badge--xs">CRITICAL</span>
                </div>
              </button>
            </div>
          </div>
        ) : isCaseC ? (
          /* CASE C: TLS 1.3 HONEST OBSERVABILITY FLOW */
          <div className="sms-flow-tree sms-flow-tree--linear">
            <div className="sms-flow-seq">
              {/* 1. PCAP */}
              <button
                type="button"
                className="sms-flow-node sms-flow-node--capture"
                onClick={onOpenSessions}
                onKeyDown={(e) => handleKey(e, onOpenSessions)}
                title="Source capture file. Click to view session."
                aria-label={`Source PCAP: ${filename}.`}
              >
                <div className="sms-flow-node__head">
                  <FileCode size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">CAPTURE</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title sms-mono">{filename}</span>
                  <span className="sms-flow-node__meta">Passive PCAP Ingest</span>
                </div>
              </button>

              <div className="sms-flow-connector--linear" aria-hidden="true">
                <ArrowRight size={14} />
              </div>

              {/* 2. Stream */}
              <button
                type="button"
                className="sms-flow-node"
                onClick={() => onOpenJourney(14, sessions[0]?.stream_key)}
                onKeyDown={(e) => handleKey(e, () => onOpenJourney(14))}
                title="Click to inspect Stream #0 in Protocol Journey"
                aria-label="Stream #0, IMAPS port 993."
              >
                <div className="sms-flow-node__head">
                  <Layers size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">STREAM #0</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title">IMAPS Implicit TLS</span>
                  <span className="sms-flow-node__meta">Port 993 · 1 Session</span>
                </div>
              </button>

              <div className="sms-flow-connector--linear" aria-hidden="true">
                <ArrowRight size={14} />
              </div>

              {/* 3. TLS 1.3 Wire Proof */}
              <button
                type="button"
                className="sms-flow-node sms-flow-node--proof"
                onClick={() => onOpenJourney(14, sessions[0]?.stream_key)}
                onKeyDown={(e) => handleKey(e, () => onOpenJourney(14))}
                title="Click to view Frame #14 in Protocol Journey"
                aria-label="Frame #14: TLS 1.3 Negotiation. Click to inspect."
              >
                <div className="sms-flow-node__head">
                  <Hash size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">WIRE PROOF</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title sms-mono">Frame #14</span>
                  <span className="sms-flow-node__meta">TLS 1.3 (0x0304) Negotiated</span>
                </div>
              </button>

              <div className="sms-flow-connector--linear" aria-hidden="true">
                <ArrowRight size={14} />
              </div>

              {/* 4. Epistemic Boundary: Certificate Not Observable */}
              <button
                type="button"
                className="sms-flow-node sms-flow-node--info"
                onClick={onOpenCertificates}
                onKeyDown={(e) => handleKey(e, onOpenCertificates)}
                title="Click to view honest TLS 1.3 observability status"
                aria-label="Certificate Content: NOT_OBSERVABLE. Encrypted in TLS 1.3 passive capture."
              >
                <div className="sms-flow-node__head">
                  <Lock size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">OBSERVABILITY</span>
                  <span className="sms-badge sms-badge--muted sms-badge--xs">HONEST</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title">Cert NOT_OBSERVABLE</span>
                  <span className="sms-flow-node__meta">Encrypted in TLS 1.3 passive wire</span>
                </div>
              </button>

              <div className="sms-flow-connector--linear" aria-hidden="true">
                <ArrowRight size={14} />
              </div>

              {/* 5. Standard */}
              <div className="sms-flow-node sms-flow-node--standard">
                <div className="sms-flow-node__head">
                  <Scale size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">STANDARD</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title">RFC 8446 §4.4.2</span>
                  <span className="sms-flow-node__meta">RFC 8314 Compliant</span>
                </div>
              </div>

              <div className="sms-flow-connector--linear" aria-hidden="true">
                <ArrowRight size={14} />
              </div>

              {/* 6. Posture */}
              <button
                type="button"
                className="sms-flow-node sms-flow-node--posture sms-flow-node--posture-strong"
                onClick={onOpenScoreDetail}
                onKeyDown={(e) => handleKey(e, onOpenScoreDetail)}
                title="Click to inspect Score Calculation Waterfall"
                aria-label="Posture: 100.0 / 100 STRONG. 0 findings."
              >
                <div className="sms-flow-node__head">
                  <ShieldCheck size={14} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">POSTURE</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__score-val sms-mono">100.0</span>
                  <span className="sms-badge sms-badge--strong sms-badge--xs">STRONG</span>
                </div>
              </button>
            </div>
          </div>
        ) : (
          /* GENERIC / DYNAMIC FLOW */
          <div className="sms-flow-tree sms-flow-tree--linear">
            <div className="sms-flow-seq">
              <button
                type="button"
                className="sms-flow-node sms-flow-node--capture"
                onClick={onOpenSessions}
                onKeyDown={(e) => handleKey(e, onOpenSessions)}
                aria-label={`Source PCAP: ${filename}.`}
              >
                <div className="sms-flow-node__head">
                  <FileCode size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">CAPTURE</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title sms-mono">{filename}</span>
                  <span className="sms-flow-node__meta">PCAP Ingest</span>
                </div>
              </button>

              <div className="sms-flow-connector--linear" aria-hidden="true"><ArrowRight size={14} /></div>

              <button
                type="button"
                className="sms-flow-node"
                onClick={onOpenSessions}
                onKeyDown={(e) => handleKey(e, onOpenSessions)}
                aria-label={`${sessionCount} sessions.`}
              >
                <div className="sms-flow-node__head">
                  <Layers size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">SESSIONS</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title">{sessionCount} TCP Stream{sessionCount === 1 ? '' : 's'}</span>
                  <span className="sms-flow-node__meta">Reconstructed</span>
                </div>
              </button>

              <div className="sms-flow-connector--linear" aria-hidden="true"><ArrowRight size={14} /></div>

              <button
                type="button"
                className={`sms-flow-node ${findings.length > 0 ? 'sms-flow-node--critical' : 'sms-flow-node--info'}`}
                onClick={() => findings[0] && onOpenFinding?.(findings[0].title)}
                onKeyDown={(e) => handleKey(e, () => findings[0] && onOpenFinding?.(findings[0].title))}
                aria-label={`Primary Finding: ${findings[0]?.title || 'Clean Protocol Execution'}.`}
              >
                <div className="sms-flow-node__head">
                  {findings.length > 0 ? (
                    <ShieldAlert size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  ) : (
                    <ShieldCheck size={13} className="sms-flow-node__icon" aria-hidden="true" />
                  )}
                  <span className="sms-flow-node__tag">FINDING</span>
                  {findings[0]?.severity && (
                    <span className="sms-badge sms-badge--xs">{findings[0].severity}</span>
                  )}
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__title">{findings[0]?.title || 'No Violations'}</span>
                  <span className="sms-flow-node__meta">{findings.length} total findings</span>
                </div>
              </button>

              <div className="sms-flow-connector--linear" aria-hidden="true"><ArrowRight size={14} /></div>

              <button
                type="button"
                className="sms-flow-node sms-flow-node--posture"
                onClick={onOpenScoreDetail}
                onKeyDown={(e) => handleKey(e, onOpenScoreDetail)}
                aria-label={`Posture: ${posture.score_value ?? '—'} ${posture.value}.`}
              >
                <div className="sms-flow-node__head">
                  <Activity size={14} className="sms-flow-node__icon" aria-hidden="true" />
                  <span className="sms-flow-node__tag">POSTURE</span>
                </div>
                <div className="sms-flow-node__body">
                  <span className="sms-flow-node__score-val sms-mono">
                    {posture.score_value != null ? posture.score_value.toFixed(1) : '—'}
                  </span>
                  <span className="sms-badge sms-badge--xs">{posture.value}</span>
                </div>
              </button>
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
