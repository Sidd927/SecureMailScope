import React, { useState } from 'react';
import { ArrowRight, Radio, Cpu, Lock, GitCompare, FileCheck, FileText } from 'lucide-react';

interface Stage {
  id: string;
  name: string;
  subtitle: string;
  icon: React.ComponentType<{ size?: number; className?: string; 'aria-hidden'?: boolean | 'true' | 'false' }>;
  detail: string;
  standards?: string;
}

const STAGES: Stage[] = [
  {
    id: 'capture',
    name: 'CAPTURE',
    subtitle: 'Passive Ingest',
    icon: Radio,
    detail: 'Ingests raw PCAP packet captures via passive wire analysis with zero active probing or endpoint disruption.',
    standards: 'Ethernet, IPv4, TCP',
  },
  {
    id: 'reconstruct',
    name: 'RECONSTRUCT',
    subtitle: 'Stream Tracking',
    icon: Cpu,
    detail: 'Reassembles bidirectional TCP streams and tracks finite state-machine transitions across SMTP, IMAP, and POP3.',
    standards: 'RFC 5321, RFC 3501, RFC 1939',
  },
  {
    id: 'analyze',
    name: 'ANALYZE',
    subtitle: 'Normative Rules',
    icon: Lock,
    detail: 'Evaluates cryptographic handshakes, cipher suites, certificate honesty, and STARTTLS negotiation deterministically.',
    standards: 'RFC 8314, RFC 8996, NIST SP 800-52r2',
  },
  {
    id: 'correlate',
    name: 'CORRELATE',
    subtitle: 'Cross-Session',
    icon: GitCompare,
    detail: 'Compares subject endpoints against simultaneous control endpoints to distinguish active downgrade attacks from server policy.',
    standards: 'Control Baseline Engine',
  },
  {
    id: 'prove',
    name: 'PROVE',
    subtitle: 'Byte Provenance',
    icon: FileCheck,
    detail: 'Binds every finding and score deduction to physical frame offsets, timestamps, and observed wire facts.',
    standards: 'Full Audit Trail',
  },
  {
    id: 'report',
    name: 'REPORT',
    subtitle: 'Audit Deliverable',
    icon: FileText,
    detail: 'Generates cryptographically signed forensic assessment reports in PDF, HTML, and JSON with verifiable SHA-256 integrity.',
    standards: 'Executive & Technical Workspace',
  },
];

export const ForensicProcessPipeline: React.FC = () => {
  const [activeStageId, setActiveStageId] = useState<string | null>(null);

  const activeStage = STAGES.find((s) => s.id === activeStageId) ?? null;

  return (
    <section className="sms-process-pipeline" aria-label="Forensic investigation process">
      <div className="sms-process-pipeline__head">
        <span className="sms-label">Forensic methodology pipeline</span>
        <span className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-11)' }}>
          Click any phase to inspect engine role
        </span>
      </div>

      <div className="sms-process-pipeline__track" role="list">
        {STAGES.map((stage, idx) => {
          const isActive = activeStageId === stage.id;
          const Icon = stage.icon;
          const isLast = idx === STAGES.length - 1;

          return (
            <React.Fragment key={stage.id}>
              <button
                type="button"
                role="listitem"
                className={`sms-pipeline-node${isActive ? ' is-active' : ''}`}
                onClick={() => setActiveStageId(isActive ? null : stage.id)}
                aria-expanded={isActive}
              >
                <div className="sms-pipeline-node__top">
                  <Icon size={14} className="sms-pipeline-node__icon" aria-hidden="true" />
                  <span className="sms-pipeline-node__step-num sms-mono">0{idx + 1}</span>
                </div>
                <span className="sms-pipeline-node__name">{stage.name}</span>
                <span className="sms-pipeline-node__subtitle">{stage.subtitle}</span>
              </button>

              {!isLast && (
                <div className="sms-pipeline-connector" aria-hidden="true">
                  <ArrowRight size={13} className="sms-pipeline-arrow" />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>

      {activeStage && (
        <div className="sms-pipeline-drawer" role="region" aria-label={`${activeStage.name} details`}>
          <div className="sms-pipeline-drawer__content">
            <div className="sms-pipeline-drawer__head">
              <div className="sms-pipeline-drawer__title-wrap">
                <activeStage.icon size={16} className="sms-brand-icon" aria-hidden="true" />
                <h4 className="sms-pipeline-drawer__title">
                  PHASE 0{STAGES.findIndex((s) => s.id === activeStage.id) + 1} — {activeStage.name}: {activeStage.subtitle}
                </h4>
              </div>
              <button
                type="button"
                className="sms-btn sms-btn--sm sms-btn--ghost"
                onClick={() => setActiveStageId(null)}
                aria-label="Close phase details"
              >
                Close
              </button>
            </div>
            <p className="sms-pipeline-drawer__desc">{activeStage.detail}</p>
            {activeStage.standards && (
              <p className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-11)' }}>
                <strong>Standards & Mechanism:</strong> {activeStage.standards}
              </p>
            )}
          </div>
        </div>
      )}
    </section>
  );
};
