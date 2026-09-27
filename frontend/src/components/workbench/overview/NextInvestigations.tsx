import React from 'react';
import {
  Table,
  Network,
  KeyRound,
  Layers,
  FileText,
  ArrowRight,
  GitBranch,
} from 'lucide-react';
import type { DashboardViewModel, SessionEvidence } from '../../../api/types';
import type { ForensicTab } from '../../../context/InvestigationContext';

interface NextInvestigationsProps {
  dashboard: DashboardViewModel;
  sessions: SessionEvidence[];
  onNavigate: (tab: ForensicTab) => void;
}

export const NextInvestigations: React.FC<NextInvestigationsProps> = ({
  dashboard,
  sessions,
  onNavigate,
}) => {
  const findingsCount = dashboard.findings?.length || 0;
  const sessionCount = sessions.length || dashboard.coverage?.sessions_total || 1;
  const hasDeviations = (dashboard.findings || []).some(
    (f) => (f.source_rule_ids || []).some((r) => r.startsWith('CS-')) || f.title.toLowerCase().includes('deviation')
  );
  const certCount = sessions.reduce((acc, s) => acc + (s.certificates?.length || 0), 0);

  const pathways = [
    {
      tab: 'evidence' as ForensicTab,
      title: 'Ranked Findings',
      count: findingsCount,
      countLabel: 'finding',
      desc: 'Inspect detailed findings, certainty metrics, and associated wire evidence fields.',
      icon: Table,
      action: 'Inspect Findings',
      accent: findingsCount > 0 ? 'var(--ds-sev-critical-text)' : 'var(--sms-text-secondary)',
    },
    {
      tab: 'journey' as ForensicTab,
      title: 'Protocol Journey',
      count: sessionCount,
      countLabel: 'stream',
      desc: 'Trace chronological packet sequence and wire state machine from greeting to close.',
      icon: Network,
      action: 'Open Protocol Journey',
      accent: 'var(--sms-brand-cyan)',
    },
    {
      tab: 'certs' as ForensicTab,
      title: 'Certificate Forensics',
      count: certCount,
      countLabel: 'cert',
      desc: 'Examine X.509 public key strength, signature hashes, and TLS 1.3 encrypted handshake boundaries.',
      icon: KeyRound,
      action: 'Examine Certificates',
      accent: '#a855f7',
    },
    {
      tab: 'cross_session' as ForensicTab,
      title: 'Cross-Session Analysis',
      count: sessionCount,
      countLabel: 'endpoint',
      desc: hasDeviations
        ? 'Active behavioral deviation: Subject 10.0.0.6 lacks STARTTLS capability advertised by Control 10.0.0.7.'
        : 'Comparative baseline across all reconstructed TCP sessions to the same service.',
      icon: Layers,
      action: 'Compare Sessions',
      accent: hasDeviations ? 'var(--ds-sev-high-text)' : 'var(--sms-text-secondary)',
      highlight: hasDeviations,
    },
    {
      tab: 'provenance' as ForensicTab,
      title: 'Traceability & Provenance',
      desc: 'Trace unbroken evidentiary chain from PCAP bytes to rule citation and posture calculation.',
      icon: GitBranch,
      action: 'Trace Chain',
      accent: 'var(--sms-brand-blue)',
    },
    {
      tab: 'report' as ForensicTab,
      title: 'Forensic Report',
      desc: 'Official cryptographic posture assessment deliverable exportable in PDF, HTML, or JSON format.',
      icon: FileText,
      action: 'Generate Report',
      accent: 'var(--sms-brand-cyan)',
    },
  ];

  return (
    <section className="sms-next-investigations" aria-label="Next Investigation Pathways">
      <div className="sms-next-investigations__head">
        <span className="sms-label">Investigate further</span>
        <span className="sms-muted sms-text-xs">
          Select an investigation pathway to dive deeper into technical evidence
        </span>
      </div>

      <div className="sms-next-grid">
        {pathways.map((p) => {
          const Icon = p.icon;
          return (
            <button
              key={p.tab}
              type="button"
              className={`sms-next-card ${p.highlight ? 'sms-next-card--highlight' : ''}`}
              onClick={() => onNavigate(p.tab)}
              title={`Navigate to ${p.title}`}
            >
              <div className="sms-next-card__top">
                <div className="sms-next-card__icon-wrap" style={{ color: p.accent }}>
                  <Icon size={16} aria-hidden="true" />
                </div>
                {p.count !== undefined && (
                  <span className="sms-badge sms-badge--muted sms-mono">
                    {p.count} {p.countLabel}{p.count === 1 ? '' : 's'}
                  </span>
                )}
              </div>

              <div className="sms-next-card__body">
                <h3 className="sms-next-card__title">{p.title}</h3>
                <p className="sms-next-card__desc">{p.desc}</p>
              </div>

              <div className="sms-next-card__footer">
                <span className="sms-next-card__action">{p.action}</span>
                <ArrowRight size={13} className="sms-next-card__arrow" aria-hidden="true" />
              </div>
            </button>
          );
        })}
      </div>
    </section>
  );
};
