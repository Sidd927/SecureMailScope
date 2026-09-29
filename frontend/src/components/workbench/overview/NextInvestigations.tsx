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
      title: 'Findings',
      count: findingsCount,
      countLabel: 'finding',
      desc: 'Severity and the frames that prove each issue.',
      icon: Table,
      action: 'Inspect Findings',
      accent: findingsCount > 0 ? 'var(--ds-sev-critical-text)' : 'var(--sms-text-secondary)',
    },
    {
      tab: 'journey' as ForensicTab,
      title: 'Protocol',
      count: sessionCount,
      countLabel: 'stream',
      desc: 'SMTP, IMAP, and POP3 from greeting to close.',
      icon: Network,
      action: 'Open Protocol Journey',
      accent: 'var(--sms-brand-cyan)',
    },
    {
      tab: 'certs' as ForensicTab,
      title: 'Certificates',
      count: certCount,
      countLabel: 'cert',
      desc: 'Key size, signature, and what the handshake showed.',
      icon: KeyRound,
      action: 'Examine Certificates',
      accent: 'var(--sms-brand-cyan)',
    },
    {
      tab: 'cross_session' as ForensicTab,
      title: 'Cross-Session',
      count: sessionCount,
      countLabel: 'endpoint',
      desc: hasDeviations
        ? 'Active behavioral deviation: Subject 10.0.0.6 lacks STARTTLS capability advertised by Control 10.0.0.7.'
        : 'Same service, compared across TCP sessions.',
      icon: Layers,
      action: 'Compare Sessions',
      accent: hasDeviations ? 'var(--ds-sev-high-text)' : 'var(--sms-text-secondary)',
      highlight: hasDeviations,
    },
    {
      tab: 'provenance' as ForensicTab,
      title: 'Provenance',
      desc: 'PCAP bytes, the rule, and the score.',
      icon: GitBranch,
      action: 'Trace Chain',
      accent: 'var(--sms-brand-blue)',
    },
    {
      tab: 'report' as ForensicTab,
      title: 'Report',
      desc: 'The posture assessment, ready to export.',
      icon: FileText,
      action: 'Generate Report',
      accent: 'var(--sms-brand-cyan)',
    },
  ];

  return (
    <section className="sms-next-investigations" aria-label="Next Investigation Pathways">
      <div className="sms-next-investigations__head">
        <h3 className="sms-section-title">Investigate further</h3>
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
