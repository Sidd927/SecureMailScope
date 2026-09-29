import React from 'react';
import { ArrowRight, Database, FileCode, GitBranch, Shield, Waypoints } from 'lucide-react';
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
  onOpenScoreDetail,
  onOpenSessions,
}) => {
  const filename = activeRun.source_filename || 'capture.pcap';
  const findings = dashboard.findings || [];
  const session = sessions[0];
  const frame = session?.timing?.first_frame;
  const streamKey = session?.stream_key;
  const sessionCount = sessions.length || dashboard.coverage?.sessions_total || 0;

  const nodes = [
    {
      id: 'capture',
      label: 'Capture bytes',
      icon: FileCode,
      detail: filename,
      onClick: onOpenSessions,
    },
    {
      id: 'wire',
      label: 'Wire events',
      icon: Waypoints,
      detail: frame != null ? `Frame #${frame}` : `${sessionCount} TCP session${sessionCount === 1 ? '' : 's'}`,
      onClick: () => onOpenJourney(frame, streamKey),
    },
    {
      id: 'protocol',
      label: 'Protocol analysis',
      icon: GitBranch,
      detail: `${sessionCount} TCP session${sessionCount === 1 ? '' : 's'}`,
      onClick: () => onOpenJourney(frame, streamKey),
    },
    {
      id: 'findings',
      label: 'Findings',
      icon: Database,
      detail: `${findings.length} finding${findings.length === 1 ? '' : 's'}`,
      onClick: () => onOpenFinding?.(findings[0]?.title || ''),
    },
    {
      id: 'score',
      label: 'Score & posture',
      icon: Shield,
      detail: dashboard.posture.formula_id || dashboard.posture.value || 'Score',
      onClick: onOpenScoreDetail,
    },
  ];

  return (
    <section className="sms-path" aria-label="Investigation path">
      <div className="sms-path__head">
        <h3>Investigation path</h3>
        <p>Capture, wire events, findings, score.</p>
      </div>
      <div className="sms-path__track">
        {nodes.map((node, idx) => {
          const Icon = node.icon;
          return (
            <React.Fragment key={node.id}>
              <button type="button" className="sms-path__node" onClick={node.onClick} disabled={!node.onClick}>
                <span className="sms-path__icon" aria-hidden="true"><Icon size={16} /></span>
                <span className="sms-path__label">{node.label}</span>
                <span className="sms-path__detail">{node.detail}</span>
              </button>
              {idx < nodes.length - 1 && <ArrowRight size={14} className="sms-path__arrow" aria-hidden="true" />}
            </React.Fragment>
          );
        })}
      </div>
    </section>
  );
};
