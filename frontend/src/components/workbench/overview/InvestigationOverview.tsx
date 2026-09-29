import React, { useMemo } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { severityRank } from '../../../utils/severity';
import { FileSpreadsheet, FileText } from 'lucide-react';
import { ForensicHash } from '../../common/ForensicHash';
import { relativeTime } from '../../../utils/time';
import { ExecutiveDetermination } from './ExecutiveDetermination';
import { InvestigationFlow } from '../flow/InvestigationFlow';
import { ScoreWaterfall } from './ScoreWaterfall';
import { ProofCard } from './ProofCard';
import { ObservabilityBoundary } from './ObservabilityBoundary';
import { NextInvestigations } from './NextInvestigations';
import type { FindingRow } from '../../../api/types';

export const InvestigationOverview: React.FC = () => {
  const {
    activeRun,
    dashboard,
    sessions,
    selectedFinding,
    selectFinding,
    setActiveTab,
    pivotToJourney,
    pivotToProvenance,
    pivotToCrossSession,
  } = useInvestigation();

  // Findings sorted by severity rank and priority
  const findings = useMemo(
    () =>
      [...(dashboard?.findings ?? [])].sort(
        (a, b) =>
          severityRank(a.severity) - severityRank(b.severity) ||
          (a.rank ?? 0) - (b.rank ?? 0)
      ),
    [dashboard]
  );

  if (!dashboard || !activeRun) return null;

  const primaryFinding = selectedFinding || findings[0];
  const generated = dashboard.identity?.generated_at;

  const handleOpenFindingByTitle = (title: string) => {
    const match = findings.find((f) => f.title.toLowerCase().includes(title.toLowerCase()));
    if (match) {
      selectFinding(match);
      setActiveTab('evidence');
    } else {
      setActiveTab('evidence');
    }
  };

  const sessionTotal = sessions.length || dashboard.coverage?.sessions_total || 0;

  return (
    <div className="sms-overview-container" aria-label="Forensic Investigation Overview">
      <div className="sms-case-strip">
        <div className="sms-case-strip__file">
          <FileSpreadsheet size={16} aria-hidden="true" />
          <span className="sms-mono sms-case-strip__name" title={activeRun.source_filename}>
            {activeRun.source_filename}
          </span>
          <ForensicHash
            value={dashboard.identity?.capture_id || activeRun.capture_id}
            length={12}
            label="SHA-256"
          />
        </div>
        <div className="sms-case-strip__meta">
          <span>{sessionTotal} TCP session{sessionTotal === 1 ? '' : 's'}</span>
          <span>{dashboard.findings.length} finding{dashboard.findings.length === 1 ? '' : 's'}</span>
          {activeRun.duration_ms != null && <span>{activeRun.duration_ms} ms</span>}
          {generated && <span>Analysed {relativeTime(generated)}</span>}
        </div>
      </div>

      <div className="sms-overview-head">
        <h2 className="sms-overview-title">
          <FileText size={18} aria-hidden="true" />
          Overview
        </h2>
      </div>

      <section className="sms-overview-section" aria-label="Executive Determination">
        <ExecutiveDetermination
          dashboard={dashboard}
          primaryFinding={primaryFinding}
          sessions={sessions}
          onOpenFinding={(f: FindingRow) => {
            selectFinding(f);
            setActiveTab('evidence');
          }}
          onOpenFrame={(frame: number, streamKey?: string) => {
            pivotToJourney(frame, streamKey);
          }}
          onTraceProvenance={(f?: FindingRow) => {
            if (f) selectFinding(f);
            pivotToProvenance(f?.source_rule_ids?.[0] || f?.title);
          }}
        />
      </section>

      <section className="sms-overview-section" aria-label="Score Deductions">
        <ScoreWaterfall posture={dashboard.posture} />
      </section>

      <section className="sms-overview-section" aria-label="Wire Proof">
        <ProofCard
          dashboard={dashboard}
          primaryFinding={primaryFinding}
          sessions={sessions}
          onOpenJourney={(frame, streamKey) => pivotToJourney(frame, streamKey)}
          onOpenProvenance={(title) => pivotToProvenance(title)}
          onOpenEvidence={() => {
            if (primaryFinding) selectFinding(primaryFinding);
            setActiveTab('evidence');
          }}
        />
      </section>

      {/* 3. INVESTIGATION PATH — Visual Evidentiary Story Map */}
      <section className="sms-overview-section" aria-label="Investigation Path">
        <InvestigationFlow
          dashboard={dashboard}
          activeRun={activeRun}
          sessions={sessions}
          onOpenJourney={(frame, streamKey) => pivotToJourney(frame, streamKey)}
          onOpenFinding={handleOpenFindingByTitle}
          onOpenCrossSession={() => pivotToCrossSession()}
          onOpenCertificates={() => setActiveTab('certs')}
          onOpenScoreDetail={() => {
            document.querySelector('.sms-score-waterfall')?.scrollIntoView({ behavior: 'smooth' });
          }}
          onOpenSessions={() => setActiveTab('journey')}
        />
      </section>

      {/* 5. WHAT CAN WE CONCLUDE VS NOT CONCLUDE? — Observability Boundary */}
      <section className="sms-overview-section" aria-label="Observability Boundary">
        <ObservabilityBoundary dashboard={dashboard} />
      </section>

      {/* 6. WHERE CAN I GO NEXT? — Investigation Pathways */}
      <section className="sms-overview-section" aria-label="Question 5: Next Investigations">
        <NextInvestigations
          dashboard={dashboard}
          sessions={sessions}
          onNavigate={(tab) => setActiveTab(tab)}
        />
      </section>
    </div>
  );
};
