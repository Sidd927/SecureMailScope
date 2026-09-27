import React, { useMemo } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { severityRank } from '../../../utils/severity';
import { ForensicHash } from '../../common/ForensicHash';
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

  return (
    <div className="sms-overview-container" aria-label="Forensic Investigation Overview">
      {/* 1. DETERMINATION & VERDICT (First Viewport Lead) */}
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

      {/* 2. WHY THE SCORE? & WIRE EVIDENCE — Aligned Mathematical & Physical Proof */}
      <section className="sms-overview-grid" aria-label="Score Deductions and Wire Proof">
        {/* Left: Score Waterfall */}
        <div style={{ gridColumn: 'span 6' }}>
          <ScoreWaterfall posture={dashboard.posture} />
        </div>

        {/* Right: Wire Evidence Table */}
        <div style={{ gridColumn: 'span 6' }}>
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
        </div>
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

      {/* 7. Capture Telemetry & Analytical Identity Footer */}
      <footer className="sms-case-identity-strip" aria-label="Investigation Case Identity">
        <div className="sms-case-identity-strip__left">
          <span className="sms-case-identity-strip__filename">
            {activeRun.source_filename}
          </span>
          <span className="sms-case-identity-strip__sep">/</span>
          <ForensicHash
            value={dashboard.identity?.capture_id || activeRun.capture_id}
            length={16}
            label="SHA-256"
          />
        </div>

        <div className="sms-case-identity-strip__right">
          <span className="sms-muted">
            <span className="sms-mono" style={{ color: 'var(--sms-text-primary)' }}>
              {sessions.length || dashboard.coverage?.sessions_total || 0}
            </span>{' '}
            TCP session{(sessions.length || dashboard.coverage?.sessions_total || 0) === 1 ? '' : 's'}
          </span>
          <span className="sms-muted">
            <span className="sms-mono" style={{ color: 'var(--sms-text-primary)' }}>
              {dashboard.findings.length}
            </span>{' '}
            finding{dashboard.findings.length === 1 ? '' : 's'}
          </span>
          {activeRun.duration_ms != null && (
            <span className="sms-muted">
              <span className="sms-mono">{activeRun.duration_ms} ms</span>
            </span>
          )}
          <span className="sms-muted">
            engine <span className="sms-mono">{dashboard.identity?.posture_engine_version || '0.8.0'}</span>
          </span>
          {generated && (
            <span className="sms-muted">
              analysed{' '}
              <span className="sms-mono">
                {generated.replace('T', ' ').replace('Z', ' UTC')}
              </span>
            </span>
          )}
        </div>
      </footer>
    </div>
  );
};
