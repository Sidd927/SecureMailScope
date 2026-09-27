import React, { useMemo } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { severityRank } from '../../../utils/severity';
import { ForensicHash } from '../../common/ForensicHash';
import { EmptyState } from '../../common/StateViews';
import { ExecutiveDetermination } from './ExecutiveDetermination';
import { ScoreWaterfall } from './ScoreWaterfall';
import { FindingDossierItem } from './FindingDossierItem';
import { ObservabilityBoundary } from './ObservabilityBoundary';
import { InvestigationPath } from './InvestigationPath';
import { CrossSessionPreviewCard } from './CrossSessionPreviewCard';
import { EvidenceCoverageCard } from './EvidenceCoverageCard';
import { AssessedSessionsCard } from './AssessedSessionsCard';
import { StandardsCard } from './StandardsCard';

export const InvestigationOverview: React.FC = () => {
  const {
    activeRun,
    dashboard,
    sessions,
    selectedFinding,
    selectedStreamKey,
    selectFinding,
    selectSession,
    setActiveTab,
    pivotToJourney,
    pivotToEvidence,
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

  // Highest severity finding affecting each stream for session indicator dots
  const worstByStream = useMemo(() => {
    const worst = new Map<string, string>();
    for (const f of dashboard?.findings ?? []) {
      for (const key of f.affected_stream_keys ?? []) {
        const current = worst.get(key);
        if (!current || severityRank(f.severity) < severityRank(current)) {
          worst.set(key, f.severity ?? '');
        }
      }
    }
    return worst;
  }, [dashboard]);

  if (!dashboard || !activeRun) return null;

  const componentFor = (issueClass: string | null) =>
    dashboard.posture.components.find((c) => c.issue_class === issueClass);

  const primaryFinding = selectedFinding || findings[0];
  const generated = dashboard.identity?.generated_at;

  return (
    <div className="sms-overview-container">
      {/* Zone 0: Case Technical Identity Strip */}
      <header className="sms-case-identity-strip" aria-label="Investigation Case Identity">
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
          {dashboard.identity?.posture_engine_version && (
            <span className="sms-muted">
              engine <span className="sms-mono">{dashboard.identity.posture_engine_version}</span>
            </span>
          )}
          {generated && (
            <span className="sms-muted">
              analysed{' '}
              <span className="sms-mono">
                {generated.replace('T', ' ').replace('Z', ' UTC')}
              </span>
            </span>
          )}
        </div>
      </header>

      {/* Zone 1: Executive Determination Hero + Score Decomposition Waterfall */}
      <div className="sms-overview-grid" aria-label="Executive Determination and Scoring">
        <ExecutiveDetermination
          dashboard={dashboard}
          primaryFinding={primaryFinding}
          sessions={sessions}
          onOpenFinding={(f) => {
            selectFinding(f);
            setActiveTab('evidence');
          }}
          onOpenJourney={(frame, streamKey) => pivotToJourney(frame, streamKey)}
        />

        <ScoreWaterfall posture={dashboard.posture} />
      </div>

      {/* Zone 2: Signature Forensic Investigation Path Motif */}
      <InvestigationPath
        sourceFilename={activeRun.source_filename}
        selectedFinding={primaryFinding}
        posture={dashboard.posture}
        onOpenJourney={(frame, streamKey) => pivotToJourney(frame, streamKey)}
        onOpenEvidence={() => {
          if (primaryFinding) selectFinding(primaryFinding);
          setActiveTab('evidence');
        }}
        onOpenProvenance={(title) => pivotToProvenance(title)}
      />

      {/* Zone 3: Key Findings Dossier + Contextual Deep Dives */}
      <div className="sms-overview-grid" aria-label="Findings Dossier and Contextual Evidence">
        {/* Left Column: Ranked Findings Dossier */}
        <section className="sms-findings-dossier-column" aria-label="Ranked Findings Dossier">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '4px' }}>
            <span className="sms-label">
              Ranked Forensic Findings ({findings.length})
            </span>
            <span className="sms-muted sms-text-xs">Ordered by cryptographic severity & certainty</span>
          </div>

          {findings.length === 0 ? (
            <EmptyState
              title="No cryptographic findings detected"
              detail={dashboard.posture.basis || 'All assessed sessions comply with transport encryption rules.'}
            />
          ) : (
            findings.map((f) => (
              <FindingDossierItem
                key={`${f.rank}-${f.title}`}
                finding={f}
                component={componentFor(f.issue_class)}
                isSelected={selectedFinding?.title === f.title}
                onSelect={() => selectFinding(f)}
                onOpenEvidence={() => {
                  selectFinding(f);
                  pivotToEvidence(f.stream_key ?? undefined);
                }}
                onOpenJourney={(frame, streamKey) => pivotToJourney(frame, streamKey)}
                onOpenProvenance={(title) => pivotToProvenance(title)}
              />
            ))
          )}
        </section>

        {/* Right Column: Contextual Deep Dives */}
        <aside className="sms-context-deep-dives-column" aria-label="Contextual Investigation Anchors">
          {/* Cross-Session Baseline Preview (active when deviations or multi-endpoints exist) */}
          <CrossSessionPreviewCard
            dashboard={dashboard}
            sessions={sessions}
            onOpenCrossSession={() => pivotToCrossSession()}
          />

          {/* Epistemic Evidence Coverage Breakdown */}
          <EvidenceCoverageCard coverage={dashboard.coverage} />

          {/* Assessed Sessions Matrix */}
          <AssessedSessionsCard
            sessions={sessions}
            worstByStream={worstByStream}
            selectedStreamKey={selectedStreamKey}
            onSelectSession={(streamKey) => selectSession(streamKey)}
            onOpenJourney={(frame, streamKey) => pivotToJourney(frame, streamKey)}
          />
        </aside>
      </div>

      {/* Zone 4: Observability Boundary + Normative Standards Baseline */}
      <div className="sms-overview-grid" aria-label="Observability Boundary and Standards">
        <ObservabilityBoundary dashboard={dashboard} />
        <StandardsCard standards={dashboard.standards} />
      </div>
    </div>
  );
};
