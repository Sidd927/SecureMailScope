import React, { useEffect, useMemo } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { severityRank } from '../../../utils/severity';
import { Panel } from '../../common/Panel';
import { SeverityDot } from '../../common/SeverityBadge';
import { EmptyState, SkeletonRows } from '../../common/StateViews';
import { CertaintyBadge } from '../../common/VocabularyBadges';
import { EvidenceChain } from './EvidenceChain';

export const ProvenanceGraph: React.FC = () => {
  const { activeRun, dashboard, assessment, sessions, selectedFinding, selectFinding, pivotToJourney, selectEventFrame, isLoading, sectionErrors } = useInvestigation();

  const findings = useMemo(
    () => [...(dashboard?.findings ?? [])].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || (a.rank ?? 0) - (b.rank ?? 0)),
    [dashboard],
  );

  // Automatically select the highest-severity finding if none is currently selected (Section 15)
  const current = (selectedFinding && findings.find((f) => f.rank === selectedFinding.rank && f.title === selectedFinding.title)) ?? findings[0] ?? null;

  useEffect(() => {
    if (!selectedFinding && findings[0]) {
      selectFinding(findings[0]);
    }
  }, [selectedFinding, findings, selectFinding]);

  const session = current ? sessions.find((s) => s.stream_key === current.stream_key) ?? null : null;
  const component = current ? dashboard?.posture.components.find((c) => c.issue_class === current.issue_class) : undefined;
  const openFrame = (frame: number, streamKey?: string) => { pivotToJourney(frame, streamKey); selectEventFrame(frame); };

  let chain: React.ReactNode;
  if (isLoading && !assessment) chain = <SkeletonRows rows={7} height={48} gap="var(--ds-space-12)" />;
  else if (!current || !activeRun) chain = <EmptyState title="No findings to trace" detail="The capture has zero findings." />;
  else chain = (
    <>
      {sectionErrors.assessment && <p className="sms-prose" style={{ color: 'var(--ds-crimson-ink)', marginBottom: 'var(--ds-space-12)' }}>Assessment failed to load: {sectionErrors.assessment}. Evidence and rule steps are unavailable.</p>}
      <EvidenceChain finding={current} run={activeRun} session={session} assessment={assessment} component={component} formulaId={dashboard?.posture.formula_id ?? null} onOpenFrame={openFrame} />
    </>
  );

  return (
    <div className="sms-page">
      <header className="sms-page-head">
        <div>
          <h1 className="sms-page-title">Provenance</h1>
          <p className="sms-page-sub">The forensic trace from capture bytes to a posture deduction: which stream, which evidence fields and frames, which rules, which standards.</p>
        </div>
      </header>

      {findings.length === 0 ? (
        <Panel><EmptyState title="No findings for this capture" detail="There is nothing to trace." /></Panel>
      ) : (
        <div className="sms-split sms-split--40">
          <Panel title="Findings" meta={String(findings.length)} flush>
            <ul className="sms-node-list" aria-label="Findings">
              {findings.map((f) => {
                const active = current === f;
                return (
                  <li key={`${f.rank}-${f.title}`}>
                    <button type="button" className="sms-node" aria-current={active} onClick={() => selectFinding(f)}>
                      <SeverityDot severity={f.severity} />
                      <span style={{ minWidth: 0 }}>{f.title}</span>
                      {f.certainty && <CertaintyBadge certainty={f.certainty} />}
                    </button>
                  </li>
                );
              })}
            </ul>
          </Panel>
          <div className="sms-sticky">
            <Panel title="Evidence chain" meta={current?.source_rule_ids?.join(', ')}>{chain}</Panel>
          </div>
        </div>
      )}
    </div>
  );
};
