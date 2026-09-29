import React, { useEffect, useMemo, useState } from 'react';
import { useInvestigation } from '../../../context/InvestigationContext';
import type { FindingRow } from '../../../api/types';
import { evidenceRefsForFinding } from '../../../utils/findingEvidence';
import { EVIDENCE_STATES } from '../../../utils/evidence';
import { severityRank } from '../../../utils/severity';
import { ClipboardList, Search } from 'lucide-react';
import { EvidenceBadge } from '../../common/EvidenceBadge';
import { Panel } from '../../common/Panel';
import { EmptyState } from '../../common/StateViews';
import { FindingsTable } from './FindingsTable';
import { FindingEvidenceDetail } from './FindingEvidenceDetail';
import { SessionEvidencePanel } from './SessionEvidencePanel';

export const EvidenceLedger: React.FC = () => {
  const { dashboard, assessment, selectedFinding, selectFinding, sectionErrors, pivotToJourney, selectEventFrame, pivotToProvenance } = useInvestigation();
  const [stateFilter, setStateFilter] = useState<string | null>(null);

  const findings = useMemo(
    () => [...(dashboard?.findings ?? [])].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || (a.rank ?? 0) - (b.rank ?? 0)),
    [dashboard],
  );

  // A finding "has" an evidence state when the rule engine cited at least one field in that state.
  const statesByFinding = useMemo(() => {
    const map = new Map<FindingRow, Set<string>>();
    for (const f of findings) map.set(f, new Set(evidenceRefsForFinding(assessment, f).map((r) => r.evidence_state)));
    return map;
  }, [findings, assessment]);

  const chips = EVIDENCE_STATES.map((s) => ({
    state: s.state,
    n: findings.filter((f) => statesByFinding.get(f)?.has(s.state)).length,
  })).filter((c) => c.n > 0);

  const visible = stateFilter ? findings.filter((f) => statesByFinding.get(f)?.has(stateFilter)) : findings;
  const selected = selectedFinding && visible.some((f) => f.rank === selectedFinding.rank && f.title === selectedFinding.title) ? selectedFinding : visible[0] ?? null;

  useEffect(() => {
    if (!selectedFinding && findings[0]) selectFinding(findings[0]);
  }, [selectedFinding, findings, selectFinding]);

  const openFrame = (frame: number, streamKey?: string) => { pivotToJourney(frame, streamKey); selectEventFrame(frame); };
  const traceFinding = (f: FindingRow) => { selectFinding(f); pivotToProvenance(f.title); };

  return (
    <div className="sms-page sms-evidence-page">
      <header className="sms-page-head sms-evidence-hero">
        <div>
          <h1 className="sms-page-title">Findings</h1>
          <p className="sms-page-sub">Severity, affected session, and proof.</p>
        </div>
        {chips.length > 0 && (
          <details className="sms-evidence-filters">
            <summary>Filter</summary>
            <div role="group" aria-label="Filter by evidence state" style={{ display: 'flex', gap: 'var(--ds-space-8)', flexWrap: 'wrap' }}>
            {chips.map((c) => {
              const on = stateFilter === c.state;
              return (
                <button
                  key={c.state}
                  type="button"
                  aria-pressed={on}
                  onClick={() => setStateFilter(on ? null : c.state)}
                  style={{ borderRadius: 'var(--ds-radius-sm)', outline: on ? '1px solid var(--ds-border-focus)' : undefined, outlineOffset: 2 }}
                  title={`${c.n} finding${c.n === 1 ? '' : 's'} cite ${c.state} evidence${on ? ' (filter on)' : ''}`}
                >
                  <EvidenceBadge state={c.state} count={c.n} />
                </button>
              );
            })}
            </div>
          </details>
        )}
      </header>

      <div className="sms-split sms-split--60 sms-evidence-grid">
        <Panel
          className="sms-evidence-card"
          title={<span className="sms-evidence-card__label"><Search size={14} aria-hidden="true" /> Findings</span>}
          meta={findings.length === 0 ? undefined : stateFilter ? `${visible.length} of ${findings.length}` : String(findings.length)}
          flush={findings.length > 0}
        >
          {findings.length === 0 ? (
            <EmptyState icon={<Search size={28} aria-hidden="true" />} title="No findings in this capture." />
          ) : (
            <FindingsTable
              findings={visible}
              selected={selected}
              onSelect={selectFinding}
              onOpenFrame={openFrame}
              onTrace={traceFinding}
            />
          )}
        </Panel>
        <div className="sms-evidence-focus">
          <Panel
            className="sms-evidence-card"
            title={<span className="sms-evidence-card__label"><ClipboardList size={14} aria-hidden="true" /> Focused evidence</span>}
          >
            <FindingEvidenceDetail
              finding={selected}
              assessment={assessment}
              assessmentError={sectionErrors.assessment}
              onOpenFrame={openFrame}
              onTrace={traceFinding}
            />
          </Panel>
        </div>
      </div>

      <SessionEvidencePanel />
    </div>
  );
};
