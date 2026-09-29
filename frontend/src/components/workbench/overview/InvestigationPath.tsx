import React from 'react';
import { ArrowRight, FileSearch, Hash, Layers, ShieldCheck, Scale, Cpu, Activity } from 'lucide-react';
import type { FindingRow, Posture } from '../../../api/types';
import { getSeverityTokens } from '../../../utils/severity';

interface InvestigationPathProps {
  sourceFilename: string;
  selectedFinding?: FindingRow;
  posture: Posture;
  onOpenJourney: (frame?: number, streamKey?: string) => void;
  onOpenEvidence: () => void;
  onOpenProvenance?: (findingTitle: string) => void;
}

export const InvestigationPath: React.FC<InvestigationPathProps> = ({
  sourceFilename,
  selectedFinding,
  posture,
  onOpenJourney,
  onOpenEvidence,
  onOpenProvenance,
}) => {
  const sev = getSeverityTokens(selectedFinding?.severity);
  const streamId = selectedFinding?.tcp_stream_id ?? 0;
  const frameNumber = selectedFinding?.frames?.[0] ?? 1;
  const ruleId = selectedFinding?.source_rule_ids?.[0] || 'SEC-DETERMINISTIC';
  const citation = selectedFinding?.citations?.[0];
  const standardText = citation ? `${citation.standard} ${citation.section || ''}` : 'NIST / RFC';

  return (
    <nav className="sms-investigation-path" aria-label="Investigation Path Traceability">
      <div className="sms-investigation-path__label-wrap">
        <span className="sms-label">Forensic Proof Chain</span>
        <span className="sms-muted sms-text-xs">Bytes ➔ Posture</span>
      </div>

      <ol className="sms-investigation-path__steps">
        {/* Step 1: Capture Source */}
        <li className="sms-path-step">
          <div className="sms-path-step__node" title={`Source capture: ${sourceFilename}`}>
            <FileSearch size={12} className="sms-path-step__icon" aria-hidden="true" />
            <span className="sms-path-step__tag">PCAP</span>
            <span className="sms-path-step__val sms-mono">{sourceFilename.slice(0, 14)}...</span>
          </div>
        </li>

        <li className="sms-path-step__arrow" aria-hidden="true">
          <ArrowRight size={11} />
        </li>

        {/* Step 2: TCP Stream */}
        <li className="sms-path-step">
          <button
            type="button"
            className="sms-path-step__node sms-path-step__node--btn"
            onClick={() => onOpenJourney(frameNumber, selectedFinding?.stream_key ?? undefined)}
            title="Inspect TCP Stream in Protocol Journey"
          >
            <Layers size={12} className="sms-path-step__icon" aria-hidden="true" />
            <span className="sms-path-step__tag">STREAM</span>
            <span className="sms-path-step__val sms-mono">#{streamId}</span>
          </button>
        </li>

        <li className="sms-path-step__arrow" aria-hidden="true">
          <ArrowRight size={11} />
        </li>

        {/* Step 3: Frame */}
        <li className="sms-path-step">
          <button
            type="button"
            className="sms-path-step__node sms-path-step__node--btn"
            onClick={() => onOpenJourney(frameNumber, selectedFinding?.stream_key ?? undefined)}
            title={`Inspect Frame #${frameNumber} in Protocol Journey`}
          >
            <Hash size={12} className="sms-path-step__icon" aria-hidden="true" />
            <span className="sms-path-step__tag">FRAME</span>
            <span className="sms-path-step__val sms-mono">#{frameNumber}</span>
          </button>
        </li>

        <li className="sms-path-step__arrow" aria-hidden="true">
          <ArrowRight size={11} />
        </li>

        {/* Step 4: Wire Evidence Fact */}
        <li className="sms-path-step">
          <button
            type="button"
            className="sms-path-step__node sms-path-step__node--btn"
            onClick={onOpenEvidence}
            title="Inspect Wire Evidence in Evidence Ledger"
          >
            <Activity size={12} className="sms-path-step__icon" aria-hidden="true" />
            <span className="sms-path-step__tag">EVIDENCE</span>
            <span className="sms-path-step__val">OBSERVED</span>
          </button>
        </li>

        <li className="sms-path-step__arrow" aria-hidden="true">
          <ArrowRight size={11} />
        </li>

        {/* Step 5: Posture Rule */}
        <li className="sms-path-step">
          <button
            type="button"
            className="sms-path-step__node sms-path-step__node--btn"
            onClick={() => selectedFinding && onOpenProvenance && onOpenProvenance(selectedFinding.title)}
            title={`Trace rule: ${ruleId}`}
          >
            <Cpu size={12} className="sms-path-step__icon" aria-hidden="true" />
            <span className="sms-path-step__tag">RULE</span>
            <span className="sms-path-step__val sms-mono">{ruleId}</span>
          </button>
        </li>

        <li className="sms-path-step__arrow" aria-hidden="true">
          <ArrowRight size={11} />
        </li>

        {/* Step 6: Standard Citation */}
        <li className="sms-path-step">
          <div className="sms-path-step__node" title={`Normative Citation: ${standardText}`}>
            <Scale size={12} className="sms-path-step__icon" aria-hidden="true" />
            <span className="sms-path-step__tag">STANDARD</span>
            <span className="sms-path-step__val">{standardText}</span>
          </div>
        </li>

        <li className="sms-path-step__arrow" aria-hidden="true">
          <ArrowRight size={11} />
        </li>

        {/* Step 7: Final Posture */}
        <li className="sms-path-step">
          <div
            className="sms-path-step__node sms-path-step__node--final"
            style={{ borderColor: sev ? sev.rule : 'var(--sms-border-strong)' }}
            title={`Final Cryptographic Posture: ${posture.value} (${posture.score_value ?? '—'})`}
          >
            <ShieldCheck size={12} className="sms-path-step__icon" aria-hidden="true" />
            <span className="sms-path-step__tag">POSTURE</span>
            <span className="sms-path-step__val sms-mono" style={{ color: sev?.rule, fontWeight: 700 }}>
              {posture.score_value != null ? posture.score_value.toFixed(1) : '—'} {posture.value}
            </span>
          </div>
        </li>
      </ol>
    </nav>
  );
};
