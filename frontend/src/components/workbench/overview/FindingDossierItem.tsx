import React from 'react';
import { Compass, GitBranch, Table } from 'lucide-react';
import type { FindingRow, ScoreComponentRow } from '../../../api/types';
import { getSeverityTokens } from '../../../utils/severity';
import { SeverityBadge } from '../../common/SeverityBadge';
import { CertaintyBadge, FindingStatusBadge } from '../../common/VocabularyBadges';

interface FindingDossierItemProps {
  finding: FindingRow;
  component?: ScoreComponentRow;
  isSelected?: boolean;
  onSelect: () => void;
  onOpenEvidence: () => void;
  onOpenJourney: (frame?: number, streamKey?: string) => void;
  onOpenProvenance?: (findingTitle: string) => void;
}

export const FindingDossierItem: React.FC<FindingDossierItemProps> = ({
  finding,
  component,
  isSelected = false,
  onSelect,
  onOpenEvidence,
  onOpenJourney,
  onOpenProvenance,
}) => {
  const sev = getSeverityTokens(finding.severity);
  const citation = finding.citations?.[0];
  const standardText = citation ? [citation.standard, citation.section].filter(Boolean).join(' ') : null;
  const primaryFrame = finding.frames?.[0];
  const primaryRule = finding.source_rule_ids?.[0];
  const penalty = component?.penalty ?? null;

  return (
    <article
      className={`sms-finding-dossier ${isSelected ? 'sms-finding-dossier--selected' : ''}`}
      style={{
        borderLeftColor: sev ? sev.rule : 'var(--sms-border-strong)',
      }}
      onClick={onSelect}
      tabIndex={0}
      role="region"
      aria-label={`${finding.severity ?? 'Unrated'} finding: ${finding.title}`}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect();
        }
      }}
    >
      {/* Top Metadata Strip */}
      <div className="sms-finding-dossier__head">
        <div className="sms-finding-dossier__badges">
          <SeverityBadge severity={finding.severity} size="sm" />
          {finding.certainty && <CertaintyBadge certainty={finding.certainty} />}
          {finding.status && <FindingStatusBadge status={finding.status} />}
        </div>

        <div className="sms-finding-dossier__penalty-wrap">
          {penalty !== null && penalty > 0 && (
            <span className="sms-mono sms-finding-dossier__penalty" title="Posture penalty deduction">
              −{penalty.toFixed(1)} pts
            </span>
          )}
        </div>
      </div>

      {/* Finding Title & Plain-English Conclusion */}
      <h3 className="sms-finding-dossier__title">{finding.title}</h3>
      {finding.conclusion && (
        <p className="sms-finding-dossier__conclusion">{finding.conclusion}</p>
      )}

      {/* Wire Evidence Anchor Strip */}
      <div className="sms-finding-dossier__wire-strip">
        <div className="sms-finding-dossier__wire-anchors">
          {finding.tcp_stream_id != null && (
            <span className="sms-mono sms-badge" title="TCP Stream Identifier">
              Stream #{finding.tcp_stream_id}
            </span>
          )}
          {finding.frames?.length > 0 && (
            <span className="sms-mono sms-badge" title="Packet Frame References">
              Frame {finding.frames_text || finding.frames.join(', ')}
            </span>
          )}
          {primaryRule && (
            <span className="sms-mono sms-badge sms-badge--rule" title="Deterministic Rule">
              {primaryRule}
            </span>
          )}
          {standardText && (
            <span className="sms-badge sms-badge--standard" title="Normative Citation">
              {standardText}
            </span>
          )}
          {finding.affected_sessions != null && finding.affected_sessions > 0 && (
            <span className="sms-badge sms-badge--muted">
              {finding.affected_sessions} session{finding.affected_sessions === 1 ? '' : 's'}
            </span>
          )}
        </div>

        {/* Pivot Action Buttons */}
        <div className="sms-finding-dossier__actions" onClick={(e) => e.stopPropagation()}>
          <button
            type="button"
            className="sms-btn sms-btn--ghost sms-btn--sm"
            onClick={onOpenEvidence}
            title="Inspect full facts and fields in Findings & Evidence"
          >
            <Table size={12} aria-hidden="true" />
            <span>Evidence</span>
          </button>

          {primaryFrame != null && (
            <button
              type="button"
              className="sms-btn sms-btn--ghost sms-btn--sm"
              onClick={() => onOpenJourney(primaryFrame, finding.stream_key ?? undefined)}
              title={`Jump to Frame #${primaryFrame} in Protocol Journey`}
            >
              <Compass size={12} aria-hidden="true" />
              <span>Frame #{primaryFrame}</span>
            </button>
          )}

          {onOpenProvenance && primaryRule && (
            <button
              type="button"
              className="sms-btn sms-btn--ghost sms-btn--sm"
              onClick={() => onOpenProvenance(finding.title)}
              title="Inspect rule provenance and rule hierarchy"
            >
              <GitBranch size={12} aria-hidden="true" />
              <span>Trace</span>
            </button>
          )}
        </div>
      </div>
    </article>
  );
};
