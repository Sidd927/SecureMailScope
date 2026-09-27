import React from 'react';
import type { AssessmentResponse, FindingRow, RunResponse, ScoreComponentRow, SessionEvidence } from '../../../api/types';
import { evidenceRefsForFinding, fieldLabel } from '../../../utils/findingEvidence';
import { EvidenceBadge } from '../../common/EvidenceBadge';
import { ForensicHash } from '../../common/ForensicHash';
import { SeverityBadge } from '../../common/SeverityBadge';
import { CertaintyBadge, FindingStatusBadge } from '../../common/VocabularyBadges';
import { sessionLabel } from '../../../utils/session';

interface Props {
  finding: FindingRow;
  run: RunResponse;
  session: SessionEvidence | null;
  assessment: AssessmentResponse | null;
  component: ScoreComponentRow | undefined;
  formulaId: string | null;
  onOpenFrame: (frame: number, streamKey?: string) => void;
}

export const EvidenceChain: React.FC<Props> = ({ finding, run, session, assessment, component, formulaId, onOpenFrame }) => {
  const refs = evidenceRefsForFinding(assessment, finding);
  const primaryFrame = finding.frames && finding.frames.length > 0 ? finding.frames[0] : (refs[0]?.frames?.[0] ?? null);
  const ruleId = finding.source_rule_ids?.[0] || finding.issue_class || 'RULE';
  const citation = finding.citations?.[0];
  const standardText = citation ? [citation.standard, citation.section].filter(Boolean).join(' ') : null;
  const clientEndpoint = session?.client ? `${session.client.ip}:${session.client.port}` : null;
  const serverEndpoint = session?.server ? `${session.server.ip}:${session.server.port}` : null;
  const penalty = component?.penalty ?? ((finding as any).penalty ?? null);

  return (
    <div className="sms-provenance-flow" aria-label={`Provenance trace for ${finding.title}`}>
      {/* 1. CAPTURE */}
      <div className="sms-prov-node sms-prov-node--capture">
        <span className="sms-prov-node__stage">1. CAPTURE</span>
        <div className="sms-prov-node__content">
          <span className="sms-mono sms-prov-node__title">{run.source_filename}</span>
          <ForensicHash value={run.capture_id} length={20} label="SHA-256" />
        </div>
      </div>

      <div className="sms-prov-arrow" aria-hidden="true">↓</div>

      {/* 2. TCP STREAM */}
      <div className="sms-prov-node sms-prov-node--stream">
        <span className="sms-prov-node__stage">2. TCP STREAM #{session?.tcp_stream_id ?? finding.tcp_stream_id ?? 0}</span>
        <div className="sms-prov-node__content">
          {clientEndpoint && serverEndpoint ? (
            <span className="sms-mono sms-prov-node__endpoints">
              {clientEndpoint} <span className="sms-prov-node__arrow-char">→</span> {serverEndpoint}
            </span>
          ) : (
            <span className="sms-mono">{session ? sessionLabel(session) : `Stream #${finding.tcp_stream_id ?? 0}`}</span>
          )}
          {finding.affected_sessions != null && finding.affected_sessions > 1 && (
            <span className="sms-muted sms-text-xs">Finding observed across {finding.affected_sessions} sessions</span>
          )}
        </div>
      </div>

      <div className="sms-prov-arrow" aria-hidden="true">↓</div>

      {/* 3. FRAME */}
      {primaryFrame != null && (
        <>
          <button
            type="button"
            className="sms-prov-node sms-prov-node--frame is-interactive"
            onClick={() => onOpenFrame(primaryFrame, finding.stream_key ?? undefined)}
            title={`Click to focus Frame #${primaryFrame} in Protocol Journey`}
          >
            <span className="sms-prov-node__stage">3. WIRE FRAME</span>
            <div className="sms-prov-node__content">
              <span className="sms-mono sms-prov-node__frame-val">Frame #{primaryFrame}</span>
              <span className="sms-prov-node__action-hint">Jump to packet dissection →</span>
            </div>
          </button>
          <div className="sms-prov-arrow" aria-hidden="true">↓</div>
        </>
      )}

      {/* 4. WIRE EVIDENCE */}
      <div className="sms-prov-node sms-prov-node--evidence">
        <span className="sms-prov-node__stage">4. WIRE EVIDENCE</span>
        <div className="sms-prov-node__facts">
          {refs.length > 0 ? (
            refs.map((r, i) => (
              <div key={`${r.field}-${i}`} className="sms-prov-fact-row">
                <span className="sms-mono sms-prov-fact-key">{fieldLabel(r.field)}</span>
                <span className="sms-mono sms-prov-fact-val">= {r.observed_value ?? 'UNKNOWN'}</span>
                <EvidenceBadge state={r.evidence_state} size="sm" />
              </div>
            ))
          ) : (
            <div className="sms-prov-fact-row">
              <span className="sms-mono sms-prov-fact-key">EVALUATION</span>
              <span className="sms-mono sms-prov-fact-val">{finding.conclusion || 'Observed wire evidence'}</span>
            </div>
          )}
        </div>
      </div>

      <div className="sms-prov-arrow" aria-hidden="true">↓</div>

      {/* 5. RULE */}
      <div className="sms-prov-node sms-prov-node--rule">
        <span className="sms-prov-node__stage">5. DETERMINISTIC RULE</span>
        <div className="sms-prov-node__content">
          <span className="sms-mono sms-prov-node__rule-id">{ruleId}</span>
          {finding.issue_class_label && (
            <span className="sms-muted sms-text-xs">{finding.issue_class_label}</span>
          )}
        </div>
      </div>

      <div className="sms-prov-arrow" aria-hidden="true">↓</div>

      {/* 6. STANDARD */}
      {standardText && (
        <>
          <div className="sms-prov-node sms-prov-node--standard">
            <span className="sms-prov-node__stage">6. NORMATIVE STANDARD</span>
            <div className="sms-prov-node__content">
              <span className="sms-mono sms-prov-node__standard-val">{standardText}</span>
              {citation?.reason && (
                <span className="sms-muted sms-text-xs">{citation.reason}</span>
              )}
            </div>
          </div>
          <div className="sms-prov-arrow" aria-hidden="true">↓</div>
        </>
      )}

      {/* 7. FINDING & CERTAINTY */}
      <div className="sms-prov-node sms-prov-node--finding">
        <span className="sms-prov-node__stage">7. POSTURE FINDING</span>
        <div className="sms-prov-node__content">
          <div className="sms-prov-node__badges">
            <SeverityBadge severity={finding.severity} />
            <CertaintyBadge certainty={finding.certainty} />
            <FindingStatusBadge status={finding.status} />
          </div>
          <span className="sms-prov-node__title" style={{ marginTop: '4px' }}>{finding.title}</span>
        </div>
      </div>

      <div className="sms-prov-arrow" aria-hidden="true">↓</div>

      {/* 8. POSTURE DEDUCTION */}
      <div className="sms-prov-node sms-prov-node--penalty">
        <span className="sms-prov-node__stage">8. SCORE DEDUCTION</span>
        <div className="sms-prov-node__content">
          <span className="sms-mono sms-prov-node__penalty-val">
            {penalty != null ? `−${penalty.toFixed(2)} pts` : 'Rule deduction'}
          </span>
          <span className="sms-muted sms-text-xs">{formulaId || 'F2-group-damped scoring'}</span>
        </div>
      </div>
    </div>
  );
};
