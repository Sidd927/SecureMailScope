import React from 'react';
import { Radio, GitFork, BookOpen } from 'lucide-react';
import type { AssessmentResponse, FindingRow } from '../../../api/types';
import { evidenceRefsForFinding, fieldLabel } from '../../../utils/findingEvidence';
import { framesLabel } from '../../../utils/evidence';
import { EvidenceBadge } from '../../common/EvidenceBadge';
import { SeverityBadge } from '../../common/SeverityBadge';
import { CertaintyBadge } from '../../common/VocabularyBadges';
import { EmptyState } from '../../common/StateViews';

interface Props {
  finding: FindingRow | null;
  assessment: AssessmentResponse | null;
  assessmentError?: string;
  onOpenFrame: (frame: number, streamKey?: string) => void;
  onTrace?: (finding: FindingRow) => void;
}

export const FindingEvidenceDetail: React.FC<Props> = ({
  finding,
  assessment,
  assessmentError,
  onOpenFrame,
  onTrace,
}) => {
  if (!finding) return <EmptyState title="Select a finding to inspect its evidence" />;

  const refs = evidenceRefsForFinding(assessment, finding);
  const remediation = finding.remediation;
  const primaryFrame = finding.frames && finding.frames.length > 0 ? finding.frames[0] : null;

  return (
    <div className="sms-focused-evidence-view" aria-label={`Forensic note for ${finding.title}`}>
      {/* 1. TITLE & VERDICT EYEBROW */}
      <header className="sms-analyst-note__header">
        <div className="sms-analyst-note__eyebrow">
          <SeverityBadge severity={finding.severity} />
          <CertaintyBadge certainty={finding.certainty} />
          <span className="sms-mono sms-analyst-note__rule-tag">
            {finding.source_rule_ids?.join(', ') || finding.issue_class_label || finding.issue_class}
          </span>
        </div>
        <h2 className="sms-analyst-note__title">{finding.title}</h2>
      </header>

      {/* 2. WHAT WAS OBSERVED */}
      <section className="sms-analyst-note__section" aria-label="What was observed">
        <span className="sms-label">What was observed</span>
        <p className="sms-prose sms-analyst-note__lead">
          {finding.conclusion || finding.explanation || 'Protocol activity was captured and evaluated under deterministic rules.'}
        </p>
      </section>

      {/* 3. WHY IT MATTERS */}
      {finding.explanation && finding.conclusion && (
        <section className="sms-analyst-note__section" aria-label="Why it matters">
          <span className="sms-label">Why it matters</span>
          <p className="sms-prose sms-analyst-note__body">
            {finding.explanation}
          </p>
        </section>
      )}

      {/* 4. WIRE FACTS (VISUALLY SPECIAL MACHINE FACT REGION) */}
      <section className="sms-analyst-note__section sms-analyst-note__wire-facts" aria-label="Wire facts">
        <div className="sms-analyst-note__section-head">
          <span className="sms-label">Wire evidence facts</span>
          <span className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-11)' }}>
            Physical wire proof
          </span>
        </div>

        {assessmentError ? (
          <p className="sms-prose" style={{ color: 'var(--ds-crimson-ink)' }}>
            Assessment failed to load: {assessmentError}
          </p>
        ) : refs.length === 0 ? (
          <p className="sms-prose sms-muted">The assessment lists no wire evidence fields for this finding.</p>
        ) : (
          <div className="sms-wire-facts-grid">
            {refs.map((ref, i) => (
              <div key={`${ref.field}-${i}`} className="sms-wire-fact-card">
                <div className="sms-wire-fact-card__header">
                  <span className="sms-wire-fact-card__key sms-mono">{fieldLabel(ref.field)}</span>
                  <EvidenceBadge state={ref.evidence_state} size="sm" />
                </div>
                <div className="sms-wire-fact-card__val sms-mono">
                  {ref.observed_value ?? <span className="sms-muted">NOT OBSERVED</span>}
                </div>
                {ref.basis && (
                  <p className="sms-wire-fact-card__basis">{ref.basis}</p>
                )}
                {ref.frames && ref.frames.length > 0 && (
                  <button
                    type="button"
                    className="sms-link sms-wire-fact-card__frame-link"
                    onClick={() => onOpenFrame(ref.frames[0], finding.stream_key ?? undefined)}
                  >
                    <Radio size={11} aria-hidden="true" />
                    <span>{framesLabel(ref.frames)}</span>
                  </button>
                )}
              </div>
            ))}

            {primaryFrame != null && (
              <div className="sms-wire-fact-card">
                <div className="sms-wire-fact-card__header">
                  <span className="sms-wire-fact-card__key sms-mono">WIRE_FRAME</span>
                  <span className="sms-badge sms-badge--muted">Anchor</span>
                </div>
                <div className="sms-wire-fact-card__val sms-mono">
                  Frame #{primaryFrame}
                </div>
                <button
                  type="button"
                  className="sms-link sms-wire-fact-card__frame-link"
                  onClick={() => onOpenFrame(primaryFrame, finding.stream_key ?? undefined)}
                >
                  <Radio size={11} aria-hidden="true" />
                  <span>Inspect Packet #{primaryFrame}</span>
                </button>
              </div>
            )}
          </div>
        )}
      </section>

      {/* 5. NORMATIVE STANDARD */}
      {finding.citations && finding.citations.length > 0 && (
        <section className="sms-analyst-note__section" aria-label="Normative standard">
          <span className="sms-label">Normative standard</span>
          <div className="sms-analyst-note__citations">
            {finding.citations.map((c, i) => (
              <div key={`${c.standard}-${c.section ?? ''}-${i}`} className="sms-citation-block">
                <div className="sms-citation-title">
                  <BookOpen size={13} aria-hidden="true" />
                  <span className="sms-mono">{[c.standard, c.section].filter(Boolean).join(' ')}</span>
                </div>
                {(c.text || c.reason) && (
                  <p className="sms-prose" style={{ fontSize: 'var(--ds-text-13)', marginTop: '4px' }}>
                    {c.text || c.reason}
                  </p>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* 6. RECOMMENDED ACTION */}
      {remediation?.recommended_action && (
        <section className="sms-analyst-note__section" aria-label="Recommended action">
          <span className="sms-label">Recommended action</span>
          <p className="sms-prose sms-analyst-note__action-text">{remediation.recommended_action}</p>
          {remediation.verification && (
            <p className="sms-prose sms-muted" style={{ fontSize: 'var(--ds-text-12)', marginTop: '6px' }}>
              <strong>Verification:</strong> {remediation.verification}
            </p>
          )}
        </section>
      )}

      {/* 7. FORENSIC LIMITATION */}
      {finding.limitations && finding.limitations.length > 0 && (
        <section className="sms-analyst-note__section" aria-label="Forensic limitations">
          <span className="sms-label">Forensic limitations</span>
          <ul className="sms-list sms-list--bulleted">
            {finding.limitations.map((l, idx) => (
              <li key={idx} style={{ fontSize: 'var(--ds-text-13)', color: 'var(--sms-text-secondary)' }}>{l}</li>
            ))}
          </ul>
        </section>
      )}

      {/* 8. PIVOT ACTION BAR */}
      <footer className="sms-analyst-note__actions">
        {primaryFrame != null && (
          <button
            type="button"
            className="sms-btn sms-btn--primary sms-btn--sm"
            onClick={() => onOpenFrame(primaryFrame, finding.stream_key ?? undefined)}
          >
            <Radio size={13} aria-hidden="true" />
            <span>Open in Protocol Journey</span>
          </button>
        )}

        {onTrace && (
          <button
            type="button"
            className="sms-btn sms-btn--secondary sms-btn--sm"
            onClick={() => onTrace(finding)}
          >
            <GitFork size={13} aria-hidden="true" />
            <span>Trace Provenance</span>
          </button>
        )}
      </footer>
    </div>
  );
};

