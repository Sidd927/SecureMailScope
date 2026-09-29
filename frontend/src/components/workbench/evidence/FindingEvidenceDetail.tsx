import React from 'react';
import { Radio, GitFork, BookOpen, MousePointer2 } from 'lucide-react';
import type { AssessmentResponse, FindingRow } from '../../../api/types';
import { evidenceRefsForFinding, fieldLabel } from '../../../utils/findingEvidence';
import { framesLabel } from '../../../utils/evidence';
import { EvidenceBadge } from '../../common/EvidenceBadge';
import { SeverityBadge } from '../../common/SeverityBadge';
import { CertaintyBadge } from '../../common/VocabularyBadges';
import { EmptyState } from '../../common/StateViews';
import { presentBasis } from './plainEvidence';

const BasisLine: React.FC<{ text: string }> = ({ text }) => {
  const [open, setOpen] = React.useState(false);
  const { show, full } = presentBasis(text, 140);
  if (!full) return <span className="sms-finding-evidence__basis">{show}</span>;
  return (
    <span className="sms-finding-evidence__basis">
      {open ? full : show}{' '}
      <button type="button" className="sms-link" onClick={() => setOpen((v) => !v)}>
        {open ? 'Less' : 'More'}
      </button>
    </span>
  );
};

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
  if (!finding) return <EmptyState icon={<MousePointer2 size={28} aria-hidden="true" />} title="Select a finding." />;

  const refs = evidenceRefsForFinding(assessment, finding);
  const remediation = finding.remediation;
  const primaryFrame = finding.frames && finding.frames.length > 0 ? finding.frames[0] : null;
  const happened = finding.conclusion || finding.explanation || 'This capture was checked against the mail-security rules.';
  const why = finding.explanation && finding.explanation.trim() !== finding.conclusion?.trim() ? finding.explanation : null;
  const whyView = why ? presentBasis(why, 180) : null;
  const rule = finding.source_rule_ids?.join(', ') || finding.issue_class_label || finding.issue_class;
  const hasTechnical = Boolean(
    rule ||
    (finding.citations && finding.citations.length > 0) ||
    remediation?.recommended_action ||
    (finding.limitations && finding.limitations.length > 0) ||
    Boolean(whyView?.full),
  );

  return (
    <div className="sms-focused-evidence-view sms-finding-read" aria-label={`Forensic note for ${finding.title}`}>
      <header className="sms-finding-read__hero">
        <div className="sms-analyst-note__eyebrow">
          <SeverityBadge severity={finding.severity} />
          <CertaintyBadge certainty={finding.certainty} />
        </div>
        <h2 className="sms-finding-read__title">{finding.title}</h2>
      </header>

      <section className="sms-finding-read__block" aria-label="What happened">
        <span className="sms-finding-read__kicker">What happened</span>
        <p className="sms-finding-read__lead">{happened}</p>
      </section>

      {why && (
        <section className="sms-finding-read__block" aria-label="Why it matters">
          <span className="sms-finding-read__kicker">Why it matters</span>
          <p className="sms-finding-read__why">{whyView?.show}</p>
        </section>
      )}

      <section className="sms-finding-read__block" aria-label="Evidence">
        <span className="sms-finding-read__kicker">Evidence</span>
        {assessmentError ? (
          <p className="sms-prose" style={{ color: 'var(--ds-crimson-ink)' }}>
            Assessment failed to load: {assessmentError}
          </p>
        ) : refs.length === 0 ? (
          <p className="sms-finding-read__why">No cited fields for this finding.</p>
        ) : (
          <ul className="sms-finding-evidence">
            {refs.map((ref, i) => (
              <li key={`${ref.field}-${i}`} className="sms-finding-evidence__row">
                <span className="sms-finding-evidence__label">{fieldLabel(ref.field)}</span>
                <span className="sms-mono sms-finding-evidence__value">
                  {ref.observed_value ?? '—'}
                </span>
                <EvidenceBadge state={ref.evidence_state} size="sm" variant="pill" />
                {ref.frames && ref.frames.length > 0 ? (
                  <button
                    type="button"
                    className="sms-link sms-finding-evidence__frame"
                    onClick={() => onOpenFrame(ref.frames[0], finding.stream_key ?? undefined)}
                  >
                    <Radio size={11} aria-hidden="true" />
                    <span>{framesLabel(ref.frames)}</span>
                  </button>
                ) : (
                  <span className="sms-finding-evidence__frame sms-muted">—</span>
                )}
                {ref.basis && <BasisLine text={ref.basis} />}
              </li>
            ))}
          </ul>
        )}
      </section>

      {hasTechnical && (
        <details className="sms-finding-tech">
          <summary>Technical details</summary>
          <div className="sms-finding-tech__body">
            {whyView?.full && <p>{whyView.full}</p>}
            {rule && (
              <p className="sms-finding-tech__line">
                <span>Rule</span>
                <span className="sms-mono">{rule}</span>
              </p>
            )}
            {finding.citations && finding.citations.length > 0 && (
              <div>
                <span className="sms-finding-read__kicker">Standards</span>
                {finding.citations.map((c, i) => (
                  <div key={`${c.standard}-${c.section ?? ''}-${i}`} className="sms-finding-tech__cite">
                    <span className="sms-mono">
                      <BookOpen size={12} aria-hidden="true" />
                      {[c.standard, c.section].filter(Boolean).join(' ')}
                    </span>
                    {(c.text || c.reason) && <p>{c.text || c.reason}</p>}
                  </div>
                ))}
              </div>
            )}
            {remediation?.recommended_action && (
              <div>
                <span className="sms-finding-read__kicker">What to do</span>
                <p>{remediation.recommended_action}</p>
                {remediation.verification && <p className="sms-muted">{remediation.verification}</p>}
              </div>
            )}
            {finding.limitations && finding.limitations.length > 0 && (
              <div>
                <span className="sms-finding-read__kicker">Limits of this capture</span>
                <ul>
                  {finding.limitations.map((l, idx) => <li key={idx}>{l}</li>)}
                </ul>
              </div>
            )}
          </div>
        </details>
      )}

      <footer className="sms-analyst-note__actions">
        {primaryFrame != null && (
          <button
            type="button"
            className="sms-btn sms-btn--primary sms-btn--sm"
            onClick={() => onOpenFrame(primaryFrame, finding.stream_key ?? undefined)}
          >
            <Radio size={13} aria-hidden="true" />
            <span>Open frame #{primaryFrame}</span>
          </button>
        )}
        {onTrace && (
          <button
            type="button"
            className="sms-btn sms-btn--secondary sms-btn--sm"
            onClick={() => onTrace(finding)}
          >
            <GitFork size={13} aria-hidden="true" />
            <span>Trace provenance</span>
          </button>
        )}
      </footer>
    </div>
  );
};
