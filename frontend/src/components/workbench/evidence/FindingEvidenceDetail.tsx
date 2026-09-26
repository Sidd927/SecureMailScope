import React from 'react';
import { Radio } from 'lucide-react';
import type { AssessmentResponse, FindingRow } from '../../../api/types';
import { evidenceRefsForFinding, fieldLabel } from '../../../utils/findingEvidence';
import { framesLabel } from '../../../utils/evidence';
import { EvidenceBadge } from '../../common/EvidenceBadge';
import { SeverityBadge } from '../../common/SeverityBadge';
import { EmptyState } from '../../common/StateViews';

interface Props {
  finding: FindingRow | null;
  assessment: AssessmentResponse | null;
  assessmentError?: string;
  onOpenFrame: (frame: number, streamKey?: string) => void;
}

export const FindingEvidenceDetail: React.FC<Props> = ({ finding, assessment, assessmentError, onOpenFrame }) => {
  if (!finding) return <EmptyState title="Select a finding to view evidence" />;
  const refs = evidenceRefsForFinding(assessment, finding);
  const remediation = finding.remediation;

  return (
    <div className="sms-stack">
      <div className="sms-stack sms-stack--tight">
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--ds-space-8)', flexWrap: 'wrap' }}>
          <SeverityBadge severity={finding.severity} />
          <span className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>{finding.issue_class_label || finding.issue_class}</span>
        </div>
        <h3 style={{ fontSize: 'var(--ds-text-16)', fontWeight: 600, color: 'var(--ds-ink-primary)' }}>{finding.title}</h3>
        {finding.explanation && <p className="sms-prose">{finding.explanation}</p>}
      </div>

      <section className="sms-stack sms-stack--tight" aria-label="Supporting evidence">
        <span className="sms-label">Supporting evidence</span>
        {assessmentError ? (
          <p className="sms-prose" style={{ color: 'var(--ds-crimson-ink)' }}>Assessment failed to load: {assessmentError}</p>
        ) : refs.length === 0 ? (
          <p className="sms-prose">The assessment lists no evidence fields for this finding.</p>
        ) : (
          <div className="sms-kv">
            {refs.map((ref, i) => {
              const proof = framesLabel(ref.frames);
              return (
                <React.Fragment key={`${ref.field}-${i}`}>
                  {i > 0 && <span className="sms-kv__divider" />}
                  <span className="sms-kv__key">{fieldLabel(ref.field)}</span>
                  <span className="sms-kv__value">
                    {ref.observed_value ?? <span className="sms-muted">no value</span>}
                    {ref.basis && <span className="sms-muted" style={{ display: 'block', fontFamily: 'var(--ds-font-sans)' }}>{ref.basis}</span>}
                    {proof && (
                      <button type="button" className="sms-link" style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--ds-space-4)', marginTop: 'var(--ds-space-4)' }} onClick={() => onOpenFrame(ref.frames[0], finding.stream_key ?? undefined)}>
                        <Radio size={11} aria-hidden="true" />{proof}
                      </button>
                    )}
                  </span>
                  <EvidenceBadge state={ref.evidence_state} size="sm" />
                </React.Fragment>
              );
            })}
          </div>
        )}
      </section>

      {finding.citations?.length > 0 && (
        <section className="sms-stack sms-stack--tight" aria-label="Standards">
          <span className="sms-label">Standards</span>
          {finding.citations.map((c, i) => (
            <div key={`${c.standard}-${c.section ?? ""}-${i}`}>
              <p className="sms-mono" style={{ fontSize: 'var(--ds-text-12)', color: 'var(--ds-ink-primary)' }}>{[c.standard, c.section].filter(Boolean).join(' ')}</p>
              {(c.text || c.reason) && <p className="sms-prose">{c.text || c.reason}</p>}
            </div>
          ))}
        </section>
      )}

      {remediation?.recommended_action && (
        <section className="sms-stack sms-stack--tight" aria-label="Recommended action">
          <span className="sms-label">Recommended action</span>
          <p className="sms-prose">{remediation.recommended_action}</p>
          {remediation.verification && <p className="sms-prose sms-muted">Verify: {remediation.verification}</p>}
        </section>
      )}

      {finding.limitations?.length > 0 && (
        <section className="sms-stack sms-stack--tight" aria-label="Limitations">
          <span className="sms-label">Limitations</span>
          <ul className="sms-list sms-list--bulleted">{finding.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
        </section>
      )}
    </div>
  );
};
