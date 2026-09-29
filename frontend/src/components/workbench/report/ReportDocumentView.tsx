import React from 'react';
import type { ReportDocument, RunResponse } from '../../../api/types';
import { severityRank } from '../../../utils/severity';
import { SeverityBadge } from '../../common/SeverityBadge';

export const ReportDocumentView: React.FC<{ doc: ReportDocument; run: RunResponse | null }> = ({ doc, run }) => {
  const groups = [...(doc.issue_groups ?? [])].filter((g) => g.penalising).sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  const primary = groups[0];
  const action = doc.remediation_summary?.find((item) => item.recommended_action);
  const cite = primary?.citations?.[0];
  const citeText = cite?.text?.trim() || '';
  const citeRef = [cite?.standard, cite?.section].filter((part) => part && part !== 'UNMAPPED').join(' ');
  const insights = [
    primary ? { label: 'Primary issue', value: primary.title } : null,
    citeText
      ? { label: 'Why it matters', value: citeText }
      : (doc.score?.basis ? { label: 'Score basis', value: doc.score.basis } : null),
    primary?.recurrence != null ? { label: 'Sessions affected', value: `${primary.recurrence}` } : null,
    citeRef ? { label: 'Critical evidence', value: citeRef } : null,
    action?.recommended_action ? { label: 'Recorded action', value: action.recommended_action } : null,
  ].filter((item): item is { label: string; value: string } => Boolean(item?.value));

  return (
    <article className="sms-doc sms-report-brief" aria-label="Report preview">
      <section className="sms-report-insights" aria-label="Key insights">
        <h3>Key insights</h3>
        {insights.length === 0 ? (
          <p className="sms-muted">No penalising findings were recorded for this capture.</p>
        ) : (
          <dl>
            {insights.map((item) => (
              <div key={item.label}>
                <dt>{item.label}</dt>
                <dd>{item.value}</dd>
              </div>
            ))}
          </dl>
        )}
      </section>

      {groups.length > 0 && (
        <section aria-label="Critical findings">
          <h3>Findings</h3>
          <ul className="sms-report-findings">
            {groups.map((group) => (
              <li key={group.issue_class}>
                <SeverityBadge severity={group.severity} />
                <div>
                  <strong>{group.title}</strong>
                  {group.recurrence != null && (
                    <span className="sms-muted"> {group.recurrence} session{group.recurrence === 1 ? '' : 's'}</span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      <details className="sms-report-details">
        <summary>Detailed report</summary>
        <dl className="sms-doc__meta">
          {run?.source_filename && (<><dt>Capture</dt><dd>{run.source_filename}</dd></>)}
          <dt>SHA-256</dt><dd>{doc.capture_id}</dd>
          <dt>Assessment</dt><dd>{doc.assessment_id}</dd>
          {doc.generated_at && (<><dt>Generated</dt><dd>{doc.generated_at}</dd></>)}
        </dl>
        {(doc.remediation_summary?.length ?? 0) > 0 && (
          <div>
            <h3>Recorded actions</h3>
            {doc.remediation_summary!.map((item, index) => (
              <p key={index}>
                {item.observed && <strong>{item.observed}. </strong>}
                {item.recommended_action}
              </p>
            ))}
          </div>
        )}
        {(doc.limitations?.length ?? 0) > 0 && (
          <div>
            <h3>Limits of this capture</h3>
            <ul className="sms-list sms-list--bulleted">{doc.limitations!.map((item) => <li key={item}>{item}</li>)}</ul>
          </div>
        )}
        {doc.provenance?.rule_ids && doc.provenance.rule_ids.length > 0 && (
          <p className="sms-mono sms-muted">Rules: {doc.provenance.rule_ids.join(', ')}</p>
        )}
      </details>
    </article>
  );
};
