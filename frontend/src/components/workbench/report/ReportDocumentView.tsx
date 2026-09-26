import React from 'react';
import type { ReportDocument, RunResponse } from '../../../api/types';
import { severityRank } from '../../../utils/severity';
import { PosturePill } from '../../common/PosturePill';
import { SeverityBadge } from '../../common/SeverityBadge';
import { CertaintyBadge } from '../../common/VocabularyBadges';

export const ReportDocumentView: React.FC<{ doc: ReportDocument; run: RunResponse | null }> = ({ doc, run }) => {
  const groups = [...(doc.issue_groups ?? [])].filter((g) => g.penalising).sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  const abstain = doc.risk_summary?.abstentions;

  return (
    <article className="sms-doc" aria-label="Report preview">
      <header className="sms-stack">
        <p className="sms-label">SecureMailScope forensic report</p>
        <h2>Cryptographic security posture assessment</h2>
        <dl className="sms-doc__meta">
          {run?.source_filename && (<><dt>Capture</dt><dd>{run.source_filename}</dd></>)}
          <dt>SHA-256</dt><dd>{doc.capture_id}</dd>
          <dt>Assessment</dt><dd>{doc.assessment_id}</dd>
          <dt>Generated</dt><dd>{doc.generated_at}</dd>
          {doc.versions?.engine && (<><dt>Engine</dt><dd>{doc.versions.engine} (schema {doc.versions.schema})</dd></>)}
          <dt>ML lane</dt><dd>{doc.ai_enabled ? 'enabled (ranking only)' : 'disabled'}</dd>
        </dl>
      </header>

      <section>
        <h3>Determination</h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--ds-space-12)', flexWrap: 'wrap' }}>
          <PosturePill band={doc.score?.band ?? doc.overall_posture} size="lg" />
          {doc.score?.value != null && <span className="sms-mono" style={{ fontSize: 'var(--ds-text-20)', color: 'var(--ds-ink-primary)' }}>{doc.score.value.toFixed(2)} / 100</span>}
        </div>
        {doc.score?.basis && <p>{doc.score.basis}.</p>}
      </section>

      {groups.length > 0 && (
        <section>
          <h3>Findings that lowered the score</h3>
          {groups.map((g) => (
            <div key={g.issue_class} className="sms-stack sms-stack--tight" style={{ paddingTop: 'var(--ds-space-8)' }}>
              <div style={{ display: 'flex', gap: 'var(--ds-space-8)', alignItems: 'center', flexWrap: 'wrap' }}>
                <SeverityBadge severity={g.severity} />
                <h4>{g.title}</h4>
                {g.certainty && <CertaintyBadge certainty={g.certainty} />}
                {g.recurrence != null && <span className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>{g.recurrence} session{g.recurrence === 1 ? '' : 's'}</span>}
              </div>
              {g.citations?.length > 0 && (
                <p className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>{g.citations.map((c) => c.text || c.standard).join(' · ')}</p>
              )}
            </div>
          ))}
        </section>
      )}

      {(doc.remediation_summary?.length ?? 0) > 0 && (
        <section>
          <h3>Remediation</h3>
          {doc.remediation_summary!.map((r, i) => (
            <div key={i} className="sms-stack sms-stack--tight" style={{ paddingTop: 'var(--ds-space-8)' }}>
              <h4>{r.observed}</h4>
              {r.why_it_matters && <p>{r.why_it_matters}</p>}
              {r.recommended_action && <p><span style={{ color: 'var(--ds-ink-primary)' }}>Action:</span> {r.recommended_action}</p>}
              {r.verification && <p><span style={{ color: 'var(--ds-ink-primary)' }}>Verify:</span> {r.verification}</p>}
            </div>
          ))}
        </section>
      )}

      {abstain && abstain.total > 0 && (
        <section>
          <h3>What the engine declined to conclude</h3>
          <p>
            {abstain.total} abstention{abstain.total === 1 ? '' : 's'}
            {abstain.by_reason && ` (${Object.entries(abstain.by_reason).map(([k, v]) => `${k.replace(/_/g, ' ').toLowerCase()} ${v}`).join(', ')})`}.
          </p>
          {/* The engine's note is about behavioural deviations in general, so it is quoted on its own line, not attached to the abstention count. */}
          {doc.risk_summary?.note && <p className="sms-muted" style={{ fontSize: 'var(--ds-text-13)' }}>Engine note: {doc.risk_summary.note}.</p>}
        </section>
      )}

      {(doc.limitations?.length ?? 0) > 0 && (
        <section>
          <h3>Limitations</h3>
          <ul className="sms-list sms-list--bulleted">{doc.limitations!.map((l) => <li key={l} style={{ fontSize: 'var(--ds-text-14)' }}>{l}</li>)}</ul>
        </section>
      )}

      {doc.provenance?.rule_ids && (
        <section>
          <h3>Provenance</h3>
          <p className="sms-mono" style={{ fontSize: 'var(--ds-text-12)' }}>{doc.provenance.rule_ids.join(', ')}</p>
          {doc.provenance.note && <p>{doc.provenance.note}</p>}
        </section>
      )}
    </article>
  );
};
