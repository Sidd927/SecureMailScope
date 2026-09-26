import React from 'react';
import type { AssessmentResponse, FindingRow, RunResponse, ScoreComponentRow, SessionEvidence } from '../../../api/types';
import { evidenceRefsForFinding, fieldLabel, sourcesForFinding } from '../../../utils/findingEvidence';
import { framesLabel } from '../../../utils/evidence';
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

const Step: React.FC<{ label: string; keyStep?: boolean; children: React.ReactNode }> = ({ label, keyStep, children }) => (
  <li className={`sms-chain__step${keyStep ? ' sms-chain__step--key' : ''}`}>
    <span className="sms-label">{label}</span>
    <div style={{ marginTop: 'var(--ds-space-4)' }}>{children}</div>
  </li>
);

export const EvidenceChain: React.FC<Props> = ({ finding, run, session, assessment, component, formulaId, onOpenFrame }) => {
  const refs = evidenceRefsForFinding(assessment, finding);
  const sources = sourcesForFinding(assessment, finding);

  return (
    <ol className="sms-chain" aria-label={`Provenance for ${finding.title}`}>
      <Step label="Capture">
        <p className="sms-mono" style={{ fontSize: 'var(--ds-text-13)', color: 'var(--ds-ink-primary)' }}>{run.source_filename}</p>
        <ForensicHash value={run.capture_id} length={24} label="SHA-256" />
      </Step>

      {session && (
        <Step label="TCP stream">
          <p className="sms-mono" style={{ fontSize: 'var(--ds-text-13)', color: 'var(--ds-ink-primary)' }}>
            {sessionLabel(session)}
          </p>
          {finding.affected_sessions != null && finding.affected_sessions > 1 && (
            <p className="sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>Representative stream; the finding covers {finding.affected_sessions} sessions.</p>
          )}
        </Step>
      )}

      <Step label="Evidence cited" keyStep>
        {refs.length === 0 ? (
          <p className="sms-prose">The assessment lists no evidence fields for this finding.</p>
        ) : (
          <div className="sms-stack sms-stack--tight">
            {refs.map((r, i) => (
              <div key={`${r.field}-${i}`} style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', gap: 'var(--ds-space-8)', alignItems: 'start' }}>
                <div>
                  <p style={{ fontSize: 'var(--ds-text-13)', color: 'var(--ds-ink-primary)' }}>
                    {fieldLabel(r.field)} <span className="sms-mono" style={{ color: 'var(--ds-ink-secondary)' }}>= {r.observed_value ?? 'no value'}</span>
                  </p>
                  {r.basis && <p className="sms-prose" style={{ fontSize: 'var(--ds-text-12)' }}>{r.basis}</p>}
                  <p className="sms-mono sms-muted" style={{ fontSize: 'var(--ds-text-12)' }}>
                    provenance: {r.provenance ?? 'not reported'}
                    {framesLabel(r.frames) && (
                      <>
                        {' · '}
                        <button type="button" className="sms-link" onClick={() => onOpenFrame(r.frames[0], finding.stream_key ?? undefined)}>{framesLabel(r.frames)}</button>
                      </>
                    )}
                  </p>
                </div>
                <EvidenceBadge state={r.evidence_state} size="sm" />
              </div>
            ))}
          </div>
        )}
      </Step>

      <Step label="Rules">
        {sources.length === 0 ? (
          <p className="sms-mono" style={{ fontSize: 'var(--ds-text-12)' }}>{finding.source_rule_ids?.join(', ') || '—'}</p>
        ) : (
          <ul className="sms-list">
            {sources.map((s, i) => (
              <li key={`${s.rule_id}-${i}`} className="sms-mono" style={{ fontSize: 'var(--ds-text-12)', color: 'var(--ds-ink-secondary)' }}>
                <span style={{ color: 'var(--ds-ink-primary)' }}>{s.rule_id}</span>
                {s.lane && <span className="sms-muted"> · {s.lane.toLowerCase().replace(/_/g, ' ')}</span>}
                {s.relation && <span className="sms-muted"> · {s.relation}</span>}
              </li>
            ))}
          </ul>
        )}
      </Step>

      <Step label="Finding" keyStep>
        <div style={{ display: 'flex', gap: 'var(--ds-space-8)', flexWrap: 'wrap', alignItems: 'center' }}>
          <SeverityBadge severity={finding.severity} />
          <FindingStatusBadge status={finding.status} />
          <CertaintyBadge certainty={finding.certainty} />
        </div>
        <p style={{ marginTop: 'var(--ds-space-8)', fontSize: 'var(--ds-text-14)', fontWeight: 500, color: 'var(--ds-ink-primary)' }}>{finding.title}</p>
        {finding.certainty && refs.length > 0 && (
          <p className="sms-prose" style={{ marginTop: 'var(--ds-space-4)' }}>
            Certainty is reported as <span className="sms-mono">{finding.certainty}</span>. The engine derives certainty from the states of the evidence it cites; here:{' '}
            {refs.map((r) => `${fieldLabel(r.field)} (${r.evidence_state})`).join(', ')}.
          </p>
        )}
      </Step>

      {finding.citations?.length > 0 && (
        <Step label="Standards">
          <ul className="sms-list">
            {finding.citations.map((c, i) => (
              <li key={`${c.standard}-${c.section ?? ''}-${i}`}>
                <p className="sms-mono" style={{ fontSize: 'var(--ds-text-12)', color: 'var(--ds-ink-primary)' }}>{[c.standard, c.section].filter(Boolean).join(' ')}</p>
                {c.reason && <p className="sms-prose" style={{ fontSize: 'var(--ds-text-12)' }}>{c.reason}</p>}
              </li>
            ))}
          </ul>
        </Step>
      )}

      {component?.penalty != null && (
        <Step label="Posture impact">
          <p className="sms-mono" style={{ fontSize: 'var(--ds-text-14)', color: 'var(--ds-crimson-ink)' }}>−{component.penalty.toFixed(2)} points{formulaId ? ` under ${formulaId}` : ''}</p>
          {component.explanation && <p className="sms-prose" style={{ fontSize: 'var(--ds-text-12)' }}>{component.explanation}</p>}
        </Step>
      )}
    </ol>
  );
};
