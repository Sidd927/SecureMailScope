import type { AssessmentResponse, FindingRow } from '../api/types';

export interface EvidenceRef {
  field: string;
  evidence_state: string;
  basis: string | null;
  frames: number[];
  observed_value: string | null;
  provenance: string | null;
}

export interface FindingSource {
  rule_id: string | null;
  relation: string | null;
  lane: string | null;
  detail: string | null;
  standards: string[];
  evidence_refs: EvidenceRef[];
  frames?: number[];
  deviation?: string | null;
  stream_key?: string | null;
}

interface PrioritisedEntry {
  rank: number;
  representative_finding?: { title?: string; sources?: FindingSource[] };
}

/**
 * Sources and evidence refs the rule engine attached to a finding, read from the canonical
 * assessment (prioritised[].representative_finding.sources). Matched by rank, then title.
 */
export function sourcesForFinding(assessment: AssessmentResponse | null, finding: FindingRow | null): FindingSource[] {
  if (!assessment || !finding) return [];
  const raw = (assessment as unknown as { assessment?: { prioritised?: PrioritisedEntry[] } })?.assessment ?? assessment;
  const prioritised = ((raw as unknown as { prioritised?: PrioritisedEntry[] })?.prioritised) ?? [];
  const entry =
    prioritised.find((p) => p.rank === finding.rank && p.representative_finding?.title === finding.title) ??
    prioritised.find((p) => p.representative_finding?.title === finding.title);
  return entry?.representative_finding?.sources ?? [];
}

export function evidenceRefsForFinding(assessment: AssessmentResponse | null, finding: FindingRow | null): EvidenceRef[] {
  const seen = new Set<string>();
  const refs: EvidenceRef[] = [];
  for (const src of sourcesForFinding(assessment, finding)) {
    for (const ref of src.evidence_refs ?? []) {
      const key = `${ref.field}|${ref.evidence_state}|${(ref.frames ?? []).join(',')}`;
      if (seen.has(key)) continue;
      seen.add(key);
      refs.push(ref);
    }
  }
  return refs;
}

export function fieldLabel(field: string): string {
  return field.replace(/_/g, ' ').replace(/^tls /, 'TLS ').replace(/starttls/, 'STARTTLS');
}
