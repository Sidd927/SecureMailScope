import type { EvidenceState } from '../api/types';

export interface EvidenceStateMeta {
  state: EvidenceState;
  token: string;
  label: string;
  borderStyle: 'solid' | 'dashed' | 'dotted';
}

// DESIGN.md §1.8: evidence states differ by border style and ink, never by alarm hue.
export const EVIDENCE_STATES: EvidenceStateMeta[] = [
  { state: 'OBSERVED', token: 'observed', label: 'Observed', borderStyle: 'solid' },
  { state: 'INFERRED', token: 'inferred', label: 'Inferred', borderStyle: 'dashed' },
  { state: 'UNKNOWN', token: 'unknown', label: 'Unknown', borderStyle: 'dotted' },
  { state: 'AMBIGUOUS', token: 'ambiguous', label: 'Ambiguous', borderStyle: 'dotted' },
  { state: 'INCOMPLETE', token: 'incomplete', label: 'Incomplete', borderStyle: 'dashed' },
  { state: 'NOT_OBSERVABLE', token: 'not-observable', label: 'Not observable', borderStyle: 'solid' },
];

export function evidenceStateMeta(state: string | null | undefined): EvidenceStateMeta | null {
  return EVIDENCE_STATES.find((s) => s.state === state) ?? null;
}

export function evidenceTokens(state: string | null | undefined) {
  const meta = evidenceStateMeta(state);
  if (!meta) return null;
  return {
    text: `var(--ds-ev-${meta.token}-text)`,
    bg: `var(--ds-ev-${meta.token}-bg)`,
    border: `var(--ds-ev-${meta.token}-border)`,
  };
}

export interface EvidenceFieldGroup {
  id: string;
  title: string;
  fields: Array<{ key: string; label: string }>;
}

// Grouping is presentation only; every row's state, value, basis and frames come from the backend EvidenceField.
export const EVIDENCE_FIELD_GROUPS: EvidenceFieldGroup[] = [
  {
    id: 'upgrade',
    title: 'Transport & upgrade',
    fields: [
      { key: 'starttls_advertised', label: 'STARTTLS advertised' },
      { key: 'starttls_requested', label: 'STARTTLS requested' },
      { key: 'starttls_accepted', label: 'STARTTLS accepted' },
      { key: 'tls_transition', label: 'TLS transition' },
      { key: 'plaintext_continuation', label: 'Plaintext continuation' },
    ],
  },
  {
    id: 'parameters',
    title: 'Negotiated parameters',
    fields: [
      { key: 'tls_negotiated_version', label: 'TLS version' },
      { key: 'tls_cipher_suite_name', label: 'Cipher suite' },
      { key: 'tls_cipher_suite', label: 'Cipher suite ID' },
      { key: 'tls_key_exchange', label: 'Key exchange' },
      { key: 'tls_named_group', label: 'Named group' },
      { key: 'tls_forward_secrecy', label: 'Forward secrecy' },
    ],
  },
  {
    id: 'certificate',
    title: 'Certificate',
    fields: [{ key: 'tls_certificate_chain', label: 'Certificates in chain' }],
  },
  {
    id: 'authentication',
    title: 'Authentication',
    fields: [{ key: 'auth_activity', label: 'Authentication activity' }],
  },
];

export function formatEvidenceValue(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (Array.isArray(value)) return value.join(', ');
  return String(value);
}

export function framesLabel(frames: number[] | null | undefined): string | null {
  if (!frames || frames.length === 0) return null;
  return frames.length === 1 ? `Frame #${frames[0]}` : `Frames ${frames.join(', ')}`;
}
