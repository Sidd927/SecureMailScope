import React from 'react';

const CERTAINTY: Record<string, string> = {
  CONFIRMED: 'confirmed',
  PROBABLE: 'probable',
  UNCERTAIN: 'uncertain',
  UNDETERMINED: 'undetermined',
};

const STATUS: Record<string, { token: string; label: string }> = {
  OBSERVED_ISSUE: { token: 'observed-issue', label: 'OBSERVED ISSUE' },
  COMPLIANT: { token: 'compliant', label: 'COMPLIANT' },
  INFORMATIONAL: { token: 'informational', label: 'INFORMATIONAL' },
  AMBIGUOUS: { token: 'ambiguous', label: 'AMBIGUOUS' },
  INSUFFICIENT_EVIDENCE: { token: 'insufficient-evidence', label: 'INSUFFICIENT EVIDENCE' },
  NOT_OBSERVABLE: { token: 'not-observable', label: 'NOT OBSERVABLE' },
};

const Unreported: React.FC<{ what: string }> = ({ what }) => (
  <span className="sms-badge sms-badge--muted" title={`${what} not reported`}>—</span>
);

/** Certainty mirrors certainty_from_refs() in posture/model.py; never shown unless the backend returned it. */
export const CertaintyBadge: React.FC<{ certainty: string | null | undefined }> = ({ certainty }) => {
  const token = certainty ? CERTAINTY[certainty] : undefined;
  if (!token) return <Unreported what="Certainty" />;
  return (
    <span
      className="sms-badge"
      title={`Certainty: ${certainty}`}
      style={{
        color: `var(--ds-certainty-${token}-text)`,
        background: `var(--ds-certainty-${token}-bg)`,
        borderColor: `var(--ds-certainty-${token}-border)`,
        borderStyle: certainty === 'PROBABLE' ? 'dashed' : certainty === 'UNCERTAIN' || certainty === 'UNDETERMINED' ? 'dotted' : 'solid',
      }}
    >
      {certainty}
    </span>
  );
};

export const FindingStatusBadge: React.FC<{ status: string | null | undefined }> = ({ status }) => {
  const meta = status ? STATUS[status] : undefined;
  if (!meta) return <Unreported what="Status" />;
  return (
    <span
      className="sms-badge"
      title={`Status: ${meta.label}`}
      style={{
        color: `var(--ds-finding-${meta.token}-text)`,
        background: `var(--ds-finding-${meta.token}-bg)`,
        borderColor: `var(--ds-finding-${meta.token}-border)`,
      }}
    >
      {meta.label}
    </span>
  );
};
