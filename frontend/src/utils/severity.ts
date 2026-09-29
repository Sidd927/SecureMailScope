export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export const SEVERITY_ORDER: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export interface SeverityTokens {
  level: SeverityLevel;
  text: string;
  bg: string;
  border: string;
  rule: string;
}

export function normalizeSeverity(severity: string | null | undefined): SeverityLevel | null {
  const upper = (severity || '').toUpperCase();
  return (SEVERITY_ORDER as string[]).includes(upper) ? (upper as SeverityLevel) : null;
}

/** Token set for a backend severity, or null when the backend gave none (never guessed). */
export function getSeverityTokens(severity: string | null | undefined): SeverityTokens | null {
  const level = normalizeSeverity(severity);
  if (!level) return null;
  const key = level.toLowerCase();
  return {
    level,
    text: `var(--ds-sev-${key}-text)`,
    bg: `var(--ds-sev-${key}-bg)`,
    border: `var(--ds-sev-${key}-border)`,
    rule: `var(--ds-sev-${key}-rule)`,
  };
}

export function severityRank(severity: string | null | undefined): number {
  const level = normalizeSeverity(severity);
  return level ? SEVERITY_ORDER.indexOf(level) : SEVERITY_ORDER.length;
}
