/**
 * SecureMailScope — Technical Presentation Formatters
 * Enforces honest display of absent, unobserved, and unknown data.
 */

export function formatEndpoint(endpoint?: { ip: string | null; port: number | null } | null): string {
  if (!endpoint) return '—';
  const { ip, port } = endpoint;
  if (!ip && !port) return 'Unobserved';
  if (ip && port) return `${ip}:${port}`;
  if (ip) return `${ip}:(unobserved)`;
  return `(unobserved):${port}`;
}

export function formatProtocol(protocol?: string | null, implicitTls?: boolean): string {
  if (!protocol) return 'TCP';
  const base = protocol.toUpperCase();
  if (implicitTls) {
    if (base === 'SMTP') return 'SMTPS';
    if (base === 'IMAP') return 'IMAPS';
    if (base === 'POP3') return 'POP3S';
    return `${base}-S`;
  }
  return base;
}

export function formatDurationMs(startEpoch: number | null, endEpoch: number | null): string | null {
  if (startEpoch === null || endEpoch === null) return null;
  const ms = (endEpoch - startEpoch) * 1000;
  if (ms < 1) return `${(ms * 1000).toFixed(0)} µs`;
  if (ms < 1000) return `${ms.toFixed(2)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function formatTimestamp(isoString?: string | null): string {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return isoString;
  }
}
