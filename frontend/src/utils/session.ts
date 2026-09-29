import type { SessionEvidence } from '../api/types';

type Endpoint = SessionEvidence['client'];

/** "10.0.0.5:587", "10.0.0.5" when the port is missing, or null when the engine recorded no address. */
export function endpointLabel(e: Endpoint): string | null {
  if (!e.ip) return null;
  return e.port != null ? `${e.ip}:${e.port}` : e.ip;
}

/** "client → server", with "not recorded" standing in for whichever side the engine could not attribute. */
export function sessionRoute(s: Pick<SessionEvidence, 'client' | 'server'>): string {
  const c = endpointLabel(s.client);
  const v = endpointLabel(s.server);
  if (!c && !v) return 'endpoints not recorded';
  return `${c ?? 'not recorded'} → ${v ?? 'not recorded'}`;
}

/** "#3 SMTP 10.0.0.5:51000 → 10.0.0.9:587"; protocol omitted when unknown. */
export function sessionLabel(s: Pick<SessionEvidence, 'tcp_stream_id' | 'protocol' | 'client' | 'server'>): string {
  return [`#${s.tcp_stream_id}`, s.protocol, sessionRoute(s)].filter(Boolean).join(' ');
}
