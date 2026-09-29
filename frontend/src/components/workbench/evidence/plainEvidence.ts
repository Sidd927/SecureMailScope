/**
 * Display-only shortening. The full engine string is returned as `full` when the
 * line on screen is not the original, so the technical wording stays one click away.
 */
const GLOSS: Record<string, string> = {
  'Certificate message observed in cleartext in this handshake': 'Certificate was visible during the handshake.',
  'not applicable: implicit TLS carries no cleartext STARTTLS dialogue': 'STARTTLS does not apply. The session started in TLS.',
  'implicit TLS but completion unproven (SERVER_HELLO_OBSERVED)': 'TLS started. A completed handshake was not proven.',
  'session is encrypted from the first record': 'Encrypted from the first record.',
  'ServerHello handshake version (no supported_versions extension)': 'TLS version comes from the ServerHello.',
  'IANA standard name for suite 0xc030': 'Name of cipher suite 0xc030.',
  'cipher suite selected in ServerHello': 'Cipher suite chosen in the ServerHello.',
  'no key_share group observed in the ServerHello': 'No named group was seen in the ServerHello.',
  'authentication occurs inside TLS and is not passively observable': 'Login details stay inside TLS and cannot be read here.',
};

function firstSentence(text: string, limit: number): { lead: string; clipped: boolean } {
  const match = text.match(/^[\s\S]*?[.!?](?:\s|$)/);
  const sentence = (match ? match[0] : text).trim();
  if (sentence.length <= limit) return { lead: sentence, clipped: sentence !== text };
  return { lead: `${sentence.slice(0, limit - 1).trimEnd()}…`, clipped: true };
}

export function presentBasis(text: string, limit = 120): { show: string; full: string | null } {
  const trimmed = text.trim();
  const gloss = GLOSS[trimmed];
  if (gloss) return { show: gloss, full: trimmed };
  if (trimmed.startsWith('key exchange encoded in the negotiated cipher suite ')) {
    const suite = trimmed.slice('key exchange encoded in the negotiated cipher suite '.length);
    return { show: `Key exchange is part of ${suite}.`, full: trimmed };
  }
  if (trimmed.includes('ephemeral key exchange (ECDHE)')) {
    return { show: 'This cipher uses ECDHE, so it has forward secrecy.', full: trimmed };
  }
  const { lead, clipped } = firstSentence(trimmed, limit);
  return { show: lead, full: clipped ? trimmed : null };
}
