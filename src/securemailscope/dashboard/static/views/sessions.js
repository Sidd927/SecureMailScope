/**
 * Sessions — the reconstructed TCP streams behind one capture, and a real
 * investigation drawer for each one.
 *
 * Backed by `GET /analyses/{id}/sessions` (`SessionEvidence.to_dict()`, verbatim) --
 * a read-only projection over what Phase 3 already computed, not a second authority.
 * Findings, posture and evidence state remain the dashboard view model's; this screen
 * cross-references them by `stream_key` / `affected_stream_keys` to show which
 * findings a session is implicated in, but never recomputes a severity, a status or an
 * evidence state itself.
 *
 * Two things this file deliberately does NOT do:
 *   - invent a column the session document does not carry (no packet-level payload,
 *     no synthetic "risk" score for a session);
 *   - fabricate a stable session identifier. A session with no `tcp_stream_id` has no
 *     deep link and is shown, but is not clickable into a drawer -- linking it to a
 *     row that does not exist would misrepresent what the capture supports.
 */
import { getDashboard, getSessions } from '../api.js';
import { el, facts, mount, notice, section, table, text } from '../dom.js';
import { cached } from '../app.js';

/** Application-layer TLS completion evidence, in the analyst's words (session/model.py
 * `TlsState` docstring) -- not renamed, only explained. */
const TLS_STATE_LABEL = {
  NONE: 'No TLS',
  CLIENT_HELLO_OBSERVED: 'ClientHello only',
  SERVER_HELLO_OBSERVED: 'Both hellos, completion unproven',
  ESTABLISHED: 'Established',
  HANDSHAKE_INTERRUPTED: 'Interrupted',
};

const COMPLETENESS_LABEL = {
  COMPLETE: 'Complete', INCOMPLETE: 'Incomplete', TRUNCATED: 'Truncated',
};

function endpoint(side) {
  if (!side || (!side.ip && !side.port)) return '—';
  return `${text(side.ip, '?')}${side.port ? ':' + side.port : ''}`;
}

function fmtTime(epoch) {
  if (typeof epoch !== 'number') return '—';
  try {
    return new Date(epoch * 1000).toISOString().replace('.000Z', 'Z');
  } catch (error) {
    return '—';
  }
}

function duration(session) {
  const t = session.timing || {};
  if (typeof t.start_epoch !== 'number' || typeof t.end_epoch !== 'number') return '—';
  const seconds = t.end_epoch - t.start_epoch;
  return seconds < 1 ? `${Math.round(seconds * 1000)} ms` : `${seconds.toFixed(2)} s`;
}

/** Findings whose `affected_stream_keys` names this session. Cross-reference only --
 * nothing here decides severity, status or evidence state; those travel with the
 * finding untouched. */
function findingsFor(session, findings) {
  const key = session.stream_key;
  if (!key) return [];
  return (findings || []).filter((f) => (f.affected_stream_keys || []).includes(key));
}

// ------------------------------------------------------------------ explorer table
const FILTERS = { protocol: '', tls: '', completeness: '', q: '' };

function matchesFilters(session) {
  if (FILTERS.protocol && session.protocol !== FILTERS.protocol) return false;
  if (FILTERS.tls && session.tls_state !== FILTERS.tls) return false;
  if (FILTERS.completeness && session.completeness !== FILTERS.completeness) return false;
  if (FILTERS.q) {
    const needle = FILTERS.q.toLowerCase();
    const haystack = [
      session.protocol, endpoint(session.client), endpoint(session.server),
      session.stream_key,
    ].filter(Boolean).join(' ').toLowerCase();
    if (!haystack.includes(needle)) return false;
  }
  return true;
}

const SORTERS = {
  time: (a, b) => (a.timing?.start_epoch ?? Infinity) - (b.timing?.start_epoch ?? Infinity),
  protocol: (a, b) => String(a.protocol || '').localeCompare(String(b.protocol || '')),
  packets: (a, b) => (b.timing?.packet_count ?? 0) - (a.timing?.packet_count ?? 0),
};
let sortKey = 'time';

function filterBar(sessions, onChange) {
  const form = el('form', { className: 'filters', attrs: { role: 'search' } });
  form.addEventListener('submit', (e) => e.preventDefault());

  const searchWrap = el('div', { className: 'facet session-search' });
  searchWrap.appendChild(el('label', { text: 'Search', attrs: { for: 'session-q' } }));
  const search = el('input', {
    id: 'session-q',
    attrs: { type: 'search', placeholder: 'protocol, address, port…' },
  });
  search.addEventListener('input', () => { FILTERS.q = search.value; onChange(); });
  searchWrap.appendChild(search);
  form.appendChild(searchWrap);

  function selectFacet(id, labelText, options, key) {
    const wrap = el('div', { className: 'facet' });
    wrap.appendChild(el('label', { text: labelText, attrs: { for: id } }));
    const sel = el('select', { id, attrs: {} });
    sel.appendChild(el('option', { text: 'All', attrs: { value: '' } }));
    for (const value of options) {
      sel.appendChild(el('option', { text: value, attrs: { value } }));
    }
    sel.addEventListener('change', () => { FILTERS[key] = sel.value; onChange(); });
    wrap.appendChild(sel);
    return wrap;
  }

  const protocols = [...new Set(sessions.map((s) => s.protocol).filter(Boolean))].sort();
  const tlsStates = [...new Set(sessions.map((s) => s.tls_state).filter(Boolean))].sort();
  const completeness = [...new Set(sessions.map((s) => s.completeness).filter(Boolean))]
    .sort();
  if (protocols.length > 1) {
    form.appendChild(selectFacet('session-protocol', 'Protocol', protocols, 'protocol'));
  }
  if (tlsStates.length > 1) {
    form.appendChild(selectFacet('session-tls', 'TLS', tlsStates, 'tls'));
  }
  if (completeness.length > 1) {
    form.appendChild(selectFacet('session-complete', 'Completeness', completeness,
      'completeness'));
  }

  const sortWrap = el('div', { className: 'facet' });
  sortWrap.appendChild(el('label', { text: 'Sort', attrs: { for: 'session-sort' } }));
  const sortSel = el('select', { id: 'session-sort' });
  for (const [value, labelText] of [['time', 'Start time'], ['protocol', 'Protocol'],
    ['packets', 'Packet count']]) {
    sortSel.appendChild(el('option', { text: labelText, attrs: { value } }));
  }
  sortSel.value = sortKey;
  sortSel.addEventListener('change', () => { sortKey = sortSel.value; onChange(); });
  sortWrap.appendChild(sortSel);
  form.appendChild(sortWrap);

  return form;
}

function sessionRow(session, runId, findingCount) {
  const idText = session.tcp_stream_id !== null && session.tcp_stream_id !== undefined
    ? String(session.tcp_stream_id) : null;
  const label = `${endpoint(session.client)} → ${endpoint(session.server)}`;
  const linkOrText = idText
    ? el('a', { text: label, attrs: { href: `#/run/${runId}/sessions/${idText}` } })
    : el('span', { text: label });
  return [
    text(session.protocol, 'unattributed'),
    linkOrText,
    fmtTime(session.timing?.start_epoch),
    duration(session),
    text(session.timing?.packet_count, '0'),
    COMPLETENESS_LABEL[session.completeness] || text(session.completeness),
    TLS_STATE_LABEL[session.tls_state] || text(session.tls_state),
    findingCount ? `${findingCount}` : '—',
  ];
}

function explorerPanel(sessions, findings, runId, host) {
  function redraw() {
    const visible = sessions.filter(matchesFilters)
      .slice().sort(SORTERS[sortKey] || SORTERS.time);
    const rows = visible.map((s) => sessionRow(s, runId, findingsFor(s, findings).length));
    mount(host, [
      table(`${visible.length} of ${sessions.length} session(s)`,
        ['Protocol', 'Client → Server', 'Started', 'Duration', 'Packets',
          'Completeness', 'TLS', 'Findings'],
        rows, { empty: 'No sessions match these filters.' }),
    ]);
  }
  return redraw;
}

// -------------------------------------------------------------------- detail drawer
function tlsField(labelText, field) {
  if (!field) return null;
  const value = field.value !== null && field.value !== undefined
    ? String(field.value) : null;
  return [labelText, value || `(${field.state.toLowerCase().replace(/_/g, ' ')})`,
    field.basis];
}

function certificateBlock(cert) {
  return el('div', { className: 'session-cert' }, [
    el('h3', { text: `Certificate ${cert.index}` }),
    facts([
      ['Subject key ID', cert.subject_key_id, null],
      ['Authority key ID', cert.authority_key_id, null],
      ['Self-signed', cert.self_signed ? 'Yes' : 'No', null],
      ['Public key', cert.public_key_algorithm
        ? `${cert.public_key_algorithm}${cert.key_bits ? ` (${cert.key_bits}-bit)` : ''}`
        : '—', null],
      ['Validity', cert.not_before_text && cert.not_after_text
        ? `${cert.not_before_text} to ${cert.not_after_text}` : '—', null],
      ['Subject alt. names', (cert.san_dns_names || []).join(', ') || '—', null],
    ]),
  ]);
}

function eventsTimeline(session) {
  const events = session.events || [];
  if (!events.length) return null;
  return el('div', { className: 'session-timeline' }, [
    el('h3', { text: 'Timeline' }),
    table('Protocol events observed in this session',
      ['Frame', 'Direction', 'Event', 'Detail'],
      events.map((e) => [
        text(e.frame, '—'), e.direction.replace(/_/g, ' ').toLowerCase(),
        e.kind.replace(/_/g, ' '), e.detail || '—',
      ]), { wide: [3] }),
  ]);
}

function relatedFindings(session, findings, runId) {
  const rows = findingsFor(session, findings);
  if (!rows.length) {
    return el('p', { className: 'muted',
      text: 'No findings in this assessment are attributed to this session.' });
  }
  return el('div', { className: 'session-findings' }, [
    el('p', {}, [el('a', {
      text: `${rows.length} finding(s) attributed to this session →`,
      attrs: { href: `#/run/${runId}/findings` },
    })]),
  ]);
}

function drawer(session, findings, runId, onClose) {
  const backdrop = el('div', { className: 'drawer-backdrop' });
  backdrop.addEventListener('click', onClose);

  const closeBtn = el('button', {
    className: 'drawer-close', text: 'Close', attrs: { type: 'button' },
    onClick: onClose,
  });

  const heading = `${text(session.protocol, 'Unattributed')} session `
    + `${endpoint(session.client)} → ${endpoint(session.server)}`;

  const body = el('div', { className: 'drawer-body' }, [
    el('h3', { id: 'drawer-title', text: heading }),
    facts([
      ['Stream key', session.stream_key, null],
      ['Completeness', COMPLETENESS_LABEL[session.completeness]
        || text(session.completeness), null],
      ['Started', fmtTime(session.timing?.start_epoch), null],
      ['Duration', duration(session), null],
      ['Packets', text(session.timing?.packet_count, '0'), null],
      ['First / last frame', `${text(session.timing?.first_frame, '—')} / `
        + `${text(session.timing?.last_frame, '—')}`, null],
      ['Endpoint basis', session.endpoint_basis || '—', null],
    ]),
    el('h3', { text: 'TLS' }),
    facts([
      tlsField('Negotiated version', session.evidence?.tls_negotiated_version),
      tlsField('Cipher suite', session.evidence?.tls_cipher_suite_name
        || session.evidence?.tls_cipher_suite),
      tlsField('Key exchange', session.evidence?.tls_key_exchange),
      tlsField('Named group', session.evidence?.tls_named_group),
      tlsField('Forward secrecy', session.evidence?.tls_forward_secrecy),
      tlsField('Certificate chain', session.evidence?.tls_certificate_chain),
    ].filter(Boolean)),
    (session.certificates || []).length
      ? el('div', {}, (session.certificates || []).map(certificateBlock))
      : null,
    eventsTimeline(session),
    el('h3', { text: 'Findings' }),
    relatedFindings(session, findings, runId),
  ].filter(Boolean));

  const panel = el('div', {
    className: 'drawer-panel',
    attrs: { role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'drawer-title' },
  }, [closeBtn, body]);

  document.addEventListener('keydown', function onKey(e) {
    if (e.key === 'Escape') { document.removeEventListener('keydown', onKey); onClose(); }
  });

  return el('div', { className: 'drawer' }, [backdrop, panel]);
}

// ----------------------------------------------------------------------- render
export async function render(root, { runId, streamId }) {
  const [sessionData, vm] = await Promise.all([
    getSessions(runId),
    cached(runId, () => getDashboard(runId)),
  ]);
  const sessions = sessionData.items || [];
  const findings = vm.findings || [];

  const explorerHost = el('div');
  const blocks = [
    section('sessions', 'Sessions', [
      sessions.length
        ? filterBar(sessions, () => redraw())
        : null,
      explorerHost,
    ], {
      lead: sessions.length
        ? 'Every TCP stream reconstructed from this capture. Findings counted here '
          + 'are the assessment\'s own; nothing on this screen assigns a severity.'
        : undefined,
    }),
  ].filter(Boolean);

  if (!sessions.length) {
    blocks[0] = section('sessions', 'Sessions', [
      el('p', { text: 'No sessions were reconstructed for this capture, or this run '
        + 'predates session persistence and has nothing stored here.' }),
    ]);
  }

  mount(root, blocks);
  const redraw = sessions.length
    ? explorerPanel(sessions, findings, runId, explorerHost) : () => {};
  redraw();

  if (!streamId) return;
  const session = sessions.find((s) => String(s.tcp_stream_id) === String(streamId));
  if (!session) {
    root.appendChild(notice(
      `No session with stream id ${streamId} was found in this capture.`, 'withheld'));
    return;
  }
  const closeToUrl = `#/run/${runId}/sessions`;
  const panel = drawer(session, findings, runId, () => { window.location.hash = closeToUrl; });
  document.body.appendChild(panel);
  const closeButton = panel.querySelector('.drawer-close');
  if (closeButton) closeButton.focus();
}
