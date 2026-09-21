/**
 * History — which analyses exist and what happened to each (doc 23 §7 Screen 1).
 *
 * Served by ONE request to `GET /api/v1/analyses`, which now carries the stored
 * `overall_posture` and `score_value` listing projections (doc 23 §6). A run that
 * produced no assessment shows its lifecycle state and no posture — never a posture
 * borrowed from somewhere else.
 */
import { listAnalyses } from '../api.js';
import { chip, el, mount, notice, section, table, text } from '../dom.js';

/** Lifecycle labels. An unknown future state renders as itself, not as a default. */
const STATE_LABEL = {
  CREATED: 'Created', VALIDATING: 'Validating', QUEUED: 'Queued', RUNNING: 'Running',
  FINALIZING: 'Finalizing', COMPLETED: 'Completed', FAILED: 'Failed',
  CANCELLED: 'Cancelled', RECOVERY_REQUIRED: 'Interrupted',
};
const STATE_TONE = {
  COMPLETED: 'completed', FAILED: 'failed', CANCELLED: 'cancelled',
  RECOVERY_REQUIRED: 'failed',
};
const POSTURE_TONE = {
  STRONG: 'strong', ADEQUATE: 'adequate', WEAK: 'weak', CRITICAL: 'critical',
  INSUFFICIENT_EVIDENCE: 'insufficient_evidence',
};

function stateLabel(value) {
  return STATE_LABEL[value] || String(value || 'Unknown');
}

function postureCell(item) {
  // A run without an assessment has no posture. Rendering anything here would be
  // inventing one (doc 23 §9).
  if (!item.assessment_id || !item.overall_posture) {
    return el('span', { className: 'muted', text: 'no assessment' });
  }
  const label = String(item.overall_posture).replace(/_/g, ' ');
  const tone = POSTURE_TONE[item.overall_posture] || 'unknown';
  return chip(label, tone, null);
}

function scoreCell(item) {
  // null is not zero: a withheld score must not read as a score of 0.
  if (item.score_value === null || item.score_value === undefined) {
    return el('span', { className: 'muted', text: 'not scored' });
  }
  return document.createTextNode(String(item.score_value));
}

export async function render(root, _ctx) {
  const body = await listAnalyses({ limit: 50 });

  if (!body.total) {
    mount(root, [
      section('history', 'Analyses', [
        el('div', { className: 'state-panel' }, [
          el('h2', { text: 'No analyses yet' }),
          el('p', {
            text: 'Submit a packet capture to the API to produce an assessment, then '
              + 'it will appear here.',
          }),
          el('pre', {
            className: 'snippet',
            text: 'curl -F file=@capture.pcap http://127.0.0.1:8000/api/v1/analyses',
          }),
        ]),
      ], { lead: 'Every analysis this instance has recorded.' }),
    ]);
    return;
  }

  const rows = body.items.map((item) => [
    el('a', {
      text: text(item.source_filename, item.run_id.slice(0, 12)),
      attrs: { href: `#/run/${item.run_id}` },
    }),
    chip(stateLabel(item.state), STATE_TONE[item.state] || 'neutral', null),
    postureCell(item),
    scoreCell(item),
    el('span', { className: 'mono', text: text(item.capture_id, '—').slice(0, 16) }),
    text(item.created_at, '—'),
    item.ai_enabled ? 'ML on' : 'ML off',
  ]);

  mount(root, [
    section('history', 'Analyses', [
      table(`${body.total} analysis run(s)`,
        ['Capture', 'State', 'Posture', 'Score', 'Capture ID', 'Analysed', 'ML lane'],
        rows,
        { empty: 'No analyses recorded.' }),
      notice(
        'Posture and score shown here are the listing projections stored with each '
        + 'assessment. Open a run to read the canonical assessment itself.'),
    ], { lead: 'Every analysis this instance has recorded, newest first.' }),
  ]);
}
