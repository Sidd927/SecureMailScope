/**
 * History — which analyses exist and what happened to each (doc 23 §7 Screen 1).
 *
 * Served by ONE request to `GET /api/v1/analyses`, which carries the stored
 * `overall_posture` and `score_value` listing projections (doc 23 §6). A run that
 * produced no assessment shows its lifecycle state and no posture — never a posture
 * borrowed from somewhere else.
 *
 * Lifecycle handling is deliberately literal. The nine states come from the Phase-8
 * enum and are shown as themselves. **No completion fraction is invented**: the API
 * exposes none, so a running analysis says it is running and nothing more. An
 * unknown future state renders as its own name rather than being mapped onto a state
 * this build happens to know.
 */
import { listAnalyses } from '../api.js';
import { chip, el, mount, notice, section, table, text } from '../dom.js';

/**
 * Backend `JobState` (verified against `backend/lifecycle.py`). `explain` is shown
 * beside the state so an analyst is not left inferring what it implies.
 *
 * `settled` means "no further change is expected without a new run", which is a
 * POLLING question and deliberately not the same as the backend's TERMINAL set.
 * `RECOVERY_REQUIRED` is settled here while not being backend-terminal: ADR-0018
 * makes it an audited intermediate that the startup sweep moves straight to FAILED,
 * so a client that somehow observes it gains nothing by re-asking. Every backend
 * TERMINAL state is settled; the converse does not hold, and a test asserts both
 * directions rather than letting the two notions quietly merge.
 */
const STATES = {
  CREATED: { label: 'Created', tone: 'neutral', settled: false,
    explain: 'accepted, not yet validated' },
  VALIDATING: { label: 'Validating', tone: 'neutral', settled: false,
    explain: 'checking the capture before analysis' },
  QUEUED: { label: 'Queued', tone: 'neutral', settled: false,
    explain: 'waiting for the analysis slot' },
  RUNNING: { label: 'Running', tone: 'neutral', settled: false,
    explain: 'analysis in progress' },
  FINALIZING: { label: 'Finalizing', tone: 'neutral', settled: false,
    explain: 'persisting the assessment' },
  COMPLETED: { label: 'Completed', tone: 'completed', settled: true,
    explain: 'assessment stored and retrievable' },
  FAILED: { label: 'Failed', tone: 'failed', settled: true,
    explain: 'no assessment was produced' },
  CANCELLED: { label: 'Cancelled', tone: 'cancelled', settled: true,
    explain: 'superseded or withdrawn before completion' },
  RECOVERY_REQUIRED: { label: 'Interrupted', tone: 'failed', settled: true,
    explain: 'the process stopped before the analysis finished' },
};

/** States worth re-checking. Derived from the table, not hard-coded twice. */
const UNSETTLED = Object.keys(STATES).filter((k) => !STATES[k].settled);

/** Poll only while something is actually in flight, and not forever. */
const POLL_INTERVAL_MS = 4000;
const POLL_MAX_TICKS = 150;          // ~10 minutes, then it stops on its own

const POSTURE_TONE = {
  STRONG: 'strong', ADEQUATE: 'adequate', WEAK: 'weak', CRITICAL: 'critical',
  INSUFFICIENT_EVIDENCE: 'insufficient_evidence',
};

let pollTimer = null;
let pollTicks = 0;

function stopPolling() {
  if (pollTimer !== null) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
  pollTicks = 0;
}

function stateFor(value) {
  // An unknown future state is shown as itself, never mapped onto a known one.
  return STATES[value] || {
    label: String(value || 'Unknown'), tone: 'unknown', settled: true,
    explain: 'a lifecycle state this console version does not recognise',
  };
}

function postureCell(item) {
  // A run without an assessment has no posture. Rendering anything here would be
  // inventing one (doc 23 §9).
  if (!item.assessment_id || !item.overall_posture) {
    const info = stateFor(item.state);
    return el('span', {
      className: 'muted',
      text: info.settled ? 'no assessment' : 'not yet assessed',
    });
  }
  const label = String(item.overall_posture).replace(/_/g, ' ');
  return chip(label, POSTURE_TONE[item.overall_posture] || 'unknown', null);
}

function scoreCell(item) {
  // null is not zero: a withheld score must not read as a score of 0.
  if (item.score_value === null || item.score_value === undefined) {
    return el('span', { className: 'muted', text: 'not scored' });
  }
  return document.createTextNode(String(item.score_value));
}

/** The capture cell links into the run only when there is something to open. */
function captureCell(item) {
  const label = text(item.source_filename, `run ${item.run_id.slice(0, 12)}`);
  if (item.state === 'COMPLETED' && item.assessment_id) {
    return el('a', { text: label, attrs: { href: `#/run/${item.run_id}` } });
  }
  return el('span', { text: label });
}

/**
 * Failure detail. The API already returns a structured code and a message authored
 * by the backend, so this renders them and adds nothing: no traceback, no path, no
 * internal detail (doc 23 §9).
 */
function failureCell(item) {
  if (!item.error_code) return document.createTextNode('—');
  const wrap = el('span', { className: 'fail-cell' });
  wrap.appendChild(el('span', { className: 'mono', text: item.error_code }));
  if (item.error_message) {
    wrap.appendChild(el('span', { className: 'note', text: item.error_message }));
  }
  return wrap;
}

function rowsFor(items) {
  return items.map((item) => {
    const info = stateFor(item.state);
    const state = el('span', { className: 'state-cell' });
    state.appendChild(chip(info.label, info.tone, null));
    state.appendChild(el('span', { className: 'note', text: info.explain }));
    return [
      captureCell(item),
      state,
      postureCell(item),
      scoreCell(item),
      el('span', { className: 'mono', text: text(item.capture_id, '—').slice(0, 16) }),
      text(item.created_at, '—'),
      item.ai_enabled ? 'ML on' : 'ML off',
      failureCell(item),
    ];
  });
}

function emptyPanel() {
  return el('div', { className: 'state-panel' }, [
    el('h2', { text: 'No analyses yet' }),
    el('p', {
      text: 'Submit a packet capture to the API to produce an assessment, then it '
        + 'will appear here.',
    }),
    el('pre', {
      className: 'snippet',
      text: 'curl -F file=@capture.pcap http://127.0.0.1:8000/api/v1/analyses',
    }),
  ]);
}

export async function render(root, _ctx) {
  stopPolling();

  const host = el('div');
  const statusLine = el('p', {
    className: 'result-count',
    attrs: { role: 'status', 'aria-live': 'polite' },
  });

  async function draw() {
    const body = await listAnalyses({ limit: 50 });

    if (!body.total) {
      statusLine.textContent = 'No analyses recorded.';
      mount(host, [emptyPanel()]);
      stopPolling();
      return;
    }

    const active = body.items.filter(
      (i) => UNSETTLED.indexOf(i.state) !== -1);
    statusLine.textContent = active.length
      ? `${body.total} analysis run(s) · ${active.length} in progress`
      : `${body.total} analysis run(s)`;

    mount(host, [
      table(`${body.total} analysis run(s), newest first`,
        ['Capture', 'State', 'Posture', 'Score', 'Capture ID', 'Analysed',
          'ML lane', 'Failure'],
        rowsFor(body.items),
        { wide: [7], empty: 'No analyses recorded.' }),
      notice('Posture and score shown here are the listing projections stored with '
        + 'each assessment. Open a run to read the canonical assessment itself.'),
    ]);

    // Re-check only while something is genuinely in flight, and stop when it settles
    // or when the budget runs out. No unbounded loop, no request storm.
    if (active.length && pollTicks < POLL_MAX_TICKS) {
      pollTicks += 1;
      pollTimer = setTimeout(() => {
        pollTimer = null;
        draw().catch(() => stopPolling());
      }, POLL_INTERVAL_MS);
    } else {
      stopPolling();
    }
  }

  await draw();

  mount(root, [
    section('history', 'Analyses', [statusLine, host], {
      lead: 'Every analysis this instance has recorded, newest first. A run that '
        + 'produced no assessment shows its lifecycle state and no posture.',
    }),
  ]);
}

export { STATES, UNSETTLED, stopPolling };
