/**
 * Capture submission — the analyst's primary action.
 *
 * Until this module existed the console could only *read* analyses; producing one
 * required leaving the product for a terminal. That was the single largest usability
 * defect in the console and this is the fix.
 *
 * What this module does NOT do, on purpose:
 *   - it does not read, parse or inspect the capture. The bytes are streamed to the
 *     existing submission endpoint and never touched here;
 *   - it does not validate the capture. The extension and size checks below are
 *     *advisory* — they never block a submission, because the server is the security
 *     boundary and the only thing entitled to refuse a file;
 *   - it does not invent progress. `fetch` cannot report upload progress, so the
 *     working state is indeterminate and carries no percentage;
 *   - it does not decide anything about the result. Whatever lifecycle state comes
 *     back is what is shown.
 *
 * Every string that originates outside this file — a filename, an API error message —
 * reaches the screen as a text node through `dom.js`, never as markup.
 */
import { isValidRunId, submitCapture } from './api.js';
import { el, mount, notice } from './dom.js';

/** Extensions a capture usually carries. Advisory only; never a gate. */
const KNOWN_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];

/**
 * Dropping a file anywhere other than the zone would make the browser navigate away
 * from the console and render the raw capture. Suppressed once per document.
 */
let strayDropsSuppressed = false;

function suppressStrayDrops() {
  if (strayDropsSuppressed) return;
  strayDropsSuppressed = true;
  for (const name of ['dragover', 'drop']) {
    document.addEventListener(name, (event) => {
      if (event.target && event.target.closest && event.target.closest('.dropzone')) {
        return;
      }
      event.preventDefault();
    });
  }
}

/** Bytes, in the units a human reads. Presentation only. */
function humanBytes(value) {
  if (typeof value !== 'number' || !isFinite(value) || value < 0) return 'unknown size';
  if (value < 1024) return `${value} B`;
  const units = ['KB', 'MB', 'GB'];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size < 10 ? size.toFixed(1) : Math.round(size)} ${units[unit]}`;
}

function hasKnownExtension(name) {
  const lower = String(name || '').toLowerCase();
  return KNOWN_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/**
 * Submission failures, in the analyst's words.
 *
 * The backend's own `message` is always shown as well — this only adds the context a
 * code alone does not carry. An unrecognised code falls through to the raw message
 * rather than to a generic shrug.
 */
const SUBMIT_ERRORS = {
  UNSUPPORTED_INPUT: 'The server did not recognise this as a packet capture.',
  CAPTURE_VALIDATION_FAILED: 'The file was received but could not be read as a '
    + 'capture. It may be truncated, or it may not be a PCAP at all.',
  CAPTURE_TOO_LARGE: 'The file is larger than this instance accepts.',
  RESOURCE_LIMIT_EXCEEDED: 'This instance is already at its analysis limit. One '
    + 'analysis runs at a time; try again when the queue drains.',
  TSHARK_UNAVAILABLE: 'The dissection backend (TShark) is not available to this '
    + 'instance, so no capture can be analysed until it is installed.',
  ANALYSIS_FAILED: 'The capture was accepted but the analysis did not complete.',
  INVALID_REQUEST: 'The server rejected the submission as malformed.',
  NETWORK_UNAVAILABLE: 'The console could not reach the SecureMailScope backend. '
    + 'Nothing was submitted.',
};

/**
 * The drop zone.
 *
 * `hero` makes it the whole first screen (no analyses yet); the compact form sits
 * above an existing history without competing with it.
 *
 * `onSubmitted` receives the run record the API returned. `onFailed` fires when the
 * submission was refused: a refusal still creates a FAILED run record, so whatever is
 * showing the history has to be told, or the screen keeps claiming a run count that
 * is already out of date.
 */
export function uploadPanel({ hero = false, limits = null, onSubmitted = null,
  onFailed = null } = {}) {
  suppressStrayDrops();

  const host = el('div', { className: hero ? 'upload hero' : 'upload' });
  const ceiling = limits && typeof limits.max_upload_bytes === 'number'
    ? limits.max_upload_bytes : null;

  let picked = null;          // the File the analyst chose
  let busy = false;           // a submission is in flight
  let failure = null;         // the ApiError from the last attempt, if any
  let withMl = false;         // the `ai` query flag

  function advisories() {
    const out = [];
    if (!picked) return out;
    if (!hasKnownExtension(picked.name)) {
      out.push(`This file does not end in ${KNOWN_EXTENSIONS.join(', ')}. It will `
        + 'still be submitted — the server decides whether it is a capture.');
    }
    if (ceiling !== null && picked.size > ceiling) {
      out.push(`This file is larger than the ${humanBytes(ceiling)} upload ceiling `
        + 'this instance publishes, so the server is likely to refuse it.');
    }
    return out;
  }

  async function submit() {
    if (!picked || busy) return;          // guards the double-submit
    busy = true;
    failure = null;
    draw();
    try {
      const run = await submitCapture(picked, { ai: withMl });
      busy = false;
      picked = null;
      draw();
      if (onSubmitted) onSubmitted(run);
      else if (run && isValidRunId(run.run_id)) goToRun(run.run_id);
    } catch (error) {
      busy = false;
      failure = error;
      draw();                              // the file is kept, so retry needs no repick
      // A refused submission is still recorded as a FAILED run. Telling the caller
      // lets the history refresh without disturbing this panel or its error card.
      if (onFailed) onFailed(error);
    }
  }

  function choose(file) {
    if (!file || busy) return;
    picked = file;
    failure = null;
    draw();
  }

  // ---------------------------------------------------------------- pieces
  function zone() {
    const node = el('div', {
      className: 'dropzone',
      attrs: { 'aria-busy': busy ? 'true' : 'false' },
    });

    node.addEventListener('dragenter', (event) => {
      event.preventDefault();
      if (!busy) node.classList.add('over');
    });
    node.addEventListener('dragover', (event) => {
      event.preventDefault();
      if (!busy) node.classList.add('over');
    });
    node.addEventListener('dragleave', (event) => {
      if (event.target === node) node.classList.remove('over');
    });
    node.addEventListener('drop', (event) => {
      event.preventDefault();
      node.classList.remove('over');
      const files = event.dataTransfer && event.dataTransfer.files;
      // A drop never starts an analysis by itself: the analyst confirms.
      if (files && files.length) choose(files[0]);
    });

    node.appendChild(el('span', { className: 'dz-mark', attrs: { 'aria-hidden': 'true' } }));
    node.appendChild(el('p', {
      className: 'dz-title',
      text: 'Drop a packet capture here',
    }));

    const input = el('input', {
      id: 'capture-input',
      className: 'dz-input',
      attrs: { type: 'file', accept: '.pcap,.pcapng,.cap' },
    });
    input.addEventListener('change', () => {
      if (input.files && input.files.length) choose(input.files[0]);
    });
    const label = el('label', {
      className: 'dz-browse',
      text: 'Select a capture file',
      attrs: { for: 'capture-input' },
    });
    node.appendChild(el('div', { className: 'dz-pick' }, [label, input]));
    node.appendChild(el('p', {
      className: 'dz-hint',
      text: 'SMTP, IMAP and POP3 — including STARTTLS and implicit TLS '
        + '(SMTPS / IMAPS / POP3S).',
    }));
    return node;
  }

  function selectedCard() {
    const card = el('div', { className: 'picked' });
    card.appendChild(el('div', { className: 'picked-file' }, [
      el('span', { className: 'picked-name', text: picked.name || 'capture' }),
      el('span', { className: 'picked-size', text: humanBytes(picked.size) }),
    ]));

    const controls = el('div', { className: 'picked-controls' });

    const analyse = el('button', {
      className: 'btn btn-primary',
      text: busy ? 'Analyzing…' : 'Analyze capture',
      attrs: { type: 'button', disabled: busy ? 'disabled' : null },
      onClick: submit,
    });
    controls.appendChild(analyse);

    const discard = el('button', {
      className: 'btn btn-quiet',
      text: 'Choose a different file',
      attrs: { type: 'button', disabled: busy ? 'disabled' : null },
      onClick: () => { if (!busy) { picked = null; failure = null; draw(); } },
    });
    controls.appendChild(discard);

    const mlId = 'submit-with-ml';
    const mlWrap = el('label', { className: 'picked-ml', attrs: { for: mlId } });
    const mlInput = el('input', {
      id: mlId,
      attrs: { type: 'checkbox', disabled: busy ? 'disabled' : null },
    });
    mlInput.checked = withMl;
    mlInput.addEventListener('change', () => { withMl = mlInput.checked; });
    mlWrap.appendChild(mlInput);
    mlWrap.appendChild(el('span', {
      text: 'Run the ML prioritisation lane (ordering only — it produces no '
        + 'security conclusion)',
    }));
    controls.appendChild(mlWrap);

    card.appendChild(controls);

    for (const message of advisories()) card.appendChild(notice(message));

    if (busy) {
      card.appendChild(el('div', {
        className: 'working',
        attrs: { role: 'status', 'aria-live': 'polite' },
      }, [
        el('span', { className: 'working-bar', attrs: { 'aria-hidden': 'true' } },
          [el('span', { className: 'working-fill' })]),
        el('span', {
          className: 'working-text',
          text: 'Analyzing capture. The elapsed time is measured and reported when '
            + 'the run completes.',
        }),
      ]));
    }
    return card;
  }

  function failureCard() {
    const code = (failure && failure.code) || 'INTERNAL_ERROR';
    const card = el('div', { className: 'submit-error' });
    card.appendChild(el('p', {
      className: 'submit-error-title',
      text: SUBMIT_ERRORS[code] || 'The submission did not succeed.',
    }));
    if (failure && failure.message) {
      card.appendChild(el('p', { className: 'submit-error-body', text: failure.message }));
    }
    card.appendChild(el('p', { className: 'code', text: `Error code: ${code}` }));
    return card;
  }

  function draw() {
    const parts = [];
    if (hero) {
      parts.push(el('p', {
        className: 'upload-kicker',
        text: 'Passive cryptographic posture assessment for email infrastructure',
      }));
    }
    parts.push(zone());
    if (picked) parts.push(selectedCard());
    if (failure) parts.push(failureCard());
    parts.push(el('p', {
      className: 'upload-scope',
      text: 'Runs locally against a capture file. No server access, no credentials, '
        + 'no active probing, and no message content is read.',
    }));
    mount(host, parts);
  }

  draw();
  return host;
}

/**
 * Navigate to a run. The identifier is re-validated against the 32-hex shape before
 * it reaches the address bar, even though it came from our own API.
 */
export function goToRun(runId) {
  if (!isValidRunId(runId)) return;
  window.location.hash = `#/run/${runId}`;
}

export { humanBytes, hasKnownExtension };
