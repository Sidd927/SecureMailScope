/**
 * Home — start an analysis, then see the ones that exist (doc 23 §7 Screen 1).
 *
 * The primary action is always the first thing on this screen. On a fresh instance it
 * is the *only* thing, because an empty console whose empty state is a sentence about
 * an API is a dead end; on a populated one it sits above the history without competing
 * with it.
 *
 * This view composes two independent pieces and adds no logic of its own:
 *   - `upload.js` submits a capture to the existing endpoint;
 *   - `history.js` renders the list exactly as it always has, and reports the total so
 *     this screen can choose the hero or the compact arrangement.
 *
 * No security value is read, derived or displayed here.
 */
import { health } from '../api.js';
import { el, mount, section } from '../dom.js';
import { uploadPanel, goToRun } from '../upload.js';
import { render as renderHistory } from './history.js';

/**
 * The instance's published upload ceiling, used only for an advisory size hint.
 * Fetched once per page load: a failure is silent because the hint is optional and
 * the server enforces the real limit regardless.
 */
let limitsPromise = null;

function instanceLimits() {
  if (limitsPromise === null) {
    limitsPromise = health().then((body) => body.limits || null).catch(() => null);
  }
  return limitsPromise;
}

/**
 * The methodology, as a slim rail — not a grid of marketing-style cards competing with
 * the drop zone above it. One row, small type, a section break before it so it never
 * reads as part of the primary action. The four steps are unchanged from the original
 * explainer; only their visual weight is demoted.
 */
function methodologyRail() {
  const steps = [
    ['Reconstruct', 'sessions rebuilt from the captured frames'],
    ['Assess', 'deterministic rules examine the evidence'],
    ['Cite', 'every finding names its standard'],
    ['Abstain', 'uncertain questions are declared, not guessed'],
  ];
  const wrap = el('div', { className: 'methodology' });
  wrap.appendChild(el('p', {
    className: 'methodology-label',
    text: 'How SecureMailScope works',
  }));
  const rail = el('ol', { className: 'methodology-rail' });
  for (const [title, body] of steps) {
    rail.appendChild(el('li', {}, [
      el('span', { className: 'methodology-title', text: title }),
      el('span', { className: 'methodology-body', text: body }),
    ]));
  }
  wrap.appendChild(rail);
  return wrap;
}

export async function render(root, _ctx) {
  const historyHost = el('div');
  const total = await renderHistory(historyHost, {});
  const limits = await instanceLimits();
  const fresh = !total;

  const panel = uploadPanel({
    hero: fresh,
    limits,
    onSubmitted: (run) => {
      // A completed run has something to show, so go straight to it. Anything else is
      // still in flight and belongs in the history, which polls until it settles.
      if (run && run.state === 'COMPLETED' && run.assessment_id) {
        goToRun(run.run_id);
      } else {
        render(root, _ctx);
      }
    },
    // Only the history is redrawn, so the panel keeps the rejected file and the
    // error text the analyst is reading.
    onFailed: () => { renderHistory(historyHost, {}); },
  });

  const blocks = [
    section('submit', fresh ? 'Assess an email capture' : 'New analysis',
      fresh ? [panel, methodologyRail()] : [panel],
      { className: fresh ? 'submit-section first-run' : 'submit-section' }),
    historyHost,
  ];
  mount(root, blocks);
}
