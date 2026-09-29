/**
 * Home — start an analysis, then see the ones that exist (doc 23 §7 Screen 1).
 *
 * Composition (V3): an investigation workspace, not a landing page. The intake and the
 * "how this works" rail sit side by side in a compact, bounded intro band — neither one
 * is allowed to dominate the viewport — and the analysis history is promoted to a
 * first-class, always-visible element directly beneath it, not a section a returning
 * analyst has to scroll past a hero to reach. There is no longer a distinct "hero"
 * layout for the empty-history case: the same compact composition holds regardless of
 * whether any analyses exist yet, because a giant centred drop zone was the single
 * largest signal that this was a demo rather than a workspace.
 *
 * This view composes two independent pieces and adds no logic of its own:
 *   - `upload.js` submits a capture to the existing endpoint;
 *   - `history.js` renders the list exactly as it always has, and reports the total so
 *     this screen can choose its heading.
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
 * The context rail: what this workspace does, in the fewest words that stay accurate.
 * A vertical list, not a card grid, sized to sit beside the intake panel rather than
 * below it — this is what replaced the four-column marketing-style row underneath the
 * old drop zone. No heading element of its own (a labelled paragraph, same pattern the
 * original explainer used): the intro band's one `h2` belongs to the section title.
 */
function contextRail() {
  const steps = [
    ['Reconstruct', 'sessions rebuilt from the captured frames'],
    ['Assess', 'deterministic rules examine the evidence'],
    ['Cite', 'every finding names its standard'],
    ['Abstain', 'uncertain questions are declared, not guessed'],
  ];
  const wrap = el('div', { className: 'context-rail' });
  wrap.appendChild(el('p', {
    className: 'context-rail-label',
    text: 'How this works',
  }));
  const rail = el('ol', { className: 'context-rail-list' });
  for (const [title, body] of steps) {
    rail.appendChild(el('li', {}, [
      el('span', { className: 'context-rail-title', text: title }),
      el('span', { className: 'context-rail-body', text: body }),
    ]));
  }
  wrap.appendChild(rail);
  wrap.appendChild(el('p', {
    className: 'context-rail-scope',
    text: 'Passive only: no server access, no credentials, no active probing, and no '
      + 'message content is read.',
  }));
  return wrap;
}

export async function render(root, _ctx) {
  const historyHost = el('div');
  const total = await renderHistory(historyHost, {});
  const limits = await instanceLimits();
  const fresh = !total;

  const panel = uploadPanel({
    hero: false,
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

  // Intake and context sit side by side in one bounded band — neither the drop zone
  // nor the explainer is allowed to read as the page's hero. The same composition
  // holds whether this is the first capture or the fiftieth.
  const intro = el('div', { className: 'workspace-intro' }, [
    el('div', { className: 'intake-panel' }, [panel]),
    contextRail(),
  ]);

  const blocks = [
    section('submit', fresh ? 'Start an investigation' : 'New analysis', [intro],
      { className: 'submit-section' }),
    historyHost,
  ];
  mount(root, blocks);
}
