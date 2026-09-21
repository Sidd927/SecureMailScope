/**
 * Evidence & provenance — placeholder (doc 23 §7).
 *
 * The Phase-10 foundation ships the shell, the router, the API client, the safe DOM
 * layer and the state handling. This screen is implemented in Milestone 6 and shows
 * what it will contain rather than pretending to be finished.
 */
import { getAssessment } from '../api.js';
import { el, mount, section } from '../dom.js';
import { cached } from '../app.js';

export async function render(root, { runId }) {
  // The canonical fetch already runs, so the route and data path are exercised.
  const body = await cached(runId, () => getAssessment(runId));
  mount(root, [
    section('evidence', 'Evidence & provenance', [
      el('div', { className: 'state-panel' }, [
        el('h2', { text: 'Not yet implemented' }),
        el('p', {
          text: 'This view will present abstentions, limitations, unmapped citations, provenance, rule ids and artifact integrity.',
        }),
        el('p', {
          text: 'The canonical assessment for this run loaded successfully: '
            + `assessment ${body.assessment_id}, posture ${body.overall_posture}.`,
        }),
        el('p', {}, [el('a', { text: '← Back to analyses', attrs: { href: '#/' } })]),
      ]),
    ]),
  ]);
}
