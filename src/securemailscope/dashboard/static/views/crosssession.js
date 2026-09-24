/**
 * Cross-session — this endpoint next to comparable sessions at the same server.
 *
 * Promoted from a summary module on Overview to a first-class investigation view: this
 * is the product's differentiating claim (doc 23; DO-NOT-CLAIM.md), so it gets its own
 * place an analyst can navigate to directly rather than scrolling past on the way to
 * something else.
 *
 * Consumes the same `DashboardViewModel` Overview does and performs no comparison of
 * its own. Two things can be present and they are different claims:
 *   - a `BEHAVIOURAL_DEVIATION` finding — an endpoint was compared against comparable
 *     sessions and differed;
 *   - an abstention on a deviation issue class — the comparison was attempted and
 *     declined. On a capture with too few comparable sessions this is what the
 *     engine's minimum-history floor produces, and the abstention's own `why` text
 *     already states the count found versus required -- nothing here hardcodes that
 *     threshold, because the frontend has no independent source of truth for it.
 *
 * With neither present, this screen says so plainly rather than rendering nothing:
 * arriving here by navigation (not a summary link) deserves an explicit answer, not a
 * blank page that looks broken.
 */
import { getDashboard } from '../api.js';
import { chip, el, mount, notice, section, table, text } from '../dom.js';
import { cached } from '../app.js';

const DEVIATION_KIND = 'BEHAVIOURAL_DEVIATION';
const DEVIATION_CLASSES = ['STARTTLS_BEHAVIOUR_DEVIATION', 'TLS_VERSION_DEVIATION'];
const HISTORY_REASONS = ['INSUFFICIENT_HISTORY', 'NOT_COMPARABLE'];

/** Identical declined comparisons collapse into one row with a count — the same
 * grouping Overview's summary already uses, kept consistent here. */
function groupDeclined(rows) {
  const out = new Map();
  for (const row of rows) {
    const key = [row.reason, row.issue_class, row.what_could_not_be_concluded,
      row.why].join('␟');
    const seen = out.get(key);
    if (seen) seen.count += 1;
    else out.set(key, { row, count: 1 });
  }
  return [...out.values()];
}

function deviationPanel(deviations, runId) {
  return section('deviations', `Established (${deviations.length})`, [
    table(`${deviations.length} behavioural deviation(s) established by comparison`,
      ['Severity', 'Condition', 'Protocol', 'Sessions', 'What was compared'],
      deviations.map((f) => [
        chip(f.severity_label, f.severity_tone, f.severity_marker),
        f.title || f.issue_class_label,
        f.protocol_label,
        text(f.affected_sessions, '1'),
        text(f.conclusion, '—'),
      ]),
      { wide: [4] }),
    el('p', {}, [
      el('a', { text: 'Inspect the evidence behind these comparisons →',
        attrs: { href: `#/run/${runId}/evidence` } }),
    ]),
  ], { lead: 'This endpoint\'s behaviour differed from comparable prior sessions at '
    + 'the same server, protocol and TLS mode.' });
}

function declinedPanel(declined) {
  const grouped = groupDeclined(declined);
  return section('declined', `Declined (${declined.length})`, [
    table(`${declined.length} declined comparison(s), grouped by question`,
      ['Reason', 'Could not conclude', 'Why', 'Sessions'],
      grouped.map((entry) => [
        el('span', {
          className: 'state-chip',
          text: entry.row.reason_label || text(entry.row.reason),
        }),
        text(entry.row.what_could_not_be_concluded, '—'),
        text(entry.row.why, '—'),
        String(entry.count),
      ]),
      { wide: [1, 2] }),
    notice('A declined comparison is not a failure. It means the required prior '
      + 'comparable history did not exist for this endpoint, protocol and TLS mode at '
      + 'the time of analysis. The engine does not extrapolate a baseline it cannot '
      + 'support.'),
  ], { lead: 'Comparisons the engine considered and chose not to make, and why.' });
}

function emptyState() {
  return section('crosssession-empty', 'Cross-session', [
    el('p', { text: 'This assessment recorded no cross-session findings and no '
      + 'declined comparisons for this capture. Cross-session rules may not have '
      + 'applied to the protocols observed here, or this run predates cross-session '
      + 'reasoning.' }),
  ], { lead: 'What this endpoint looks like next to comparable sessions at the same '
    + 'server.' });
}

export async function render(root, { runId }) {
  const vm = await cached(runId, () => getDashboard(runId));

  const deviations = (vm.findings || []).filter((f) => f.fact_kind === DEVIATION_KIND);
  const declined = (vm.abstentions || []).filter(
    (a) => DEVIATION_CLASSES.indexOf(a.issue_class) !== -1
      || HISTORY_REASONS.indexOf(a.reason) !== -1);

  if (!deviations.length && !declined.length) {
    mount(root, [emptyState()]);
    return;
  }

  // Sibling top-level sections, not nested — the same flat pattern Overview uses, so
  // this screen contributes one heading landmark per topic rather than a section
  // inside a section.
  const blocks = [
    section('crosssession-intro', 'Cross-session', [
      el('p', { className: 'lead-strong', text: 'Comparable history means prior '
        + 'sessions at the same endpoint, protocol and TLS mode — never pooled across '
        + 'the whole capture, and never across a different TLS mode.' }),
    ]),
  ];
  if (deviations.length) blocks.push(deviationPanel(deviations, runId));
  if (declined.length) blocks.push(declinedPanel(declined));
  blocks.push(notice('A deviation is a statement about behaviour relative to '
    + 'comparable sessions at the same server. It is not an attribution, and it is '
    + 'not a claim that an attack occurred.'));

  mount(root, blocks);
}
