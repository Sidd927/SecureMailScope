/**
 * Findings — what requires attention, why, and on what basis (doc 23 §7 Screen 3).
 *
 * Filtering here is a **view** over the canonical list. Three properties hold by
 * construction, not by care:
 *
 *   1. `vm.findings` is never mutated and never sorted. Filtering produces a new array
 *      with `Array.prototype.filter`, which preserves source order, so clearing every
 *      filter reproduces the canonical rank order exactly.
 *   2. Facet counts come from `vm.filters`, computed once by the Python projection.
 *      Nothing is counted here.
 *   3. A finding with `protocol === null` is reachable through an explicit
 *      "Not attributed to a protocol" option, so an anomaly signal cannot be hidden by
 *      a protocol filter.
 *
 * No threshold, bucket or comparison decides what is important. The assessment already
 * decided, and this screen shows severity, status, certainty and observability as four
 * separate columns rather than one "risk" verdict.
 */
import { getDashboard } from '../api.js';
import { chip, el, facts, mount, notice, section, table, text } from '../dom.js';
import { cached } from '../app.js';
import { FACETS, activeCount, applyFilters } from '../filtering.js';

/**
 * Filter selections, kept per run so navigating to Overview and back does not lose
 * them. Deliberately module state and not the URL: a filtered view is a working
 * position, not a citable fact — the assessment id is what gets cited.
 */
const selections = new Map();

function stateFor(runId) {
  if (!selections.has(runId)) selections.set(runId, {});
  return selections.get(runId);
}

function findingSummaryLine(row) {
  const parts = [`#${text(row.rank, '?')}`];
  const line = el('span', { className: 'sum-line' });
  line.appendChild(el('span', { className: 'sum-rank', text: parts[0] }));
  line.appendChild(chip(row.severity_label || 'unknown', row.severity_tone,
    row.severity_marker));
  line.appendChild(el('span', {
    className: 'sum-title',
    text: row.title || row.issue_class_label || 'Untitled finding',
  }));
  const meta = [row.status_label, row.certainty_label, row.protocol_label]
    .filter(Boolean).join(' · ');
  if (meta) line.appendChild(el('span', { className: 'sum-meta', text: meta }));
  if (!row.severity_known) {
    line.appendChild(el('span', {
      className: 'sum-meta warn',
      text: 'severity not recognised by this console',
    }));
  }
  return line;
}

/** Full detail for one finding. Every value is canonical; none is rewritten. */
function findingDetail(row) {
  const body = el('div', { className: 'finding-body' });

  body.appendChild(facts([
    ['Issue class', row.issue_class_label || text(row.issue_class)],
    ['Fact kind', row.fact_kind_label || text(row.fact_kind)],
    ['Risk dimension', row.dimension_label || text(row.dimension)],
    ['Severity', row.severity_label || text(row.severity)],
    ['Status', row.status_label || text(row.status)],
    ['Evidence certainty', row.certainty_label || text(row.certainty)],
    ['Observability', row.observability_label || text(row.observability)],
    ['Protocol', row.protocol_label],
    ['Affected sessions', text(row.affected_sessions, '1')],
    ['Investigative priority', text(row.priority_score)],
    ['ML adjustment', text(row.ml_adjustment, '0'),
      'ordering only; cannot cross a severity tier'],
    ['Stream', text(row.stream_key, 'not recorded')],
    ['Frame references', row.frames_text],
    ['Rule ids', row.source_rule_ids.length
      ? row.source_rule_ids.join(' · ') : 'none recorded'],
  ]));

  if (row.conclusion) {
    body.appendChild(el('h3', { text: 'Conclusion' }));
    body.appendChild(el('p', { text: row.conclusion }));
  }
  if (row.explanation) {
    body.appendChild(el('h3', { text: 'Explanation' }));
    body.appendChild(el('p', { text: row.explanation }));
  }
  if (row.explanation_priority) {
    body.appendChild(el('h3', { text: 'Why this priority' }));
    body.appendChild(el('p', { text: row.explanation_priority }));
  }

  for (const contradiction of row.contradictions || []) {
    body.appendChild(notice(`Contradictory evidence recorded: ${contradiction}`));
  }

  if (row.citations && row.citations.length) {
    body.appendChild(el('h3', { text: 'Standards basis' }));
    body.appendChild(table('Standards cited by the rule that produced this finding',
      ['Standard', 'Section', 'Why it applies'],
      row.citations.map((c) => [c.standard, c.section || '—', c.reason || '—']),
      { wide: [2] }));
  }

  if (row.remediation) {
    const r = row.remediation;
    body.appendChild(el('h3', { text: 'Remediation' }));
    body.appendChild(facts([
      ['Observed', r.observed],
      ['Why it matters', r.why_it_matters],
      ['Recommended action', r.recommended_action],
      ['Affected scope', r.affected_scope],
      ['Verification', r.verification],
      ['Standards', (r.citations || []).map((c) => c.standard).join(' · ') || '—'],
    ]));
    for (const limitation of r.limitations || []) {
      body.appendChild(notice(limitation));
    }
    body.appendChild(notice('This system does not verify that remediation was '
      + 'performed or that it succeeded.'));
  }

  for (const limitation of row.limitations || []) {
    body.appendChild(notice(limitation));
  }
  return body;
}

function findingCard(row) {
  // <details> gives native keyboard operation and expanded state without ARIA
  // bookkeeping that could drift out of sync.
  const card = el('details', { className: 'finding' });
  const summary = el('summary');
  summary.appendChild(findingSummaryLine(row));
  card.appendChild(summary);
  card.appendChild(findingDetail(row));
  return card;
}

function filterControls(vm, state, runId, onChange) {
  const form = el('form', { className: 'filters', attrs: { role: 'search' } });
  form.addEventListener('submit', (event) => event.preventDefault());

  let any = false;
  for (const [facet, legend] of FACETS) {
    const options = (vm.filters && vm.filters[facet]) || [];
    if (!options.length) continue;
    any = true;
    const fieldset = el('fieldset', { className: 'facet' });
    fieldset.appendChild(el('legend', {
      text: options.length > 1 ? `${legend} (${options.length})` : legend,
    }));
    // High-cardinality facets — issue_class can have one value per finding — are
    // bounded and scrolled rather than truncated: every value stays reachable, but a
    // long facet must not push the findings themselves below the fold.
    const list = el('div', { className: 'facet-options' });
    for (const option of options) {
      const inputId = `f-${facet}-${option.value}`.replace(/[^A-Za-z0-9_-]/g, '_');
      const wrap = el('label', { className: 'facet-option', attrs: { for: inputId } });
      const input = el('input', {
        id: inputId,
        attrs: { type: 'checkbox', name: facet, value: option.value },
      });
      if (state[facet] && state[facet].has(option.value)) input.checked = true;
      input.addEventListener('change', () => {
        if (!state[facet]) state[facet] = new Set();
        if (input.checked) state[facet].add(option.value);
        else state[facet].delete(option.value);
        onChange();
      });
      wrap.appendChild(input);
      wrap.appendChild(el('span', { className: 'facet-label', text: option.label }));
      // Counts come from the projection and describe the whole assessment, not the
      // current selection — recomputing them here would be a second source of truth.
      wrap.appendChild(el('span', { className: 'facet-count', text: String(option.count) }));
      list.appendChild(wrap);
    }
    fieldset.appendChild(list);
    form.appendChild(fieldset);
  }
  if (!any) return null;
  return form;
}

export async function render(root, { runId }) {
  const vm = await cached(runId, () => getDashboard(runId));
  const state = stateFor(runId);

  const resultsHost = el('div', { className: 'results' });
  const statusLine = el('p', {
    className: 'result-count',
    attrs: { role: 'status', 'aria-live': 'polite' },
  });
  const activeHost = el('div', { className: 'active-filters' });

  const clearButton = el('button', {
    className: 'clear-filters',
    text: 'Clear all filters',
    attrs: { type: 'button' },
    onClick: () => {
      for (const key of Object.keys(state)) delete state[key];
      redraw();
      // Rebuild the controls so every checkbox reflects the cleared state.
      const fresh = filterControls(vm, state, runId, redraw);
      if (fresh && controlsHost.firstChild) {
        controlsHost.replaceChild(fresh, controlsHost.firstChild);
      }
    },
  });

  const controlsHost = el('div', { className: 'filter-host' });
  const controls = filterControls(vm, state, runId, redraw);
  if (controls) controlsHost.appendChild(controls);

  function redraw() {
    const visible = applyFilters(vm.findings, state);
    const active = activeCount(state);

    statusLine.textContent = active
      ? `Showing ${visible.length} of ${vm.findings.length} findings · `
        + `${active} filter${active === 1 ? '' : 's'} active`
      : `Showing all ${vm.findings.length} findings in canonical priority order`;

    mount(activeHost, active ? [clearButton] : []);

    if (!vm.findings.length) {
      mount(resultsHost, [el('div', { className: 'state-panel' }, [
        el('h3', { text: 'No findings' }),
        el('p', {
          text: 'The assessment produced no prioritised findings for this capture. '
            + 'That is not a statement that the infrastructure is secure — review the '
            + 'evidence coverage and abstentions to see what could and could not be '
            + 'assessed.',
        }),
      ])]);
      return;
    }
    if (!visible.length) {
      mount(resultsHost, [el('div', { className: 'state-panel' }, [
        el('h3', { text: 'No findings match these filters' }),
        el('p', {
          text: `This assessment has ${vm.findings.length} findings. None of them `
            + 'matches the current selection. Clearing the filters restores the full '
            + 'list in its canonical order.',
        }),
      ])]);
      return;
    }
    mount(resultsHost, visible.map(findingCard));
  }

  redraw();

  const blocks = [
    section('findings', 'Prioritised findings', [
      controlsHost,
      activeHost,
      statusLine,
      resultsHost,
    ], {
      lead: 'Ranked by the assessment. Severity states how serious a condition is; '
        + 'priority states the order in which to work. Filtering changes what is '
        + 'shown and never changes a finding.',
    }),
    notice('Findings are grouped by condition. Recurrence counts the sessions in '
      + 'which a condition was observed, so one misconfiguration seen many times is '
      + 'one finding with a recurrence count, not many findings.'),
  ];
  if (vm.unavailable && vm.unavailable.length) {
    const list = el('ul', { className: 'plain' });
    for (const item of vm.unavailable) list.appendChild(el('li', { text: item }));
    blocks.push(section('findings-unavailable', 'Not available at finding level',
      [list]));
  }
  mount(root, blocks);
}
