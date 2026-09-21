/**
 * Finding filter logic (doc 23 §7 Screen 3).
 *
 * Deliberately free of DOM imports so it is a pure function of (findings, selections)
 * and can be executed directly by a test runner against real view-model data. Logic
 * that decides what an analyst sees should be testable without a browser.
 *
 * The invariants this module exists to hold:
 *
 *   - `findings` is never mutated and never sorted. `Array.prototype.filter` preserves
 *     source order, so clearing every selection reproduces canonical rank order.
 *   - A finding whose canonical `protocol` is null is matched through `protocol_key`,
 *     which is never null, so an anomaly signal cannot be hidden by a protocol filter.
 *   - An unknown or future enum value is matched by its own string. It is never mapped
 *     to a default and therefore never silently disappears.
 *   - Nothing here reads or writes severity, status or any other security value.
 */

/** Facets the projection provides, in the order an analyst tends to reach for. */
export const FACETS = [
  ['severity', 'Severity'],
  ['status', 'Status'],
  ['certainty', 'Certainty'],
  ['observability', 'Observability'],
  ['fact_kind', 'Fact kind'],
  ['dimension', 'Dimension'],
  ['protocol', 'Protocol'],
  ['issue_class', 'Issue class'],
];

/** The finding attribute each facet tests. `protocol` uses the never-null key. */
export const FIELD = {
  severity: 'severity',
  status: 'status',
  certainty: 'certainty',
  observability: 'observability',
  fact_kind: 'fact_kind',
  dimension: 'dimension',
  protocol: 'protocol_key',
  issue_class: 'issue_class',
};

/** Selections may be Sets (live UI) or arrays (tests, restored state). */
function has(chosen, value) {
  if (!chosen) return false;
  if (typeof chosen.has === 'function') return chosen.has(value);
  return Array.isArray(chosen) && chosen.indexOf(value) !== -1;
}

function size(chosen) {
  if (!chosen) return 0;
  if (typeof chosen.size === 'number') return chosen.size;
  return Array.isArray(chosen) ? chosen.length : 0;
}

export function activeCount(state) {
  return FACETS.reduce((n, [facet]) => n + size(state[facet]), 0);
}

/**
 * Apply selections. Returns a NEW array; the input is untouched.
 * Within a facet the test is OR; across facets it is AND. A facet with nothing
 * selected does not constrain.
 */
export function applyFilters(findings, state) {
  const selections = state || {};
  return findings.filter((row) => FACETS.every(([facet]) => {
    const chosen = selections[facet];
    if (size(chosen) === 0) return true;
    const value = row[FIELD[facet]];
    return has(chosen, value === null || value === undefined ? '' : String(value));
  }));
}
