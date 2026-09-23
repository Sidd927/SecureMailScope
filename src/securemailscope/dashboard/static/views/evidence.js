/**
 * Evidence & provenance — why the system says this, and what it could not determine
 * (doc 23 §7 Screen 4).
 *
 * This is the screen where the product's honesty is most visible, so it is the screen
 * least allowed to smooth anything over. It renders what the assessment recorded and
 * states plainly what the canonical contract does not contain.
 *
 * Specifically it does NOT:
 *   - rewrite `resolved_by` guidance into new security advice;
 *   - invent a standards mapping, including for `unmapped_citations`, which is a gap
 *     the engine reports about itself and is shown rather than hidden;
 *   - fabricate packet drill-down, a session timeline or per-session finding rows,
 *     none of which exist in `to_dict()`;
 *   - present an absent observation as a reassuring one.
 */
import { getDashboard, listArtifacts } from '../api.js';
import { el, facts, mount, notice, section, table, text } from '../dom.js';
import { cached } from '../app.js';

/** Evidence states, ordered so the confident ones do not bury the uncertain ones. */
const STATE_ORDER = ['OBSERVED', 'INFERRED', 'AMBIGUOUS', 'INCOMPLETE', 'UNKNOWN',
  'NOT_OBSERVABLE'];

/**
 * The two clusters the six states fall into. This is a presentation grouping only —
 * the underlying vocabulary, its spelling and its six-way distinction are unchanged.
 * A state this build does not recognise is grouped with the uncertain cluster: an
 * unrecognised reading is definitionally not a settled one.
 */
const ESTABLISHED_STATES = ['OBSERVED', 'INFERRED'];
const UNCERTAIN_STATES = ['AMBIGUOUS', 'INCOMPLETE', 'UNKNOWN', 'NOT_OBSERVABLE'];

/** What each evidence state means. Project vocabulary, not new security advice. */
const STATE_MEANING = {
  OBSERVED: 'directly present in the captured bytes',
  INFERRED: 'derived from what was observed, not read directly',
  AMBIGUOUS: 'more than one reading remains possible',
  INCOMPLETE: 'the capture did not contain the whole exchange',
  UNKNOWN: 'not determined from this capture',
  NOT_OBSERVABLE: 'structurally impossible to see from a passive capture',
};

/** One evidence-state table's rows. `names` with no observation still get a row: the
 * six-state vocabulary is a fixed set, and silently dropping the ones that did not
 * occur would make it look smaller than it is. */
function stateRows(names, counts, fractions) {
  return names.map((name) => [
    el('span', { className: 'state-chip', text: name.replace(/_/g, ' ') }),
    STATE_MEANING[name] || 'a state this console version does not recognise',
    counts[name] === undefined
      ? el('span', { className: 'muted', text: 'none recorded' })
      : String(counts[name]),
    fractions[name] === undefined ? '—' : `${(fractions[name] * 100).toFixed(1)}%`,
  ]);
}

/**
 * Evidence states actually recorded, with their counts and shares — grouped into what
 * was established and what could not be, because that distinction is the product's
 * core claim and deserves to be visible before the reader parses six rows of a flat
 * table to find it.
 */
function evidencePanel(vm) {
  const c = vm.coverage;
  const children = [];

  if (!c.present) {
    children.push(notice('This assessment carries no coverage information, so the '
      + 'distribution of evidence states is not available.'));
    return section('evidence-states', 'Evidence status', children, {
      lead: 'How the individual observations behind this assessment were classified.',
    });
  }

  const counts = c.observation_counts || {};
  const fractions = c.observation_fractions || {};
  // Any state the engine emits that this build does not know is appended to the
  // uncertain cluster, so a future addition is displayed rather than discarded.
  const extra = Object.keys(counts).filter((n) => STATE_ORDER.indexOf(n) === -1)
    .sort((a, b) => a.localeCompare(b));

  children.push(facts([
    ['Sessions total', text(c.sessions_total, '0')],
    ['Sessions assessed', text(c.sessions_assessed, '0')],
    ['Sessions abstained', text(c.sessions_abstained, '0')],
    ['Assessed fraction', c.percent_text],
  ]));

  children.push(el('h3', { text: 'What was established' }));
  children.push(table(
    'Evidence states that reached a definite reading',
    ['Evidence state', 'Meaning', 'Count', 'Share'],
    stateRows(ESTABLISHED_STATES, counts, fractions),
    { wide: [1], empty: 'None recorded.' }));

  children.push(el('h3', { text: 'What could not be established' }));
  children.push(table(
    'Evidence states that could not settle a reading',
    ['Evidence state', 'Meaning', 'Count', 'Share'],
    stateRows(UNCERTAIN_STATES.concat(extra), counts, fractions),
    { wide: [1], empty: 'None recorded.' }));

  const completeness = c.completeness_counts || {};
  if (Object.keys(completeness).length) {
    children.push(table('Session completeness', ['Completeness', 'Sessions'],
      Object.entries(completeness).sort((a, b) => a[0].localeCompare(b[0]))
        .map(([k, v]) => [k.replace(/_/g, ' '), String(v)]),
      { empty: '' }));
  }

  children.push(notice('These six states are kept distinct on purpose. '
    + 'NOT OBSERVABLE, AMBIGUOUS and UNKNOWN are three different reasons for not '
    + 'knowing something, and none of them is evidence that a thing is safe.'));
  return section('evidence-states', 'Evidence status', children, {
    lead: 'How the individual observations behind this assessment were classified.',
  });
}

/** Abstentions: what was declined, why, and what would settle it. */
function abstentionPanel(vm) {
  const rows = vm.abstentions || [];
  if (!rows.length) {
    return section('abstentions', 'Abstentions', [
      el('p', {
        text: 'The assessment recorded no abstentions. Every question the rule set '
          + 'asked of this capture could be answered from the available evidence.',
      }),
    ], { lead: 'Questions the assessment declined to answer.' });
  }

  return section('abstentions', 'Abstentions', [
    table(`${rows.length} abstention(s)`,
      ['Reason', 'Issue class', 'Could not conclude', 'Why', 'Would be resolved by',
        'Protocol', 'Frames'],
      rows.map((a) => [
        a.reason_label || text(a.reason),
        a.issue_class_label || text(a.issue_class, '—'),
        text(a.what_could_not_be_concluded, '—'),
        text(a.why, '—'),
        text(a.resolved_by, '—'),
        a.protocol_label,
        a.frames && a.frames.length ? a.frames.join(', ') : 'none recorded',
      ]),
      { wide: [2, 3, 4] }),
    notice('An abstention is neither a failure nor a pass. It records that the '
      + 'evidence did not support a conclusion. Treating any row above as compliant, '
      + 'or as a detected problem, misreads it.'),
  ], {
    lead: 'What the assessment declined to conclude, why, and what evidence would '
      + 'settle it. The resolution guidance is the assessment\'s own wording.',
  });
}

/** Standards actually cited, plus the citations the registry could not map. */
function standardsPanel(vm) {
  const s = vm.standards;
  if (!s || !s.present) {
    return section('standards', 'Standards basis', [
      el('p', { text: 'This assessment recorded no standards summary.' }),
    ]);
  }
  const children = [];
  if (s.distinct_standards !== null && s.distinct_standards !== undefined) {
    children.push(facts([['Distinct standards cited', String(s.distinct_standards)]]));
  }
  children.push(table('Standards cited by the rules that produced these findings',
    ['Standard', 'Sections'],
    (s.standards || []).map((row) => [
      row.standard,
      row.sections && row.sections.length ? row.sections.join(' · ') : '—',
    ]),
    { empty: 'No standards were cited by this assessment.' }));

  if (s.unmapped_citations && s.unmapped_citations.length) {
    children.push(el('h3', { text: 'Unmapped citations' }));
    children.push(el('p', {
      text: 'The engine cited these but its standards registry could not map them to '
        + 'a structured entry. They are shown because a gap the system reports about '
        + 'itself is evidence, and suppressing it would make the coverage above look '
        + 'more complete than it is.',
    }));
    const list = el('ul', { className: 'plain' });
    for (const item of s.unmapped_citations) list.appendChild(el('li', { text: item }));
    children.push(list);
  }

  if (s.note) children.push(el('p', { className: 'lead', text: s.note }));
  children.push(notice('A standard appearing here means a rule cited it as the basis '
    + 'for an observation. It is not a statement of compliance or certification '
    + 'against that standard.'));
  return section('standards', 'Standards basis', children, {
    lead: 'The published specifications the findings are grounded in.',
  });
}

/** Provenance: identity, versions, rules that ran, source counts. */
/**
 * The pipeline shape, as a short fixed rail: six static labels, not a data binding.
 * The tables that follow are the same provenance detail this screen has always shown;
 * this is only a visual anchor so the detail reads as a trail rather than a
 * spreadsheet. Never labelled "chain of custody" — that is a forensic-legal term this
 * product does not claim.
 */
function provenanceRail() {
  const rail = el('ol', { className: 'rail' });
  for (const step of ['Capture', 'Frame / stream', 'Evidence', 'Finding', 'Posture',
    'Report']) {
    rail.appendChild(el('li', { className: 'rail-step', text: step }));
  }
  return rail;
}

function provenancePanel(vm) {
  const id = vm.identity;
  const p = vm.provenance || { rule_ids: [], source_counts: {}, entries: {} };
  const children = [
    el('p', {
      className: 'rail-caption',
      text: 'The path from bytes to conclusion, for every finding on this assessment:',
    }),
    provenanceRail(),
    facts([
    ['Assessment ID', id.assessment_id],
    ['Capture ID (SHA-256)', id.capture_id],
    ['Run ID', text(id.run_id, 'not recorded')],
    ['Analysed at', id.generated_at, 'time of analysis, not of viewing'],
    ['Posture schema', id.posture_schema_version],
    ['Posture engine', id.posture_engine_version],
    ['Dashboard schema', id.dashboard_schema_version],
    ['Projection version', id.projection_version],
    ['ML lane', id.ai_enabled ? 'Enabled' : 'Disabled'],
  ])];

  if (p.rule_ids && p.rule_ids.length) {
    children.push(el('h3', { text: 'Rules that examined this capture' }));
    const list = el('ul', { className: 'plain mono-list' });
    for (const ruleId of p.rule_ids) list.appendChild(el('li', { text: ruleId }));
    children.push(list);
  }

  const counts = Object.entries(p.source_counts || {});
  if (counts.length) {
    children.push(table('Inputs to the posture engine', ['Source', 'Count'],
      counts.sort((a, b) => a[0].localeCompare(b[0]))
        .map(([k, v]) => [k.replace(/_/g, ' '), String(v)]),
      { empty: '' }));
  }

  const entries = Object.entries(p.entries || {});
  if (entries.length) {
    children.push(table('Engine provenance', ['Item', 'Value'],
      entries.sort((a, b) => a[0].localeCompare(b[0])).map(([k, v]) => [
        k.replace(/_/g, ' '),
        typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v),
      ]),
      { wide: [1], empty: '' }));
  }

  if (p.note) children.push(el('p', { className: 'lead', text: p.note }));
  children.push(el('p', {
    text: 'Every conclusion in this assessment traces to specific frames in the '
      + 'capture, to the rule that examined them, and to the standard that rule '
      + 'cited. The capture ID above is the SHA-256 of the analysed bytes; a capture '
      + 'that hashes differently is a different capture and this assessment does not '
      + 'describe it.',
  }));
  return section('provenance', 'Provenance', children, {
    lead: 'What was analysed, by which engine, and on what basis.',
  });
}

/** Stored artifacts with their recorded hashes and verified integrity. */
function artifactPanel(artifacts, error) {
  if (error) {
    return section('artifacts', 'Artifact integrity', [
      notice('Artifact integrity could not be retrieved for this run. The assessment '
        + 'itself is unaffected.'),
    ]);
  }
  const items = (artifacts && artifacts.items) || [];
  if (!items.length) {
    return section('artifacts', 'Artifact integrity', [
      el('p', { text: 'No artifacts are recorded for this run.' }),
    ]);
  }
  return section('artifacts', 'Artifact integrity', [
    table('Stored artifacts, re-hashed on request',
      ['Kind', 'SHA-256', 'Size (bytes)', 'Created', 'Integrity', 'Original name'],
      items.map((a) => [
        text(a.kind),
        el('span', { className: 'mono', text: text(a.sha256) }),
        text(a.size_bytes),
        text(a.created_at),
        text(a.integrity, 'not checked'),
        text(a.original_filename, '—'),
      ]),
      { wide: [1] }),
    notice('Integrity is established by re-reading each stored artifact and '
      + 're-computing its SHA-256. A file that no longer matches its recorded hash is '
      + 'reported as a mismatch rather than served as intact.'),
  ], { lead: 'The stored bytes behind this analysis, and whether they still match.' });
}

/** What the canonical contract does not contain. Stated, never approximated. */
function unavailablePanel(vm) {
  const list = el('ul', { className: 'plain' });
  for (const item of vm.unavailable || []) {
    list.appendChild(el('li', { text: item }));
  }
  list.appendChild(el('li', {
    text: 'Session timelines: the assessment records which sessions were affected and '
      + 'which frames a finding cites, but not an ordered per-session event trace.',
  }));
  return section('unavailable', 'What this console cannot show', [
    el('p', {
      text: 'These are absences in the canonical assessment, not omissions in this '
        + 'view. The console shows them rather than approximating them, because an '
        + 'approximation here would be indistinguishable from evidence.',
    }),
    list,
    el('p', {
      text: 'Where deeper detail exists it is in the forensic report, which carries '
        + 'the same canonical assessment in full.',
    }),
  ], { lead: 'Evidence the canonical contract does not carry.' });
}

function limitationsPanel(vm) {
  const children = [];
  for (const item of vm.notices || []) {
    children.push(notice(item, vm.posture.withheld ? 'withheld' : ''));
  }
  if (!vm.limitations || !vm.limitations.length) {
    children.push(notice('This assessment carries no recorded limitations. That is '
      + 'unusual and should be verified against the engine version that produced it.'));
  } else {
    for (const item of vm.limitations) children.push(notice(item));
  }
  return section('limitations', 'Assessment limitations', children, {
    lead: 'Constraints that bound what this assessment can support. These are the '
      + 'engine\'s own words and are not summarised here.',
  });
}

export async function render(root, { runId }) {
  const vm = await cached(runId, () => getDashboard(runId));

  // Artifact integrity is a separate call; its failure must not take the screen down.
  let artifacts = null;
  let artifactError = null;
  try {
    artifacts = await listArtifacts(runId, { verify: true });
  } catch (error) {
    artifactError = error;
  }

  mount(root, [
    evidencePanel(vm),
    abstentionPanel(vm),
    limitationsPanel(vm),
    standardsPanel(vm),
    provenancePanel(vm),
    artifactPanel(artifacts, artifactError),
    unavailablePanel(vm),
  ]);
}
