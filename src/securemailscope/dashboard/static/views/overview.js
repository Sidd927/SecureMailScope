/**
 * Overview — what was found, how strong the evidence is, what to inspect next
 * (doc 23 §7 Screen 2).
 *
 * Consumes the `DashboardViewModel` produced by the Python projection. It performs no
 * security calculation of its own: every severity, band, score, count and ML statement
 * on this screen arrived already decided. Nothing here thresholds, buckets or infers.
 *
 * The one rule the layout itself enforces: posture and coverage are rendered in a
 * single block that cannot be separated. A band shown without the evidence coverage
 * that qualifies it is the misleading claim ADR-0016 §4 exists to prevent.
 */
import { getDashboard, reportUrl } from '../api.js';
import {
  bar, chip, el, facts, mount, notice, section, table, text,
} from '../dom.js';
import { cached } from '../app.js';

const TOP_FINDINGS = 5;

/** Identity + lifecycle. Answers "which assessment am I looking at?". */
function identityPanel(vm, run) {
  const id = vm.identity;
  const rows = [
    ['Capture file', run ? text(run.source_filename, '—') : '—'],
    ['Analysis state', run ? text(run.state, '—') : '—'],
    ['Assessment ID', id.assessment_id],
    ['Capture ID (SHA-256)', id.capture_id],
    ['Run ID', text(id.run_id, 'not recorded')],
    ['Analysed at', id.generated_at, 'time of analysis, not of viewing'],
    ['Engine', `posture ${id.posture_engine_version} · schema ${id.posture_schema_version}`],
    ['ML lane', id.ai_enabled ? 'Enabled' : 'Disabled'],
  ];
  if (run && run.duration_ms !== null && run.duration_ms !== undefined) {
    rows.push(['Analysis duration', `${run.duration_ms} ms`]);
  }
  return section('identity', 'Analysis', [facts(rows)], {
    lead: 'What was analysed, by which engine version.',
  });
}

/**
 * The verdict block. Posture, score and coverage sit together by construction —
 * there is no arrangement of this function that renders one without the others.
 */
function verdictPanel(vm) {
  const grid = el('div', { className: 'verdict' });

  const postureCell = el('div', {}, [
    el('div', { className: 'k', text: 'Overall posture' }),
    el('div', { className: 'v' }, [chip(vm.posture.label, vm.posture.tone, null)]),
  ]);
  if (vm.posture.withheld) {
    postureCell.appendChild(el('div', { className: 'note', text: vm.posture.withheld_note }));
  }
  if (!vm.posture.known) {
    postureCell.appendChild(el('div', {
      className: 'note',
      text: 'This posture value is not recognised by this console version and is '
        + 'shown exactly as recorded.',
    }));
  }
  grid.appendChild(postureCell);

  grid.appendChild(el('div', {}, [
    el('div', { className: 'k', text: 'Posture score' }),
    el('div', { className: 'v small', text: vm.posture.score_text }),
    vm.posture.formula_id
      ? el('div', { className: 'note', text: vm.posture.formula_id }) : null,
  ]));

  grid.appendChild(el('div', {}, [
    el('div', { className: 'k', text: 'Evidence coverage' }),
    el('div', { className: 'v small', text: vm.coverage.summary_text }),
    vm.coverage.present
      ? null
      : el('div', { className: 'note', text: 'no coverage recorded' }),
  ]));

  grid.appendChild(el('div', {}, [
    el('div', { className: 'k', text: 'Abstentions' }),
    el('div', { className: 'v small', text: String(vm.abstentions.length) }),
    el('div', { className: 'note', text: 'questions declined' }),
  ]));

  return grid;
}

/** Score decomposition — the assessment's own components, never recomputed. */
function scorePanel(vm) {
  const children = [];
  if (vm.posture.basis) {
    children.push(el('p', { text: vm.posture.basis }));
  }
  if (vm.posture.components.length) {
    children.push(table(
      'Score decomposition',
      ['Issue class', 'Severity', 'Recurrence', 'Weight', 'Multiplier', 'Penalty'],
      vm.posture.components.map((c) => [
        c.issue_class_label,
        chip(c.severity_label, c.severity ? c.severity.toLowerCase() : 'unknown', null),
        text(c.recurrence),
        text(c.base_weight),
        text(c.recurrence_multiplier),
        c.penalty === null || c.penalty === undefined ? '—' : `-${c.penalty}`,
      ]),
      { empty: 'No penalties were applied.' }));
    children.push(el('p', {
      text: `The score starts at ${text(vm.posture.starting_value, '100')} and each `
        + 'penalty above is subtracted. Only observed issues penalise; compliant '
        + 'observations earn no credit, and missing evidence neither penalises nor '
        + 'rewards.',
    }));
  }
  children.push(notice(
    'The severity weights and band thresholds behind this score are transparent '
    + 'engineering policy, not a calibrated measurement derived from incident data.'));
  return section('score', 'Posture score', children, {
    lead: 'How the score was arrived at.',
  });
}

/** Coverage detail. Absence of coverage is a statement, not an empty panel. */
function coveragePanel(vm) {
  const c = vm.coverage;
  if (!c.present) {
    return section('coverage', 'Evidence coverage', [
      notice('This assessment carries no coverage information. A posture claim cannot '
        + 'be qualified without it and should be treated with corresponding caution.'),
    ]);
  }
  const children = [facts([
    ['Sessions total', text(c.sessions_total, '0')],
    ['Sessions assessed', text(c.sessions_assessed, '0')],
    ['Sessions abstained', text(c.sessions_abstained, '0')],
    ['Assessed fraction', c.percent_text],
  ])];

  const states = Object.entries(c.observation_counts || {});
  if (states.length) {
    children.push(table(
      'Evidence states observed across all fields',
      ['Evidence state', 'Count', 'Share'],
      states.sort((a, b) => a[0].localeCompare(b[0])).map(([state, count]) => [
        state.replace(/_/g, ' '),
        String(count),
        c.observation_fractions && c.observation_fractions[state] !== undefined
          ? `${(c.observation_fractions[state] * 100).toFixed(1)}%` : '—',
      ]),
      { empty: 'No evidence-state counts recorded.' }));
  }
  children.push(el('p', {
    text: 'Coverage is reported beside the posture score and is never folded into it. '
      + 'A score computed over a small share of the traffic and the same score computed '
      + 'over nearly all of it are different claims.',
  }));
  return section('coverage', 'Evidence coverage', children, {
    lead: 'How much of the captured traffic the analysis could actually assess.',
  });
}

/**
 * Per-protocol posture. `dimensions_not_observable` is shown beside
 * `dimensions_assessed` so "no issue found" is never mistaken for "secure".
 */
function protocolPanel(vm) {
  if (!vm.protocols.length) return null;
  const rows = vm.protocols.map((p) => [
    p.protocol,
    text(p.sessions),
    chip(p.band_label, p.band_tone, null),
    p.score_text,
    p.dimensions_assessed.length
      ? p.dimensions_assessed.map((d) => d.replace(/_/g, ' ')).join(' · ')
      : 'none recorded',
    p.dimensions_not_observable.length
      ? p.dimensions_not_observable.map((d) => d.replace(/_/g, ' ')).join(' · ')
      : 'none',
    text(p.abstentions, '0'),
  ]);
  return section('protocols', 'Protocol posture', [
    table('Posture per protocol',
      ['Protocol', 'Sessions', 'Band', 'Score', 'Dimensions assessed',
        'Not observable', 'Abstentions'],
      rows, { wide: [4, 5], empty: 'No per-protocol posture recorded.' }),
    notice('A dimension listed as not observable was not assessed. Absence of an '
      + 'observed issue is not evidence that a protocol is secure.'),
  ], { lead: 'Posture per protocol, across the dimensions the evidence supports.' });
}

/** Distributions. Every bar prints its own number. */
function distributionPanel(vm) {
  if (!vm.distributions.length) return null;
  const children = [];
  for (const dist of vm.distributions) {
    children.push(el('h3', { text: dist.caption }));
    if (dist.note) children.push(el('p', { className: 'lead', text: dist.note }));
    const wrap = el('div', { className: 'bars' });
    for (const item of dist.bars) wrap.appendChild(bar(item));
    children.push(wrap);
  }
  return section('distributions', 'Finding distributions', children, {
    lead: 'Counts recorded by the assessment. No proportion here is derived.',
  });
}

/** Top prioritised findings, in canonical rank order. No sort is applied. */
function findingsPanel(vm, runId) {
  if (!vm.findings.length) {
    return section('top-findings', 'Prioritised findings', [
      el('div', { className: 'state-panel' }, [
        el('h2', { text: 'No prioritised findings' }),
        el('p', {
          text: 'The assessment produced no prioritised findings for this capture. '
            + 'That is not a statement that the infrastructure is secure — review the '
            + 'evidence coverage and abstentions above to see what could and could not '
            + 'be assessed.',
        }),
      ]),
    ]);
  }

  const shown = vm.findings.slice(0, TOP_FINDINGS);
  const rows = shown.map((f) => [
    text(f.rank),
    chip(f.severity_label, f.severity_tone, f.severity_marker),
    f.title || f.issue_class_label,
    f.status_label || '—',
    f.certainty_label || '—',
    f.observability_label || '—',
    f.protocol_label,
    text(f.affected_sessions, '1'),
  ]);

  const children = [
    table(`Top ${shown.length} of ${vm.findings.length} in investigative priority order`,
      ['Rank', 'Severity', 'Issue', 'Status', 'Certainty', 'Observability',
        'Protocol', 'Sessions'],
      rows, { wide: [2] }),
    el('p', {
      text: 'Severity states how serious a condition is. Priority states the order in '
        + 'which an analyst should work. They are different questions and are shown '
        + 'as different columns.',
    }),
  ];
  if (vm.findings.length > TOP_FINDINGS) {
    children.push(el('p', {}, [
      el('a', {
        text: `View all ${vm.findings.length} findings →`,
        attrs: { href: `#/run/${runId}/findings` },
      }),
    ]));
  }
  return section('top-findings', 'Prioritised findings', children, {
    lead: 'What the assessment ranked as most worth an analyst\'s attention.',
  });
}

/**
 * ML transparency. Renders `model_summary.role` and its limitations verbatim and
 * states the boundary. It never describes the lane as detecting anything.
 */
function mlPanel(vm) {
  const ml = vm.ml;
  const children = [];
  if (!ml.enabled) {
    children.push(facts([['ML lane', 'Disabled']]));
    children.push(el('p', {
      text: ml.note || 'The machine-learning lane was not used. Every conclusion in '
        + 'this assessment comes from deterministic rules and cross-session reasoning.',
    }));
    return section('ml', 'AI / ML transparency', children, {
      lead: 'What the machine-learning lane did, and what it is not permitted to do.',
    });
  }

  const rows = [['ML lane', 'Enabled']];
  if (ml.role) rows.push(['Role', ml.role]);
  for (const [key, value] of Object.entries(ml.facts || {})) {
    if (value === null || value === undefined) continue;
    if (typeof value === 'object') continue;
    rows.push([key.replace(/_/g, ' ').replace(/^./, (m) => m.toUpperCase()),
      String(value)]);
  }
  children.push(facts(rows));
  children.push(el('p', { text: ml.boundary_statement }));
  for (const limitation of ml.limitations || []) {
    children.push(notice(limitation));
  }
  return section('ml', 'AI / ML transparency', children, {
    lead: 'What the machine-learning lane did, and what it is not permitted to do.',
  });
}

/** Report actions. Every href is built from a validated run id + fixed allowlist. */
function reportPanel(runId) {
  const actions = el('div', { className: 'actions' });
  const items = [
    ['html', 'View HTML report', 'opens the standalone forensic report'],
    ['pdf', 'Download PDF report', 'a real, paginated PDF'],
    ['json', 'Download canonical JSON', 'the assessment exactly as stored'],
  ];
  for (const [format, label, hint] of items) {
    const a = el('a', {
      className: 'action',
      text: label,
      attrs: { href: reportUrl(runId, format) },
    });
    if (format !== 'html') a.setAttribute('download', '');
    const wrap = el('div', { className: 'action-wrap' }, [a,
      el('span', { className: 'note', text: hint })]);
    actions.appendChild(wrap);
  }
  return section('reports', 'Reports', [
    actions,
    el('p', {
      text: 'Reports render the same canonical assessment shown on this screen. The '
        + 'console does not generate them; it links to the reporting API.',
    }),
  ], { lead: 'Export this assessment for review or archival.' });
}

/** Notices and limitations — the parts a reader must not skim past. */
function limitationsPanel(vm) {
  const children = [];
  for (const item of vm.notices) {
    children.push(notice(item, vm.posture.withheld ? 'withheld' : ''));
  }
  for (const item of vm.limitations) children.push(notice(item));
  if (vm.unavailable.length) {
    const list = el('ul', { className: 'plain' });
    for (const item of vm.unavailable) list.appendChild(el('li', { text: item }));
    children.push(el('h3', { text: 'Not available from this assessment' }));
    children.push(list);
  }
  if (!children.length) return null;
  return section('limitations', 'Limitations', children, {
    lead: 'Constraints that bound what this assessment can support.',
  });
}

export async function render(root, { runId }) {
  const vm = await cached(runId, () => getDashboard(runId));
  let run = null;
  try {
    const { getRun } = await import('../api.js');
    run = await getRun(runId);
  } catch (error) {
    run = null;           // identity still renders from the assessment itself
  }

  const blocks = [
    identityPanel(vm, run),
    verdictPanel(vm),
  ];
  // Withheld verdicts and absent coverage are surfaced immediately under the block
  // they qualify, not at the bottom of the page.
  for (const item of vm.notices) {
    blocks.push(notice(item, vm.posture.withheld ? 'withheld' : ''));
  }
  blocks.push(
    scorePanel(vm),
    coveragePanel(vm),
    protocolPanel(vm),
    distributionPanel(vm),
    findingsPanel(vm, runId),
    mlPanel(vm),
    reportPanel(runId),
    limitationsPanel(vm),
  );
  mount(root, blocks);
}
