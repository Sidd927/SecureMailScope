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
import { getDashboard, getRun, reportUrl } from '../api.js';
import {
  bar, chip, el, facts, mount, notice, sanitiseTone, section, table, text,
} from '../dom.js';
import { cached } from '../app.js';

const TOP_FINDINGS = 5;

/**
 * Which capture, which protocols, when, how long. This line sits directly under the
 * page's own heading (the capture filename, rendered by `section()`), so it carries
 * only the supporting facts — not a second restatement of what was analysed.
 *
 * Every value is either the run record or the assessment's own identity block. The
 * protocol list is the assessment's per-protocol posture read back as names — it is
 * not inferred from anything.
 */
function resultMeta(vm, run) {
  const id = vm.identity;
  const meta = [];
  const protocols = vm.protocols.map((p) => p.protocol).join(' · ');
  if (protocols) meta.push(protocols);
  if (vm.coverage.present && vm.coverage.sessions_total !== null) {
    meta.push(`${vm.coverage.sessions_total} session(s)`);
  }
  meta.push(`analysed ${text(id.generated_at, 'time not recorded')}`);
  if (run && run.duration_ms !== null && run.duration_ms !== undefined) {
    meta.push(`${run.duration_ms} ms`);
  }
  meta.push(id.ai_enabled ? 'ML lane on' : 'ML lane off');
  return el('p', { className: 'result-meta', text: meta.join('  ·  ') });
}

/**
 * The verdict. One typographic headline — the posture band — and nothing else on this
 * screen is allowed to compete with it in size. Score and coverage are a single
 * subline underneath it, never a separate box: a band shown without the coverage that
 * qualifies it is the misleading claim ADR-0016 §4 exists to prevent, so there is no
 * arrangement of this function that can render one without the other.
 *
 * `tone` reaches a class only through `sanitiseTone`, and the band itself is always
 * spelled out, so the result survives greyscale and colour blindness intact.
 */
function verdictPanel(vm, runId) {
  const wrap = el('div', { className: 'verdict' });

  wrap.appendChild(el('p', { className: 'posture-eyebrow', text: 'Security posture' }));
  wrap.appendChild(el('p', {
    className: `posture-display tone-${sanitiseTone(vm.posture.tone)}`,
    text: vm.posture.label,
  }));

  // score_text and summary_text are both self-contained ("88 / 100", "100.0% (1 of 1
  // sessions assessed)") — concatenating them with the raw percentage as well would
  // repeat the coverage figure twice in one sentence.
  const subParts = [vm.posture.score_text];
  subParts.push(vm.coverage.present
    ? `evidence coverage ${vm.coverage.summary_text}` : 'evidence coverage not recorded');
  wrap.appendChild(el('p', { className: 'posture-subline', text: subParts.join(' · ') }));

  if (vm.posture.withheld) {
    wrap.appendChild(el('p', { className: 'posture-note', text: vm.posture.withheld_note }));
  }
  if (!vm.posture.known) {
    wrap.appendChild(el('p', {
      className: 'posture-note',
      text: 'This posture value is not recognised by this console version and is '
        + 'shown exactly as recorded.',
    }));
  }
  wrap.appendChild(el('p', {
    className: 'posture-guarantee',
    text: 'Missing evidence never improves this score.',
  }));

  wrap.appendChild(heroActions(vm, runId));
  return wrap;
}

/**
 * What to do next: inspect the findings, or read the evidence behind them. Export
 * lives in the persistent tab-bar control now (reachable from every tab, not just this
 * one) — this row is investigation, not output.
 */
function heroActions(vm, runId) {
  const row = el('div', { className: 'hero-actions' });
  row.appendChild(el('a', {
    className: 'btn btn-primary',
    text: vm.findings.length
      ? `Inspect ${vm.findings.length} finding(s)` : 'Open findings',
    attrs: { href: `#/run/${runId}/findings` },
  }));
  row.appendChild(el('a', {
    className: 'btn',
    text: 'Evidence & provenance',
    attrs: { href: `#/run/${runId}/evidence` },
  }));
  return row;
}

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
  return section('identity', 'Analysis identity', [facts(rows)], {
    lead: 'What was analysed, by which engine version.',
  });
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
  const heading = vm.findings.length
    ? `Prioritised findings (${vm.findings.length})` : 'Prioritised findings';
  if (!vm.findings.length) {
    return section('top-findings', heading, [
      el('div', { className: 'state-panel' }, [
        el('h3', { text: 'No prioritised findings' }),
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
  return section('top-findings', heading, children, {
    lead: 'What the assessment ranked as most worth an analyst\'s attention.',
  });
}

/**
 * What could not be determined.
 *
 * The product's distinguishing claim, so it gets its own place on the headline screen
 * rather than being buried. Every row is the assessment's own wording: the reason, the
 * question it declined, and what would settle it. Nothing here is styled as a severity,
 * because an abstention is not one.
 */
function abstentionPanel(vm, runId) {
  const rows = vm.abstentions || [];
  const heading = rows.length
    ? `What could not be determined (${rows.length})` : 'What could not be determined';
  if (!rows.length) {
    return section('not-concluded', heading, [
      el('p', {
        text: 'The assessment recorded no abstentions: every question its rules asked '
          + 'of this capture could be answered from the available evidence.',
      }),
    ], { lead: 'Questions the assessment declined to answer, and why.' });
  }

  const list = el('div', { className: 'abstention-list' });
  for (const row of rows.slice(0, TOP_FINDINGS)) {
    const card = el('div', { className: 'abstention' });
    card.appendChild(el('div', { className: 'abstention-head' }, [
      el('span', { className: 'state-chip', text: row.reason_label || text(row.reason) }),
      el('span', {
        className: 'abstention-title',
        text: row.what_could_not_be_concluded || row.issue_class_label
          || 'Not recorded',
      }),
      el('span', { className: 'abstention-proto', text: row.protocol_label }),
    ]));
    if (row.why) {
      card.appendChild(el('p', { className: 'abstention-why', text: row.why }));
    }
    if (row.resolved_by) {
      card.appendChild(el('p', { className: 'abstention-fix' }, [
        el('span', { className: 'abstention-fix-k', text: 'Would be settled by: ' }),
        document.createTextNode(row.resolved_by),
      ]));
    }
    list.appendChild(card);
  }

  const children = [list];
  if (rows.length > TOP_FINDINGS) {
    children.push(el('p', {}, [
      el('a', {
        text: `View all ${rows.length} abstention(s) →`,
        attrs: { href: `#/run/${runId}/evidence` },
      }),
    ]));
  }
  children.push(notice('An abstention is neither a pass nor a failure. It records '
    + 'that the evidence did not support a conclusion, so nothing above may be read '
    + 'as compliant or as a detected problem.'));
  return section('not-concluded', heading, children, {
    lead: 'Questions the assessment declined to answer, why, and what evidence would '
      + 'settle them.',
  });
}

/**
 * Cross-session reasoning, rendered ONLY when the assessment actually contains it.
 *
 * Two things can be present and they are different claims:
 *   - a `BEHAVIOURAL_DEVIATION` finding — an endpoint was compared against comparable
 *     sessions and differed;
 *   - an abstention on a deviation issue class — the comparison was attempted and
 *     declined, which on a capture with too few comparable sessions is what the
 *     engine's minimum-history floor produces.
 *
 * The declined side is detected by ISSUE CLASS rather than by abstention reason.
 * Verified against real engine output: a history shortfall is recorded as
 * `INSUFFICIENT_CAPTURE` on `STARTTLS_BEHAVIOUR_DEVIATION`, not as
 * `INSUFFICIENT_HISTORY`, so keying on the reason alone would have silently missed
 * every real occurrence. Both history reasons are still matched, because either may
 * appear and neither should be dropped.
 *
 * With neither present, this returns null and the screen says nothing: a panel
 * announcing that cross-session reasoning exists would imply a comparison that never
 * happened.
 */
const DEVIATION_KIND = 'BEHAVIOURAL_DEVIATION';
const DEVIATION_CLASSES = ['STARTTLS_BEHAVIOUR_DEVIATION', 'TLS_VERSION_DEVIATION'];
const HISTORY_REASONS = ['INSUFFICIENT_HISTORY', 'NOT_COMPARABLE'];

/** Identical declined comparisons collapse into one row with a count. */
function groupDeclined(rows) {
  const out = new Map();
  for (const row of rows) {
    const key = [row.reason, row.issue_class, row.what_could_not_be_concluded,
      row.why].join('\u241f');
    const seen = out.get(key);
    if (seen) seen.count += 1;
    else out.set(key, { row, count: 1 });
  }
  return [...out.values()];
}

function crossSessionPanel(vm, runId) {
  const deviations = (vm.findings || []).filter((f) => f.fact_kind === DEVIATION_KIND);
  const declined = (vm.abstentions || []).filter(
    (a) => DEVIATION_CLASSES.indexOf(a.issue_class) !== -1
      || HISTORY_REASONS.indexOf(a.reason) !== -1);
  if (!deviations.length && !declined.length) return null;

  const children = [];
  if (deviations.length) {
    children.push(table(
      `${deviations.length} behavioural deviation(s) established by comparison`,
      ['Severity', 'Condition', 'Protocol', 'Sessions', 'What was compared'],
      deviations.map((f) => [
        chip(f.severity_label, f.severity_tone, f.severity_marker),
        f.title || f.issue_class_label,
        f.protocol_label,
        text(f.affected_sessions, '1'),
        text(f.conclusion, '—'),
      ]),
      { wide: [4] }));
  }
  if (declined.length) {
    const grouped = groupDeclined(declined);
    children.push(el('h3', { text: 'Comparisons the engine declined to make' }));
    children.push(table(
      `${declined.length} declined comparison(s), grouped by question`,
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
      { wide: [1, 2] }));
  }
  children.push(notice('A deviation is a statement about behaviour relative to '
    + 'comparable sessions at the same server. It is not an attribution, and it is '
    + 'not a claim that an attack occurred.'));
  children.push(el('p', {}, [
    el('a', {
      text: 'See the evidence behind these comparisons →',
      attrs: { href: `#/run/${runId}/evidence` },
    }),
  ]));
  return section('cross-session', 'Cross-session reasoning', children, {
    lead: 'What this endpoint looks like next to comparable sessions to the same '
      + 'server.',
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
      className: 'ml-section',
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
    className: 'ml-section',
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
  // Cached like the view model: navigating between tabs must not refetch it.
  // Measurement showed this call repeating on every Overview visit.
  let run = null;
  try {
    run = await cached(`run:${runId}`, () => getRun(runId));
  } catch (error) {
    run = null;           // identity still renders from the assessment itself
  }

  // The result comes first. Ordering is the whole point of this screen: posture and
  // coverage, then what to act on, then what could not be determined, then the
  // supporting detail an analyst needs to defend any of it.
  //
  // The section title IS the capture filename — the page's one true heading, doing
  // double duty as the accessible landmark and the visible identity line, rather than
  // a generic "Assessment result" label repeated above it.
  const resultTitle = run ? text(run.source_filename, 'Overview') : 'Overview';
  const blocks = [
    section('result', resultTitle, [resultMeta(vm, run), verdictPanel(vm, runId)],
      { className: 'result-section' }),
  ];
  // Withheld verdicts and absent coverage are surfaced immediately under the block
  // they qualify, not at the bottom of the page.
  for (const item of vm.notices) {
    blocks.push(notice(item, vm.posture.withheld ? 'withheld' : ''));
  }
  blocks.push(
    findingsPanel(vm, runId),
    abstentionPanel(vm, runId),
    protocolPanel(vm),
    crossSessionPanel(vm, runId),
    scorePanel(vm),
    coveragePanel(vm),
    distributionPanel(vm),
    mlPanel(vm),
    reportPanel(runId),
    identityPanel(vm, run),
    limitationsPanel(vm),
  );
  mount(root, blocks);
}
