/**
 * Router and shell (doc 23 §7, §9).
 *
 * Hash routing, so the console is a single static document with no server-side
 * rewrite rule and no SPA fallback to get wrong.
 *
 *   #/                        home — submit a capture, then the analysis history
 *   #/about                   what this product is, and what this instance is
 *   #/run/{run_id}            overview
 *   #/run/{run_id}/findings   findings
 *   #/run/{run_id}/evidence   evidence and provenance
 *
 * The shell owns loading, empty, failure and not-found states so no view has to
 * reinvent them — doc 23 §9 requires six failure modes to look like six different
 * things, not one shrug.
 */
import { ApiError, isValidRunId } from './api.js';
import { clear, el, mount, notice, spinner } from './dom.js';

const main = document.getElementById('main');
const crumbs = document.getElementById('crumbs');
const tabs = document.getElementById('run-tabs');
const tabList = document.getElementById('tab-list');
const navNew = document.getElementById('nav-new');
const navAbout = document.getElementById('nav-about');

/** Assessment cache, keyed by run id: fetched once per run, not once per screen. */
const cache = new Map();

export function cached(runId, loader) {
  if (!cache.has(runId)) cache.set(runId, loader());
  return cache.get(runId);
}

export function invalidate(runId) {
  if (runId) {
    cache.delete(runId);
    cache.delete(`run:${runId}`);
  } else {
    cache.clear();
  }
}

const ROUTES = [
  { pattern: /^#?\/?$/, view: () => import('./views/home.js'), name: 'home' },
  { pattern: /^#\/about$/, view: () => import('./views/about.js'), name: 'about' },
  {
    pattern: /^#\/run\/([0-9a-f]{32})$/,
    view: () => import('./views/overview.js'),
    name: 'overview',
  },
  {
    pattern: /^#\/run\/([0-9a-f]{32})\/findings$/,
    view: () => import('./views/findings.js'),
    name: 'findings',
  },
  {
    pattern: /^#\/run\/([0-9a-f]{32})\/evidence$/,
    view: () => import('./views/evidence.js'),
    name: 'evidence',
  },
];

const TABS = [
  { name: 'overview', label: 'Overview', suffix: '' },
  { name: 'findings', label: 'Findings', suffix: '/findings' },
  { name: 'evidence', label: 'Evidence & provenance', suffix: '/evidence' },
];

/**
 * Mark the active shell action. The two header links are static markup, so this only
 * sets `aria-current` and a class — it never builds a URL.
 */
function setNav(active) {
  for (const [name, node] of [['home', navNew], ['about', navAbout]]) {
    if (!node) continue;
    if (name === active) {
      node.setAttribute('aria-current', 'page');
      node.classList.add('current');
    } else {
      node.removeAttribute('aria-current');
      node.classList.remove('current');
    }
  }
}

function setCrumbs(trail) {
  clear(crumbs);
  trail.forEach((item, index) => {
    const li = el('li');
    if (item.href && index < trail.length - 1) {
      li.appendChild(el('a', { text: item.label, attrs: { href: item.href } }));
    } else {
      li.appendChild(el('span', { text: item.label, attrs: { 'aria-current': 'page' } }));
    }
    crumbs.appendChild(li);
  });
}

function setTabs(runId, active) {
  if (!runId) {
    tabs.hidden = true;
    clear(tabList);
    return;
  }
  tabs.hidden = false;
  clear(tabList);
  for (const tab of TABS) {
    const li = el('li');
    const a = el('a', {
      text: tab.label,
      className: tab.name === active ? 'active' : '',
      attrs: { href: `#/run/${runId}${tab.suffix}` },
    });
    if (tab.name === active) a.setAttribute('aria-current', 'page');
    li.appendChild(a);
    tabList.appendChild(li);
  }
}

/** Distinct, actionable messages per failure mode (doc 23 §9). */
function renderError(error) {
  const known = {
    NOT_FOUND: {
      title: 'No such analysis',
      body: 'This run identifier does not exist in the catalog. It may have been '
        + 'removed, or the link may be from another SecureMailScope instance.',
    },
    INVALID_REQUEST: {
      title: 'Invalid request',
      body: 'The identifier in this address is not a valid analysis run id.',
    },
    MALFORMED_ASSESSMENT: {
      title: 'Assessment does not match the expected schema',
      body: 'The stored assessment could not be interpreted by this console. It is '
        + 'not being displayed rather than being displayed incorrectly. The raw '
        + 'document is still retrievable from the API.',
    },
    NETWORK_UNAVAILABLE: {
      title: 'Cannot reach the API',
      body: 'The console could not contact the SecureMailScope backend. This is a '
        + 'connection failure, not an empty result.',
    },
    MALFORMED_RESPONSE: {
      title: 'Unreadable API response',
      body: 'The API returned something this console could not parse.',
    },
    REPORT_RENDERER_UNAVAILABLE: {
      title: 'Report renderer unavailable',
      body: 'This deployment cannot produce that report format. The assessment and '
        + 'the other formats are unaffected.',
    },
  };
  const code = (error && error.code) || 'INTERNAL_ERROR';
  const entry = known[code] || {
    title: 'The console could not complete this request',
    body: (error && error.message) || 'An unexpected error occurred.',
  };

  const panel = el('div', { className: 'state-panel error' }, [
    el('h2', { text: entry.title }),
    el('p', { text: entry.body }),
    el('p', { className: 'code', text: `Error code: ${code}` }),
    el('p', {}, [el('a', { text: '← Back to analyses', attrs: { href: '#/' } })]),
  ]);
  mount(main, [panel]);
}

async function route() {
  const hash = window.location.hash || '#/';
  const match = ROUTES.map((r) => ({ r, m: hash.match(r.pattern) })).find((x) => x.m);

  if (!match) {
    setTabs(null);
    setNav(null);
    setCrumbs([{ label: 'Analyses', href: '#/' }, { label: 'Not found' }]);
    renderError(new ApiError('NOT_FOUND', 'unknown route'));
    return;
  }

  const runId = match.m[1] || null;
  if (runId && !isValidRunId(runId)) {
    renderError(new ApiError('INVALID_REQUEST', 'invalid run id'));
    return;
  }

  setTabs(runId, match.r.name);
  // Home is the root of the trail, so it carries no crumbs of its own; an empty
  // list collapses rather than rendering a lone orphan label.
  setCrumbs(runId
    ? [{ label: 'Analyses', href: '#/' },
       { label: `Run ${runId.slice(0, 12)}…`, href: `#/run/${runId}` },
       ...(match.r.name === 'overview' ? [] : [{ label: TABS.find(
         (t) => t.name === match.r.name).label }])]
    : (match.r.name === 'about'
      ? [{ label: 'Analyses', href: '#/' }, { label: 'About' }]
      : []));

  // Leaving a view must not leave a timer behind. History polls while runs are in
  // flight; every other route stops it.
  try {
    const history = await import('./views/history.js');
    history.stopPolling();
  } catch (error) {
    /* history module unavailable; nothing to stop */
  }

  setNav(match.r.name);
  mount(main, [spinner(runId ? 'Loading analysis…' : 'Loading…')]);
  try {
    const module = await match.r.view();
    await module.render(main, { runId });
    main.focus({ preventScroll: true });
  } catch (error) {
    renderError(error);
  }
}

window.addEventListener('hashchange', route);

/**
 * Start exactly once.
 *
 * A module may evaluate before or after DOMContentLoaded, so both triggers are
 * needed — but measurement showed both firing on a single load, rendering the first
 * screen twice and duplicating its API calls. The guard makes the first render
 * idempotent; `hashchange` drives every navigation after that.
 */
let started = false;
function start() {
  if (started) return;
  started = true;
  route();
}

window.addEventListener('DOMContentLoaded', start);
if (document.readyState !== 'loading') start();

export { renderError };
