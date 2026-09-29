/**
 * Safe DOM construction (doc 23 §11, ADR-0022 Decision 4).
 *
 * Everything the API returns ultimately derives from a capture, and a capture is
 * hostile input. This module is the ONLY way the console puts data on screen, and it
 * can only produce text nodes and attribute values drawn from fixed vocabularies.
 *
 * Deliberately absent, and asserted absent by a structural test over this directory:
 * innerHTML, outerHTML, insertAdjacentHTML, document.write, eval, new Function, and
 * any href or src taken from API data.
 */

/** Create an element. `text` becomes a text node — never markup. */
export function el(tag, opts = {}, children = []) {
  const node = document.createElement(tag);
  if (opts.className) node.className = opts.className;
  if (opts.id) node.id = opts.id;
  if (opts.text !== undefined && opts.text !== null) node.textContent = String(opts.text);
  if (opts.attrs) {
    for (const [key, value] of Object.entries(opts.attrs)) {
      if (value === undefined || value === null || value === false) continue;
      node.setAttribute(key, String(value));
    }
  }
  if (opts.onClick) node.addEventListener('click', opts.onClick);
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

export function text(value, fallback = '—') {
  if (value === null || value === undefined || value === '') return fallback;
  return String(value);
}

/** Remove all children. Uses removeChild rather than innerHTML = ''. */
export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function mount(node, children) {
  clear(node);
  for (const child of children) {
    if (child) node.appendChild(child);
  }
}

/**
 * A same-origin application link. The only hrefs this console produces are
 * hash routes it builds itself and API paths built from a validated run id —
 * never a URL supplied by the API.
 */
export function link(href, label, opts = {}) {
  return el('a', { text: label, className: opts.className, attrs: { href } });
}

/** A definition list of label/value pairs. */
export function facts(pairs, className = 'facts') {
  const dl = el('dl', { className });
  for (const pair of pairs) {
    if (!pair) continue;
    const [label, value, note] = pair;
    dl.appendChild(el('dt', { text: label }));
    const dd = el('dd', {}, [document.createTextNode(text(value))]);
    if (note) dd.appendChild(el('span', { className: 'note', text: note }));
    dl.appendChild(dd);
  }
  return dl;
}

/**
 * An accessible table. `rows` are arrays of strings or nodes.
 * `caption` is required: a table without one is unreadable to a screen reader.
 */
export function table(caption, columns, rows, opts = {}) {
  const figure = el('figure', { className: 'table-wrap' });
  if (!rows.length) {
    figure.appendChild(el('p', { className: 'empty', text: opts.empty || 'No rows.' }));
    return figure;
  }
  const t = el('table');
  t.appendChild(el('caption', { text: caption }));
  const thead = el('thead');
  const hr = el('tr');
  for (const col of columns) {
    hr.appendChild(el('th', { text: col, attrs: { scope: 'col' } }));
  }
  thead.appendChild(hr);
  t.appendChild(thead);

  const tbody = el('tbody');
  for (const row of rows) {
    const tr = el('tr');
    row.forEach((cell, index) => {
      const td = el('td');
      if (cell && typeof cell === 'object' && cell.nodeType) td.appendChild(cell);
      else td.textContent = text(cell);
      if (opts.wide && opts.wide.includes(index)) td.className = 'wide';
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  }
  t.appendChild(tbody);
  figure.appendChild(t);
  return figure;
}

/**
 * A severity or posture chip. The CSS class comes from `tone`, which the Python
 * projection derived from a KNOWN vocabulary — never from raw assessment text.
 * `marker` carries the meaning when colour is unavailable.
 */
export function chip(label, tone, marker) {
  const node = el('span', { className: `chip chip-${sanitiseTone(tone)}` });
  if (marker) node.appendChild(el('span', { className: 'marker', text: marker }));
  node.appendChild(document.createTextNode(text(label, 'unknown')));
  return node;
}

/**
 * Defence in depth: even though `tone` originates in the projection's fixed
 * vocabulary, it is filtered before reaching a class attribute.
 */
export function sanitiseTone(tone) {
  const value = String(tone || 'unknown');
  return /^[a-z_]+$/.test(value) ? value : 'unknown';
}

/**
 * A CSS class-name fragment. Anything outside `[a-z0-9_-]` is dropped.
 *
 * Every interpolation into a `className` template goes through this or
 * `sanitiseTone`, asserted by the security matrix. `notice()` previously
 * interpolated its `variant` unguarded: every caller passed a literal, so nothing
 * was wrong in practice, but an unguarded path into a class attribute is exactly
 * the kind of thing a later edit turns into a vulnerability without noticing.
 */
export function safeToken(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9_-]/g, '');
}

export function notice(message, variant = '') {
  return el('div', { className: `notice ${safeToken(variant)}`.trim(),
    text: message });
}

export function section(id, title, children, opts = {}) {
  const s = el('section', { id, className: opts.className });
  s.appendChild(el('h2', { text: title }));
  if (opts.lead) s.appendChild(el('p', { className: 'lead', text: opts.lead }));
  for (const child of children) {
    if (child) s.appendChild(child);
  }
  return s;
}

/** A bar row. Width is a computed percentage; the number is always shown as text. */
export function bar(item) {
  const row = el('div', { className: 'bar' });
  row.appendChild(el('span', { className: 'bar-label', text: item.label }));
  const track = el('span', { className: 'bar-track' });
  const fill = el('span', { className: `bar-fill tone-${sanitiseTone(item.tone)}` });
  const pct = item.max_value ? Math.max(0, Math.min(1, item.value / item.max_value)) : 0;
  fill.style.width = `${(pct * 100).toFixed(1)}%`;
  track.appendChild(fill);
  row.appendChild(track);
  row.appendChild(el('span', { className: 'bar-value', text: item.value_text }));
  return row;
}

export function spinner(message) {
  return el('div', { className: 'loading', attrs: { role: 'status', 'aria-live': 'polite' } },
    [el('span', { className: 'spinner', attrs: { 'aria-hidden': 'true' } }),
     el('span', { text: message || 'Loading…' })]);
}
