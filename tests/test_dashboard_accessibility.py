"""
Phase-10 accessibility and layout regressions (doc 23 §12, §13).

These lock in what Milestone 9's visual QA measured in a real browser, so the findings
cannot silently return. They assert the *source* properties that produced those
measurements — heading levels, table semantics, label association, non-colour status,
contrast tokens — because a headless assertion about the shipped code is the part that
can run in CI.

What was verified in a browser and is NOT claimed here: rendered pixel layout, computed
contrast, and focus-ring visibility. Those measurements are recorded in doc 23 §17a.
"""
import os
import re

import pytest

STATIC = "src/securemailscope/dashboard/static"
VIEWS = os.path.join(STATIC, "views")


def _source(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _view_files():
    return [os.path.join(VIEWS, n) for n in sorted(os.listdir(VIEWS))
            if n.endswith(".js")]


def _headings(path):
    return re.findall(r"el\('(h[1-6])'", _source(path))


# ------------------------------------------------------------ heading order
def test_views_never_skip_a_heading_level():
    """Visual QA measured an h2 -> h4 jump in the findings detail cards.

    Sections render `h2` (via `dom.section`), so content inside a view may only
    introduce `h3`. An `h4` under an `h2` skips a level, and a second `h2` inside a
    section misrepresents subordinate content as a sibling of the section itself —
    both were present and both are fixed.

    The router's error panel is excluded: it mounts directly to `<main>` rather than
    inside a section, so its `h2` is the correct level.
    """
    for path in _view_files():
        used = set(_headings(path))
        assert "h1" not in used, path        # the shell owns the single h1
        assert "h2" not in used, path        # sections own h2
        assert used <= {"h3"}, (path, sorted(used))


def test_router_error_panel_is_a_top_level_heading():
    app = _source(os.path.join(STATIC, "app.js"))
    assert "el('h2', { text: entry.title })" in app
    assert "mount(main, [panel])" in app


def test_shell_declares_exactly_one_h1():
    html = _source(os.path.join(STATIC, "index.html"))
    assert html.count("<h1>") == 1


def test_sections_render_h2():
    dom = _source(os.path.join(STATIC, "dom.js"))
    assert "s.appendChild(el('h2', { text: title }))" in dom


# ------------------------------------------------------------ table semantics
def test_tables_always_have_a_caption_and_scoped_headers():
    dom = _source(os.path.join(STATIC, "dom.js"))
    assert "el('caption', { text: caption })" in dom
    assert "attrs: { scope: 'col' }" in dom
    # caption is a required positional argument, not an option that can be omitted
    assert "export function table(caption, columns, rows" in dom


def test_every_table_call_passes_a_caption():
    for path in _view_files():
        for call in re.findall(r"table\(\s*([^,]+),", _source(path)):
            stripped = call.strip()
            assert stripped and stripped != "''", (path, call)


# -------------------------------------------------------------- form labels
def test_filter_checkboxes_are_label_associated():
    findings = _source(os.path.join(VIEWS, "findings.js"))
    assert "attrs: { for: inputId }" in findings
    assert "id: inputId" in findings
    assert "el('legend'" in findings
    assert "el('fieldset'" in findings


def test_interactive_controls_carry_text():
    """No icon-only control may exist without an accessible name."""
    for path in _view_files():
        source = _source(path)
        for call in re.findall(r"el\('button',\s*\{([^}]*)\}", source):
            assert "text:" in call, (path, call)


# ---------------------------------------------------- non-colour status
def test_severity_carries_a_text_marker_not_only_colour():
    from securemailscope.dashboard import vocabulary as vocab
    for severity in vocab.SEVERITY_ORDER:
        assert vocab.severity_marker(severity).strip(), severity
    assert vocab.severity_marker("SOMETHING_NEW") == "[?  ]"


def test_every_chip_renders_its_label_as_text():
    dom = _source(os.path.join(STATIC, "dom.js"))
    assert "document.createTextNode(text(label, 'unknown'))" in dom


def test_posture_and_state_are_words_not_colours():
    """A greyscale or colour-blind reader must get the same information."""
    from securemailscope.dashboard import vocabulary as vocab
    assert vocab.label("posture", "INSUFFICIENT_EVIDENCE") == "INSUFFICIENT EVIDENCE"
    history = _source(os.path.join(VIEWS, "history.js"))
    # each state chip is built from a label, and the explain text is separate
    assert "chip(info.label, info.tone, null)" in history
    assert "text: info.explain" in history


def test_bars_print_their_value_as_text():
    dom = _source(os.path.join(STATIC, "dom.js"))
    assert "className: 'bar-value', text: item.value_text" in dom


# ------------------------------------------------------------ live regions
def test_result_counts_are_announced():
    for path, expected in ((os.path.join(VIEWS, "findings.js"), True),
                           (os.path.join(VIEWS, "history.js"), True)):
        source = _source(path)
        assert ("'aria-live': 'polite'" in source) is expected, path
        assert ("role: 'status'" in source) is expected, path


def test_loading_state_is_announced():
    dom = _source(os.path.join(STATIC, "dom.js"))
    assert "role: 'status', 'aria-live': 'polite'" in dom
    assert "'aria-hidden': 'true'" in dom       # the spinner glyph itself is decorative


def test_current_page_is_marked_in_navigation():
    app = _source(os.path.join(STATIC, "app.js"))
    assert "aria-current" in app


# ------------------------------------------------------------- keyboard
def test_skip_link_exists_and_is_first():
    html = _source(os.path.join(STATIC, "index.html"))
    body = html.split("<body>", 1)[1]
    assert body.index('class="skip"') < body.index("<header")


def test_focus_is_visible():
    css = _source(os.path.join(STATIC, "style.css"))
    assert ":focus-visible" in css
    assert "outline: 3px solid var(--accent)" in css
    # the skip link must become visible when focused
    assert ".skip:focus { left: 0; }" in css


def test_findings_use_native_disclosure_for_keyboard_support():
    """`<details>` gives keyboard operation without ARIA state that can drift."""
    findings = _source(os.path.join(VIEWS, "findings.js"))
    assert "el('details'" in findings
    assert "el('summary')" in findings
    css = _source(os.path.join(STATIC, "style.css"))
    assert ".finding > summary:focus-visible" in css


def test_reduced_motion_is_respected():
    css = _source(os.path.join(STATIC, "style.css"))
    assert "prefers-reduced-motion" in css


# ------------------------------------------------------------------ layout
def test_wide_tables_scroll_rather_than_clip():
    css = _source(os.path.join(STATIC, "style.css"))
    assert "overflow-x: auto" in css
    # and carry an affordance, since macOS hides scrollbars
    assert "background-attachment: local, local, scroll, scroll" in css


def test_headers_do_not_wrap_mid_word():
    css = _source(os.path.join(STATIC, "style.css"))
    block = css.split("th {", 1)[1].split("}", 1)[0]
    assert "white-space: nowrap" in block


def test_ordinary_words_are_not_broken():
    """`word-break: break-word` split OBSERVABLE as "OBSERVAB LE" in visual QA.

    Comments are stripped first: the rule's own comment names the property it
    replaced, and a naive search would flag that explanation as the defect.
    """
    css = re.sub(r"/\*.*?\*/", "", _source(os.path.join(STATIC, "style.css")),
                 flags=re.S)
    cell_block = css.split("th, td {", 1)[1].split("}", 1)[0]
    assert "overflow-wrap: break-word" in cell_block
    assert "word-break" not in cell_block
    # hashes, which genuinely have no word boundaries, may still break anywhere
    assert ".mono, td.wide { word-break: break-word; }" in css


def test_high_cardinality_facets_are_bounded():
    css = _source(os.path.join(STATIC, "style.css"))
    assert ".facet-options { max-height" in css
    assert "overflow-y: auto" in css


def test_narrow_viewport_rules_exist():
    css = _source(os.path.join(STATIC, "style.css"))
    assert "@media (max-width: 860px)" in css
    narrow = css.split("@media (max-width: 860px) {", 1)[1]
    assert ".filters { flex-direction: column" in narrow
    assert "dl.facts { grid-template-columns: 1fr" in narrow


def test_contrast_tokens_meet_wcag_aa():
    """Measured 5.84:1 for muted text and 17.65:1 for body text in the browser.

    The tokens are asserted here so a future palette change cannot quietly drop below
    the 4.5:1 threshold for normal text.
    """
    css = _source(os.path.join(STATIC, "style.css"))

    def srgb(channel):
        channel /= 255.0
        return channel / 12.92 if channel <= 0.03928 else \
            ((channel + 0.055) / 1.055) ** 2.4

    def luminance(hex_colour):
        value = hex_colour.lstrip("#")
        r, g, b = (int(value[i:i + 2], 16) for i in (0, 2, 4))
        return 0.2126 * srgb(r) + 0.7152 * srgb(g) + 0.0722 * srgb(b)

    def ratio(fg, bg="#ffffff"):
        a, b = luminance(fg), luminance(bg)
        return (max(a, b) + 0.05) / (min(a, b) + 0.05)

    tokens = dict(re.findall(r"--(\w[\w-]*): (#[0-9a-fA-F]{6});", css))
    for name in ("ink", "muted", "accent", "critical", "high", "medium", "low",
                 "info", "withheld"):
        assert name in tokens, name
        assert ratio(tokens[name]) >= 4.5, (name, tokens[name], ratio(tokens[name]))


# ------------------------------------------------------- performance guards
def test_router_starts_exactly_once():
    """Measured defect: the first screen rendered twice, duplicating its API calls.

    A module may evaluate before or after DOMContentLoaded, so both triggers are
    needed; the guard makes the first render idempotent.
    """
    app = _source(os.path.join(STATIC, "app.js"))
    assert "let started = false" in app
    assert "if (started) return;" in app
    assert "window.addEventListener('DOMContentLoaded', start)" in app
    assert "if (document.readyState !== 'loading') start();" in app
    # route() must not be wired directly to a load event any more
    assert "addEventListener('DOMContentLoaded', route)" not in app


def test_run_record_is_cached_like_the_view_model():
    """Measured defect: the run detail refetched on every Overview visit."""
    overview = _source(os.path.join(VIEWS, "overview.js"))
    assert "cached(`run:${runId}`, () => getRun(runId))" in overview
    app = _source(os.path.join(STATIC, "app.js"))
    assert "cache.delete(`run:${runId}`)" in app


def test_views_fetch_the_view_model_through_the_cache():
    """No screen may fetch the assessment independently."""
    for name in ("overview.js", "findings.js", "evidence.js"):
        source = _source(os.path.join(VIEWS, name))
        assert "cached(runId, () => getDashboard(runId))" in source, name
        # and never calls it outside the cache
        assert source.count("getDashboard(runId)") == 1, name


def test_filtering_rebuilds_only_the_results_region():
    """A filter change must not re-render the whole screen."""
    findings = _source(os.path.join(VIEWS, "findings.js"))
    assert "mount(resultsHost," in findings
    # redraw touches the results host, the status line and the active-filter host only
    redraw = findings.split("function redraw()", 1)[1].split("\n  }", 1)[0]
    assert "mount(root," not in redraw
