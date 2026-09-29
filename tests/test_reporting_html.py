"""
Phase-9 tests: the HTML renderer (doc 22 §9, §16).

The security-critical assertions here are the escaping tests. Assessment text originates
in a capture, and a capture is untrusted input: it must arrive in the document as text
and never as markup.
"""
import re
from html.parser import HTMLParser

import pytest

from securemailscope.reporting.html import esc, render, render_html
from securemailscope.reporting.projection import project
from tests.reporting_fixtures import (
    HOSTILE, HOSTILE_ATTR, HOSTILE_PATH, ai_enabled_assessment, base_assessment,
    critical_assessment, empty_assessment, hostile_assessment, insufficient_evidence,
    large_assessment,
)


class _Collector(HTMLParser):
    """Parses the document and records structure. Proves it is well-formed enough
    for a browser to build a tree from."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.scripts = []
        self.text = []
        self.attrs = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.extend((tag, k, v) for k, v in attrs)
        if tag == "script":
            self._in_script = True

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        (self.scripts if self._in_script else self.text).append(data)


def _parse(html: str) -> _Collector:
    c = _Collector()
    c.feed(html)
    return c


# ------------------------------------------------------------------ structure
def test_document_is_standalone_and_well_formed():
    html = render(base_assessment())
    assert html.startswith("<!DOCTYPE html>")
    assert html.rstrip().endswith("</html>")
    c = _parse(html)
    for tag in ("html", "head", "title", "style", "body", "main", "section",
                "table", "footer"):
        assert tag in c.tags, tag


def test_no_external_resources_and_no_script():
    """§9: opens from disk, offline, with no CDN, font or script."""
    html = render(base_assessment())
    assert "<script" not in html.lower()
    assert "javascript:" not in html.lower()
    for pattern in ("http://", "https://", "//cdn", "@import", "url(",
                    "<link", "<iframe", "<img"):
        assert pattern not in html.lower(), pattern
    assert _parse(html).scripts == []


def test_semantic_markup_for_accessibility():
    html = render(base_assessment())
    assert '<html lang="en">' in html
    assert "<caption>" in html
    assert 'scope="col"' in html
    assert "<dl class=\"facts\">" in html
    assert re.search(r"<h1>.*?</h1>", html)
    assert "<h2>" in html


def test_print_css_present():
    html = render(base_assessment())
    assert "@page" in html and "@media print" in html
    assert "break-inside: avoid" in html
    assert "display: table-header-group" in html   # table headers repeat per page


def test_sections_are_numbered_and_anchored():
    doc = project(base_assessment())
    html = render_html(doc)
    for section in doc.sections:
        assert 'id="%s"' % section.section_id in html


# ------------------------------------------------------------------- escaping
@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '" onclick="alert(1)',
    "</td></tr><script>x</script>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "&lt;script&gt;",
    "'><script>alert(String.fromCharCode(88))</script>",
])
def test_hostile_payloads_are_escaped(payload):
    a = base_assessment()
    a["issue_groups"][0]["title"] = payload
    a["limitations"] = [payload]
    a["prioritised"][0]["representative_finding"]["conclusion"] = payload
    html = render(a)
    c = _parse(html)

    # Nothing executable was produced. Asserted against the PARSED tree rather than
    # against the raw string: correctly escaped text legitimately contains the
    # substring "onclick=" inside a <p>, and a substring search would call that a
    # failure while missing a real attribute injection.
    assert c.scripts == []
    assert "script" not in c.tags and "img" not in c.tags and "svg" not in c.tags
    for tag, key, value in c.attrs:
        assert not key.lower().startswith("on"), (tag, key, value)
    # the payload survives as readable TEXT
    joined = "".join(c.text)
    assert payload in joined


def test_hostile_assessment_renders_as_text_everywhere():
    html = render(hostile_assessment())
    c = _parse(html)
    assert c.scripts == []
    joined = "".join(c.text)
    for payload in (HOSTILE, HOSTILE_ATTR, HOSTILE_PATH):
        assert payload in joined
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_no_attribute_carries_assessment_text():
    """Attributes must only ever hold values this module controls."""
    html = render(hostile_assessment())
    for tag, key, value in _parse(html).attrs:
        if value is None:
            continue
        assert "alert" not in value
        assert "<" not in value and ">" not in value
        assert "script" not in value.lower()


def test_esc_covers_quote_contexts():
    assert esc('a"b') == "a&quot;b"
    assert esc("a'b") == "a&#x27;b"
    assert esc("<&>") == "&lt;&amp;&gt;"


def test_class_attribute_is_never_derived_from_assessment_text():
    a = base_assessment()
    a["issue_groups"][0]["severity"] = 'MEDIUM" onload="alert(1)'
    html = render(a)
    assert 'onload="alert' not in html
    assert _parse(html).scripts == []


# ------------------------------------------------------------------- semantics
def test_posture_and_coverage_appear_in_one_block():
    """§7: the verdict block always carries both."""
    html = render(base_assessment())
    block = html.split('<div class="verdict">')[1].split("</div></div>")[0]
    assert "Overall posture" in block
    verdict = html.split('<div class="verdict">')[1].split("<main>")[0]
    assert "Evidence coverage" in verdict and "75.0%" in verdict


def test_insufficient_evidence_never_reads_as_a_pass():
    html = render(insufficient_evidence())
    assert "INSUFFICIENT EVIDENCE" in html
    verdict = html.split('<div class="verdict">')[1].split("<main>")[0]
    assert "band withheld" in verdict
    for forbidden in (">STRONG<", ">ADEQUATE<", ">WEAK<", ">Secure<", ">Safe<",
                      ">Pass<"):
        assert forbidden not in html
    assert "Not scored" in html


def test_not_observable_and_abstentions_are_rendered():
    html = render(base_assessment())
    assert "Not observable" in html
    assert "Would be resolved by" in html
    assert "neither a failure nor a pass" in html


def test_severity_is_readable_without_colour():
    """§29: greyscale and screen readers must convey the same severity."""
    html = render(critical_assessment())
    assert "[!!!]" in html and "CRITICAL" in html
    # strip every inline colour and the severity must still be present
    stripped = re.sub(r"style=\"[^\"]*\"", "", html)
    stripped = re.sub(r"<style>.*?</style>", "", stripped, flags=re.S)
    assert "CRITICAL" in stripped and "[!!!]" in stripped


def test_ml_role_is_verbatim_and_bounded():
    html = render(ai_enabled_assessment())
    assert "secondary prioritisation signal only" in html
    assert "does not determine any security fact" in html
    assert "cannot move a finding from one tier to another" in html
    assert "AI detected" not in html


def test_limitations_and_provenance_present():
    a = base_assessment()
    html = render(a)
    for limitation in a["limitations"]:
        assert esc(limitation) in html
    assert a["capture_id"] in html
    assert a["assessment_id"] in html


def test_footer_states_the_timestamp_meaning():
    html = render(base_assessment())
    assert "time of analysis, not of report generation" in html
    assert "introduces no security conclusion of its own" in html


def test_no_filesystem_or_database_paths_leak():
    html = render(base_assessment())
    for leak in ("/Users/", "site-packages", ".db", "securemailscope-data",
                 "sqlite", "Traceback"):
        assert leak not in html


# ---------------------------------------------------------------- determinism
def test_rendering_is_byte_deterministic():
    a = render(base_assessment())
    b = render(base_assessment())
    assert a == b


def test_same_assessment_different_object_same_bytes():
    import copy
    source = base_assessment()
    assert render(source) == render(copy.deepcopy(source))


# ------------------------------------------------------------------ edge cases
@pytest.mark.parametrize("builder", [
    base_assessment, insufficient_evidence, empty_assessment, critical_assessment,
    ai_enabled_assessment, hostile_assessment,
])
def test_every_fixture_renders_valid_html(builder):
    html = render(builder())
    c = _parse(html)
    assert html.startswith("<!DOCTYPE html>")
    assert "main" in c.tags and c.scripts == []


def test_empty_assessment_still_states_its_limits():
    html = render(empty_assessment())
    assert "INSUFFICIENT EVIDENCE" in html
    assert "no abstentions" in html.lower()
    assert "Evidence coverage" in html


def test_large_assessment_renders_and_discloses_truncation():
    html = render(large_assessment(groups=600, abstentions=200))
    assert "truncated" in html.lower()
    assert _parse(html).scripts == []
    assert html.count("<tr>") > 200


def test_long_unbroken_string_cannot_break_the_layout():
    a = base_assessment()
    a["prioritised"][0]["representative_finding"]["conclusion"] = "A" * 4000
    html = render(a)
    assert "word-break: break-word" in html
    assert "…truncated]" in html
