"""
Phase-9 tests: the PDF renderer (doc 22 §10, ADR-0020).

A PDF is only acceptable if it is a real PDF: parseable, paginated, with extractable
text. "The bytes start with %PDF" is not the bar, so every assertion here goes through
a PDF parser.
"""
import io
import re

import pytest

from securemailscope.reporting.errors import RendererUnavailable
from securemailscope.reporting.projection import project
from tests.reporting_fixtures import (
    HOSTILE, ai_enabled_assessment, base_assessment, critical_assessment,
    empty_assessment, hostile_assessment, insufficient_evidence, large_assessment,
)

reportlab = pytest.importorskip("reportlab", reason="reporting-pdf extra not installed")
pypdf = pytest.importorskip("pypdf", reason="pypdf required to verify PDFs")

from securemailscope.reporting.pdf import available, render, render_pdf  # noqa: E402


def _read(data: bytes):
    return pypdf.PdfReader(io.BytesIO(data))


def _text(data: bytes) -> str:
    return "\n".join(page.extract_text() or "" for page in _read(data).pages)


def _norm(text: str) -> str:
    """Collapse whitespace: PDF text extraction inserts line breaks mid-sentence."""
    return re.sub(r"\s+", " ", text)


# -------------------------------------------------------------------- validity
def test_renderer_is_available():
    assert available() is True


def test_output_is_a_real_pdf():
    data = render(base_assessment())
    assert data[:5] == b"%PDF-"
    assert b"%%EOF" in data[-2048:]
    reader = _read(data)
    assert len(reader.pages) > 0


def test_pages_are_not_blank():
    reader = _read(render(base_assessment()))
    blank = [i for i, p in enumerate(reader.pages) if not (p.extract_text() or "").strip()]
    assert blank == [], "blank pages at %r" % blank


def test_document_metadata_is_set():
    reader = _read(render(base_assessment()))
    meta = reader.metadata
    assert "SecureMailScope" in (meta.get("/Title") or "")
    assert "a1b2c3d4e5f60718" in (meta.get("/Title") or "")
    assert (meta.get("/Author") or "") == "SecureMailScope"


@pytest.mark.parametrize("builder", [
    base_assessment, insufficient_evidence, empty_assessment, critical_assessment,
    ai_enabled_assessment, hostile_assessment,
])
def test_every_fixture_produces_a_valid_paginated_pdf(builder):
    data = render(builder())
    reader = _read(data)
    assert len(reader.pages) >= 1
    assert all((p.extract_text() or "").strip() for p in reader.pages)


# ------------------------------------------------------------------- semantics
def test_required_forensic_content_is_present():
    a = base_assessment()
    text = _norm(_text(render(a)))
    assert a["assessment_id"] in text
    assert a["capture_id"] in text
    assert "SecureMailScope" in text
    assert "Cryptographic Security Posture Assessment" in text
    assert "ADEQUATE" in text
    assert "88 / 100" in text
    assert "75.0%" in text
    assert a["generated_at"] in text


def test_all_canonical_sections_reach_the_pdf():
    doc = project(base_assessment())
    text = _norm(_text(render_pdf(doc)))
    for section in doc.sections:
        assert section.title in text, section.section_id


def test_limitations_reach_the_pdf():
    a = base_assessment()
    text = _norm(_text(render(a)))
    for limitation in a["limitations"]:
        assert _norm(limitation)[:60] in text


def test_insufficient_evidence_is_not_softened_in_pdf():
    text = _norm(_text(render(insufficient_evidence())))
    assert "INSUFFICIENT EVIDENCE" in text
    assert "band withheld" in text
    assert "Not scored" in text
    assert "not a passing result" in text
    # The verdict must not be softened. Checked against the verdict block rather than
    # the whole document, because "Secure" legitimately occurs in "SecureMailScope".
    verdict = text.split("1. Executive summary")[0]
    for forbidden in ("STRONG", "ADEQUATE", "WEAK", "Unknown", "Safe", "Compliant"):
        assert forbidden not in verdict, forbidden


def test_not_observable_and_abstentions_reach_the_pdf():
    text = _norm(_text(render(base_assessment())))
    assert "Not observable" in text
    assert "neither a failure nor a pass" in text
    # Table headers are uppercased by the PDF header style, so match case-insensitively.
    assert "would be resolved by" in text.lower()
    assert "TLS 1.3" in text            # the abstention's own reasoning survives


def test_ml_role_reaches_the_pdf_verbatim():
    text = _norm(_text(render(ai_enabled_assessment())))
    assert "secondary prioritisation signal only" in text
    assert "does not determine any security fact" in text
    assert "AI detected" not in text


def test_severity_marker_survives_extraction():
    """§29: severity must be readable without colour, including from extracted text."""
    text = _text(render(critical_assessment()))
    assert "CRITICAL" in text
    assert "[!!!]" in text


def test_footer_carries_assessment_and_page_numbers():
    data = render(base_assessment())
    reader = _read(data)
    first = reader.pages[0].extract_text() or ""
    assert "a1b2c3d4e5f60718" in first
    assert "Page 1" in first
    last_index = len(reader.pages)
    last = reader.pages[last_index - 1].extract_text() or ""
    assert "Page %d" % last_index in last


def test_timestamp_meaning_is_stated():
    text = _norm(_text(render(base_assessment())))
    assert "time of analysis, not of report generation" in text


def test_no_paths_or_internals_leak():
    text = _text(render(base_assessment()))
    for leak in ("/Users/", "site-packages", "sqlite", "Traceback", ".db"):
        assert leak not in text


# ---------------------------------------------------------------- determinism
def test_pdf_rendering_is_byte_deterministic():
    """ADR-0020/0021: invariant=1 plus an assessment-derived timestamp."""
    import hashlib
    import time
    a = render(base_assessment())
    time.sleep(1.1)          # a wall-clock timestamp would differ across this gap
    b = render(base_assessment())
    assert hashlib.sha256(a).hexdigest() == hashlib.sha256(b).hexdigest()


def test_creation_date_is_pinned_not_live():
    data = render(base_assessment())
    match = re.search(rb"/CreationDate\s*\(([^)]*)\)", data)
    assert match is not None
    assert b"D:20000101000000" in match.group(1)


def test_different_assessments_differ():
    assert render(base_assessment()) != render(critical_assessment())


# -------------------------------------------------------------------- escaping
def test_hostile_text_is_escaped_for_reportlab_markup():
    """ReportLab paragraphs accept XML-ish markup; capture text must not reach it."""
    data = render(hostile_assessment())
    text = _norm(_text(data))
    # The payload appears as readable text, and rendering did not fail or drop it.
    assert "alert(1)" in text
    assert "script" in text.lower()
    assert len(_read(data).pages) > 0


def test_unbalanced_markup_does_not_break_rendering():
    a = base_assessment()
    for payload in ("<b>unclosed", "</para>", "<font color=", "<&>", "<<<>>>"):
        a["issue_groups"][0]["title"] = payload
        data = render(a)
        assert data[:5] == b"%PDF-"
        assert len(_read(data).pages) > 0


def test_ampersand_and_angle_brackets_survive():
    a = base_assessment()
    a["limitations"] = ["A & B < C > D"]
    text = _norm(_text(render(a)))
    assert "A & B < C > D" in text


# ----------------------------------------------------------------- layout QA
def test_wide_table_does_not_overflow_the_page():
    """Column widths must never exceed the usable frame (visual QA regression)."""
    from securemailscope.reporting.pdf import _USABLE_MM, _column_widths
    from reportlab.lib.units import mm
    doc = project(large_assessment(groups=5, abstentions=5))
    for section in doc.sections:
        for table in section.tables:
            widths = _column_widths(table, mm)
            assert sum(widths) <= _USABLE_MM * mm + 0.5, (
                section.section_id, table.caption, sum(widths) / mm)


def test_headers_are_wide_enough_to_avoid_mid_word_breaks():
    """Regression for a defect visual QA found: PROTOCOL rendered as 'PROTO COL'."""
    from securemailscope.reporting.pdf import (
        _BODY_MM_PER_CHAR, _HEADER_MM_PER_CHAR, _column_widths, _longest_word)
    from reportlab.lib.units import mm
    doc = project(base_assessment())
    for section in doc.sections:
        for table in section.tables:
            widths = _column_widths(table, mm)
            for index, column in enumerate(table.columns):
                needed = _longest_word(column) * _HEADER_MM_PER_CHAR * mm
                assert widths[index] >= needed, (table.caption, column)


def test_large_report_paginates_without_pathology():
    data = render(large_assessment(groups=150, abstentions=100))
    reader = _read(data)
    assert 5 < len(reader.pages) < 120
    assert all((p.extract_text() or "").strip() for p in reader.pages)
    assert len(data) < 32 * 1024 * 1024


def test_long_unbroken_token_does_not_break_layout():
    a = base_assessment()
    a["prioritised"][0]["representative_finding"]["conclusion"] = "Z" * 3000
    data = render(a)
    assert len(_read(data).pages) > 0


def test_page_breaks_land_where_requested():
    doc = project(base_assessment())
    breaks = [s.section_id for s in doc.sections if s.page_break_before]
    assert breaks, "fixture should exercise page breaks"
    reader = _read(render_pdf(doc))
    assert len(reader.pages) >= len(breaks)


# --------------------------------------------------- optional-dependency path
def test_missing_reportlab_raises_structured_error(monkeypatch):
    """ADR-0019 Decision 4: absence is a structured 503, not a crash."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "reportlab" or name.startswith("reportlab."):
            raise ImportError("simulated absence")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    from securemailscope.reporting import pdf as pdf_module
    with pytest.raises(RendererUnavailable) as exc:
        pdf_module.render_pdf(project(base_assessment()))
    assert exc.value.http_status == 503
    assert exc.value.code == "REPORT_RENDERER_UNAVAILABLE"
    assert "reporting-pdf" in exc.value.detail["install"]
    assert pdf_module.available() is False
