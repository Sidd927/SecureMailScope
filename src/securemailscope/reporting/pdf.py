"""
PDF renderer (doc 22 §10, ADR-0020).

Composed from the same `ReportDocument` the HTML renderer walks — not from the rendered
HTML. ADR-0020 records why: every HTML→PDF engine (WeasyPrint, wkhtmltopdf, Chromium,
Playwright) was measured absent here, and depending on a browser bundle that happens to
exist on one machine would produce a renderer that works only where it was written.

ReportLab is imported lazily and is an optional extra. Its absence raises
`RendererUnavailable`; HTML and JSON are unaffected (ADR-0019 Decision 4).

Determinism: `invariant=1` pins the PDF `CreationDate` and removes per-run identifiers,
and the document takes its timestamp from the assessment, so the same assessment renders
to the same bytes (ADR-0021).
"""
from __future__ import annotations

import io
from typing import Any, List, Optional, Tuple

from securemailscope.reporting import styles
from securemailscope.reporting.errors import RendererUnavailable
from securemailscope.reporting.model import Bar, ReportDocument, Section, Table

#: Cells longer than this are wrapped into a Paragraph so ReportLab can break them.
#: A long unbroken evidence string would otherwise widen a column past the page.
_WRAP_THRESHOLD = 28


def _require_reportlab():
    try:
        import reportlab  # noqa: F401
    except ImportError:
        raise RendererUnavailable(
            "PDF rendering requires the optional reporting-pdf extra",
            detail={"install": "pip install 'securemailscope[reporting-pdf]'",
                    "package": "reportlab"})


def available() -> bool:
    try:
        _require_reportlab()
        return True
    except RendererUnavailable:
        return False


# ------------------------------------------------------------------- styling
def _stylesheet():
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm

    sheet = getSampleStyleSheet()
    ink = styles.COLOR["ink"]
    muted = styles.COLOR["muted"]

    def add(name, **kw):
        sheet.add(ParagraphStyle(name=name, **kw))

    add("SMSTitle", fontName=styles.PDF_FONT_BOLD, fontSize=20, leading=24,
        textColor=ink, spaceAfter=2)
    add("SMSSubtitle", fontName=styles.PDF_FONT, fontSize=11, leading=14,
        textColor=muted, spaceAfter=10)
    add("SMSIds", fontName=styles.PDF_FONT_MONO, fontSize=7, leading=10,
        textColor=muted, spaceAfter=2)
    add("SMSHeading", fontName=styles.PDF_FONT_BOLD, fontSize=12.5, leading=15,
        textColor=ink, spaceBefore=10, spaceAfter=3)
    add("SMSLead", fontName=styles.PDF_FONT, fontSize=9, leading=12,
        textColor=muted, spaceAfter=6)
    add("SMSBody", fontName=styles.PDF_FONT, fontSize=9, leading=12.5,
        textColor=ink, spaceAfter=4, alignment=TA_LEFT)
    add("SMSNotice", fontName=styles.PDF_FONT, fontSize=8.5, leading=11.5,
        textColor=ink, leftIndent=6, borderPadding=4, spaceBefore=3, spaceAfter=5,
        backColor=styles.COLOR["panel"])
    add("SMSCaption", fontName=styles.PDF_FONT, fontSize=7.5, leading=10,
        textColor=muted, spaceBefore=4, spaceAfter=2)
    add("SMSCell", fontName=styles.PDF_FONT, fontSize=7, leading=9, textColor=ink)
    add("SMSCellHead", fontName=styles.PDF_FONT_BOLD, fontSize=6.6, leading=8.5,
        textColor=muted)
    add("SMSVerdictKey", fontName=styles.PDF_FONT, fontSize=7, leading=9,
        textColor=muted)
    add("SMSVerdictValue", fontName=styles.PDF_FONT_BOLD, fontSize=13, leading=16,
        textColor=ink)
    add("SMSFooterNote", fontName=styles.PDF_FONT, fontSize=7.5, leading=10,
        textColor=muted, spaceBefore=8)
    return sheet, mm


def _pdf_escape(value: object) -> str:
    """Escape for ReportLab's mini-markup.

    ReportLab Paragraphs accept a small XML-like markup, so assessment text must be
    escaped here for exactly the reason it is escaped in HTML: it came from a capture.
    """
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


# --------------------------------------------------------------- page furniture
class _Furniture:
    """Header rule and footer with page numbers and the assessment id."""

    def __init__(self, document: ReportDocument) -> None:
        self.document = document

    def __call__(self, canvas, doc) -> None:
        from reportlab.lib.units import mm
        canvas.saveState()
        width, _height = doc.pagesize
        m = self.document.metadata

        canvas.setStrokeColor(_c(styles.COLOR["rule"]))
        canvas.setLineWidth(0.5)
        canvas.line(doc.leftMargin, doc.bottomMargin - 6 * mm,
                    width - doc.rightMargin, doc.bottomMargin - 6 * mm)

        canvas.setFont(styles.PDF_FONT, 7)
        canvas.setFillColor(_c(styles.COLOR["muted"]))
        canvas.drawString(doc.leftMargin, doc.bottomMargin - 10 * mm,
                          "SecureMailScope · Forensic assessment · %s"
                          % m.assessment_id)
        canvas.drawRightString(width - doc.rightMargin, doc.bottomMargin - 10 * mm,
                               "Page %d" % canvas.getPageNumber())
        canvas.restoreState()


def _c(hex_colour: str):
    from reportlab.lib.colors import HexColor
    return HexColor(hex_colour)


# --------------------------------------------------------------------- blocks
def _para(text: str, style) -> Any:
    from reportlab.platypus import Paragraph
    return Paragraph(_pdf_escape(text), style)


def _verdict_block(document: ReportDocument, sheet, mm) -> Any:
    """Posture and coverage in one table. Never separable (doc 22 §7)."""
    from reportlab.platypus import Paragraph, Table as RLTable, TableStyle

    key = sheet["SMSVerdictKey"]
    value = sheet["SMSVerdictValue"]
    small = sheet["SMSBody"]

    withheld = document.overall_posture == "INSUFFICIENT_EVIDENCE"
    posture_cell = [Paragraph("OVERALL POSTURE", key),
                    Paragraph('<font color="%s">%s</font>'
                              % (styles.posture_color(document.overall_posture),
                                 _pdf_escape(document.overall_posture_label)), value)]
    if withheld:
        posture_cell.append(
            Paragraph("band withheld: coverage below the assessment floor", key))

    rows = [[posture_cell,
             [Paragraph("POSTURE SCORE", key),
              Paragraph(_pdf_escape(document.score_text), small)],
             [Paragraph("EVIDENCE COVERAGE", key),
              Paragraph(_pdf_escape(document.coverage_text), small)],
             [Paragraph("ML LANE", key),
              Paragraph("Enabled" if document.metadata.ai_enabled else "Disabled",
                        small)]]]

    table = RLTable(rows, colWidths=[46 * mm, 38 * mm, 52 * mm, 28 * mm])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, _c(styles.COLOR["rule"])),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def _facts_table(facts, sheet, mm) -> Any:
    from reportlab.platypus import Paragraph, Table as RLTable, TableStyle
    rows = []
    for fact in facts:
        value = _pdf_escape(fact.value)
        if fact.note:
            value += '<br/><font size="6.5" color="%s">%s</font>' % (
                styles.COLOR["muted"], _pdf_escape(fact.note))
        rows.append([Paragraph(_pdf_escape(fact.label), sheet["SMSCell"]),
                     Paragraph(value, sheet["SMSBody"])])
    table = RLTable(rows, colWidths=[52 * mm, 112 * mm])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, _c(styles.COLOR["rule"])),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    return table


def _data_table(table: Table, sheet, mm) -> List[Any]:
    """Render one table, wrapping long cells so nothing overflows the page."""
    from reportlab.platypus import KeepTogether, Paragraph, Table as RLTable, TableStyle

    out: List[Any] = [_para(table.caption, sheet["SMSCaption"])]
    if not table.rows:
        out.append(_para(table.empty_note or "No data recorded for this table.",
                         sheet["SMSLead"]))
        return out

    header = [Paragraph(_pdf_escape(c).upper(), sheet["SMSCellHead"])
              for c in table.columns]
    body = [header]
    for row in table.rows:
        cells = []
        for index, cell in enumerate(row):
            text = str(cell)
            if len(text) > _WRAP_THRESHOLD or index in table.wide_columns:
                cells.append(Paragraph(_pdf_escape(text), sheet["SMSCell"]))
            else:
                cells.append(Paragraph(_pdf_escape(text), sheet["SMSCell"]))
        body.append(cells)

    widths = _column_widths(table, mm)
    rl = RLTable(body, colWidths=widths, repeatRows=1)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, _c(styles.COLOR["rule"])),
        ("BACKGROUND", (0, 0), (-1, 0), _c(styles.COLOR["panel"])),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]
    for index in range(1, len(body)):
        if index % 2 == 0:
            style.append(("BACKGROUND", (0, index), (-1, index), _c("#fbfcfd")))
    rl.setStyle(TableStyle(style))
    out.append(rl)
    return out


#: mm of usable width inside the A4 margins used by `render_pdf`.
_USABLE_MM = 164.0
#: Approximate mm per character at the 6.6pt header / 7pt body sizes, plus cell padding.
_HEADER_MM_PER_CHAR = 1.30
_BODY_MM_PER_CHAR = 1.38
_CELL_PADDING_MM = 2.6


def _longest_word(text: str) -> int:
    return max([len(w) for w in str(text).split()] or [0])


def _column_widths(table: Table, mm) -> List[float]:
    """Width per column: never narrower than its longest unbreakable word.

    Visual QA found `PROTOCOL` rendering as "PROTO COL" and `ADEQUATE` as "ADEQU ATE"
    because a purely proportional split squeezed short columns below the width of a
    single word. A header that breaks mid-word reads as a rendering defect, so each
    column first claims enough room for its longest word and only the surplus is
    distributed by weight.
    """
    count = len(table.columns)
    minimums: List[float] = []
    demands: List[float] = []
    for index in range(count):
        header_word = _longest_word(table.columns[index]) * _HEADER_MM_PER_CHAR
        cell_word = max(
            [_longest_word(row[index]) for row in table.rows] or [0]) * _BODY_MM_PER_CHAR
        # A very long token (a hash, a frame list) may wrap; cap what it can demand.
        minimums.append(min(max(header_word, min(cell_word, 26.0)) + _CELL_PADDING_MM,
                            40.0))
        longest_cell = max([len(str(row[index])) for row in table.rows] or [1])
        demand = max(len(str(table.columns[index])), min(longest_cell, 60))
        demands.append(demand * (3.0 if index in table.wide_columns else 1.0))

    if sum(minimums) >= _USABLE_MM:
        # Pathologically wide table: fall back to an even split so nothing overflows.
        return [(_USABLE_MM / count) * mm] * count

    surplus = _USABLE_MM - sum(minimums)
    total_demand = sum(demands) or 1.0
    return [(minimums[i] + surplus * (demands[i] / total_demand)) * mm
            for i in range(count)]


def _bars_block(bars: List[Bar], sheet, mm) -> List[Any]:
    """Bars with their numbers as text. A chart that cannot be read is decoration."""
    from reportlab.platypus import Paragraph, Table as RLTable, TableStyle
    if not bars:
        return []
    rows = []
    for bar in bars:
        filled = int(round(max(0.0, min(1.0, bar.fraction)) * 28))
        meter = "█" * filled + "·" * (28 - filled)
        rows.append([
            Paragraph(_pdf_escape(bar.label), sheet["SMSCell"]),
            Paragraph('<font name="%s" color="%s">%s</font>'
                      % (styles.PDF_FONT_MONO,
                         styles.severity_color(bar.severity) if bar.severity
                         else styles.COLOR["muted"], meter), sheet["SMSCell"]),
            Paragraph(_pdf_escape(bar.value_text), sheet["SMSCell"]),
        ])
    # Sized so the count sits beside its bar rather than drifting to the page edge —
    # a number detached from the bar it labels is harder to read, not easier.
    table = RLTable(rows, colWidths=[30 * mm, 46 * mm, 14 * mm])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))
    return [table]


def _notice(text: str, sheet) -> Any:
    from reportlab.platypus import Paragraph
    return Paragraph(_pdf_escape(text), sheet["SMSNotice"])


def _section_flowables(index: int, section: Section, sheet, mm) -> List[Any]:
    from reportlab.platypus import PageBreak, Spacer

    out: List[Any] = []
    if section.page_break_before:
        out.append(PageBreak())
    out.append(_para("%d. %s" % (index, section.title), sheet["SMSHeading"]))
    if section.lead:
        out.append(_para(section.lead, sheet["SMSLead"]))
    if section.facts:
        out.append(_facts_table(section.facts, sheet, mm))
        out.append(Spacer(1, 4))
    for paragraph in section.paragraphs:
        out.append(_para(paragraph, sheet["SMSBody"]))
    out.extend(_bars_block(section.bars, sheet, mm))
    for table in section.tables:
        out.extend(_data_table(table, sheet, mm))
        out.append(Spacer(1, 5))
    for notice in section.notices:
        out.append(_notice(notice, sheet))
    return out


# --------------------------------------------------------------------- render
def render_pdf(document: ReportDocument) -> bytes:
    """Render the report as PDF bytes. Deterministic for a given assessment."""
    _require_reportlab()

    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate, Spacer

    sheet, mm = _stylesheet()
    buffer = io.BytesIO()

    doc = BaseDocTemplate(
        buffer, pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=15 * mm, bottomMargin=22 * mm,
        title="%s — %s" % (document.title, document.metadata.assessment_id),
        author="SecureMailScope",
        subject=document.subtitle,
        creator="SecureMailScope %s" % document.metadata.renderer_version,
        # invariant=1 pins CreationDate and drops per-run ids: the same assessment
        # renders to identical bytes (ADR-0020, ADR-0021).
        invariant=1,
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin,
                  doc.width, doc.height, id="body",
                  leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate(id="report", frames=[frame],
                                       onPage=_Furniture(document))])

    m = document.metadata
    story: List[Any] = [
        _para(document.title, sheet["SMSTitle"]),
        _para(document.subtitle, sheet["SMSSubtitle"]),
        _para("Assessment %s" % m.assessment_id, sheet["SMSIds"]),
        _para("Capture %s" % m.capture_id, sheet["SMSIds"]),
    ]
    if m.run_id:
        story.append(_para("Run %s" % m.run_id, sheet["SMSIds"]))
    story.append(_para("Analysed %s" % m.generated_at, sheet["SMSIds"]))
    story.append(Spacer(1, 8))
    story.append(_verdict_block(document, sheet, mm))
    story.append(Spacer(1, 6))

    if document.truncations:
        story.append(_notice("Some content was truncated for rendering: "
                             + "; ".join(document.truncations), sheet))

    for index, section in enumerate(document.sections, start=1):
        story.extend(_section_flowables(index, section, sheet, mm))

    story.append(Spacer(1, 10))
    story.append(_para(
        "Report schema %s · Renderer %s · Posture schema %s · Posture engine %s"
        % (m.report_schema_version, m.renderer_version, m.posture_schema_version,
           m.posture_engine_version), sheet["SMSFooterNote"]))
    story.append(_para(
        "The timestamp shown is the time of analysis, not of report generation. This "
        "report is a rendering of the canonical assessment and introduces no security "
        "conclusion of its own.", sheet["SMSFooterNote"]))

    doc.build(story)
    return buffer.getvalue()


def render(assessment: dict) -> bytes:
    """Convenience: project then render."""
    from securemailscope.reporting.projection import project
    return render_pdf(project(assessment))
