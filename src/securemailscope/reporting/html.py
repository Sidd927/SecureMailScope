"""
Standalone HTML renderer (doc 22 §9, §16, ADR-0019 Decision 2).

Zero dependencies: `html.escape` plus string composition, no template engine. That keeps
JSON and HTML available to a core install, and it puts the escaping boundary at every
call site rather than behind an autoescape setting a later edit could switch off.

The output is one self-contained file. Inline CSS, no CDN, no webfont, no `<script>`, no
external image. It opens from disk with no server running.

**Every value that came from the assessment passes through `esc()`.** Assessment text
originates in a capture, and a capture is untrusted input; it is data, never markup.
CSS and structural markup are literals in this module and are never interpolated from
assessment content.
"""
from __future__ import annotations

from html import escape
from typing import Iterable, List

from securemailscope.reporting import styles
from securemailscope.reporting.model import Bar, ReportDocument, Section, Table


def esc(value: object) -> str:
    """Escape for HTML text and attribute contexts. The only way content gets in."""
    return escape(str(value), quote=True)


# ------------------------------------------------------------------------ CSS
#: A literal. No assessment value is ever interpolated into this string.
_CSS = """
:root {
  --ink: %(ink)s; --muted: %(muted)s; --rule: %(rule)s; --panel: %(panel)s;
  --accent: %(accent)s; --critical: %(critical)s; --high: %(high)s;
  --medium: %(medium)s; --low: %(low)s; --info: %(info)s; --withheld: %(withheld)s;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%%; }
body {
  margin: 0; padding: 0 0 4rem; color: var(--ink); background: #fff;
  font-family: %(font)s; font-size: 15px; line-height: 1.55;
}
.wrap { max-width: 60rem; margin: 0 auto; padding: 0 1.5rem; }
a { color: var(--accent); }

/* ---- masthead ---- */
.masthead { border-bottom: 3px solid var(--accent); padding: 2.5rem 0 1.25rem;
  margin-bottom: 2rem; }
.masthead h1 { margin: 0; font-size: 1.6rem; letter-spacing: .04em; }
.masthead p { margin: .25rem 0 0; color: var(--muted); font-size: 1rem; }
.ids { margin-top: 1rem; font-family: %(mono)s; font-size: .76rem;
  color: var(--muted); word-break: break-all; }
.ids span { display: inline-block; margin-right: 1.25rem; }

/* ---- verdict: posture and coverage are one block, never separable ---- */
.verdict { display: flex; flex-wrap: wrap; gap: 1px; background: var(--rule);
  border: 1px solid var(--rule); margin: 0 0 2rem; }
.verdict > div { background: #fff; padding: 1rem 1.25rem; flex: 1 1 11rem; }
.verdict .k { font-size: .7rem; letter-spacing: .09em; text-transform: uppercase;
  color: var(--muted); margin-bottom: .3rem; }
.verdict .v { font-size: 1.35rem; font-weight: 700; }
.verdict .v.small { font-size: 1.05rem; font-weight: 600; }
.verdict .note { font-size: .78rem; color: var(--muted); margin-top: .25rem; }

/* ---- sections ---- */
section { margin: 0 0 2.5rem; }
h2 { font-size: 1.1rem; margin: 0 0 .2rem; padding-bottom: .4rem;
  border-bottom: 2px solid var(--rule); letter-spacing: .02em; }
h2 .num { color: var(--muted); font-weight: 400; margin-right: .5rem; }
.lead { color: var(--muted); margin: .5rem 0 1rem; }
p { margin: .6rem 0; }

/* ---- facts ---- */
dl.facts { display: grid; grid-template-columns: minmax(10rem, 16rem) 1fr;
  gap: .4rem 1.25rem; margin: 1rem 0; }
dl.facts dt { color: var(--muted); font-size: .84rem; }
dl.facts dd { margin: 0; font-weight: 600; word-break: break-word; }
dl.facts dd .note { display: block; font-weight: 400; font-size: .78rem;
  color: var(--muted); }

/* ---- tables ---- */
figure { margin: 1.25rem 0; }
table { width: 100%%; border-collapse: collapse; font-size: .82rem; }
caption { text-align: left; font-size: .78rem; color: var(--muted);
  padding-bottom: .4rem; }
th, td { border: 1px solid var(--rule); padding: .4rem .55rem; text-align: left;
  vertical-align: top; word-break: break-word; }
th { background: var(--panel); font-size: .74rem; letter-spacing: .05em;
  text-transform: uppercase; color: var(--muted); font-weight: 700; }
td.wide { min-width: 12rem; }
tbody tr:nth-child(even) td { background: #fbfcfd; }
.empty { color: var(--muted); font-style: italic; padding: .6rem 0; }

/* ---- severity: colour is redundant with the text marker ---- */
.sev { font-family: %(mono)s; font-size: .78rem; white-space: nowrap; }
.sev-CRITICAL { color: var(--critical); font-weight: 700; }
.sev-HIGH { color: var(--high); font-weight: 700; }
.sev-MEDIUM { color: var(--medium); font-weight: 600; }
.sev-LOW { color: var(--low); }
.sev-INFO { color: var(--info); }

/* ---- notices ---- */
.notice { border-left: 4px solid var(--accent); background: var(--panel);
  padding: .7rem .9rem; margin: .6rem 0; font-size: .87rem; }
.notice.withheld { border-left-color: var(--withheld); }

/* ---- bars: numbers are shown as text beside every bar ---- */
.bars { margin: 1rem 0; }
.bar { display: grid; grid-template-columns: 6rem 1fr 3rem; align-items: center;
  gap: .6rem; margin: .3rem 0; font-size: .8rem; }
.bar .track { background: var(--panel); border: 1px solid var(--rule);
  height: .85rem; position: relative; }
.bar .fill { position: absolute; inset: 0 auto 0 0; background: var(--muted); }
.bar .n { text-align: right; font-family: %(mono)s; }

/* ---- footer ---- */
footer { border-top: 1px solid var(--rule); margin-top: 3rem; padding-top: 1rem;
  font-size: .76rem; color: var(--muted); }
footer code { font-family: %(mono)s; word-break: break-all; }

/* ---- print ---- */
@page { size: A4; margin: 16mm 14mm; }
@media print {
  body { font-size: 10.5pt; }
  .wrap { max-width: none; padding: 0; }
  section { break-inside: auto; }
  h2 { break-after: avoid; }
  figure, .notice, .bar { break-inside: avoid; }
  tr { break-inside: avoid; }
  thead { display: table-header-group; }
  .page-break { break-before: page; }
}
"""


def _css() -> str:
    tokens = dict(styles.COLOR)
    tokens["font"] = styles.HTML_FONT_STACK
    tokens["mono"] = styles.HTML_MONO_STACK
    return _CSS % tokens


# -------------------------------------------------------------------- helpers
def _severity_class(cell: str) -> str:
    """Derive a CSS class from a severity cell. Returns a fixed literal or ''.

    Deliberately matches against the known severity vocabulary rather than
    interpolating the cell, so no assessment text can reach a class attribute.
    """
    for severity in styles.SEVERITY_ORDER:
        if severity in cell:
            return "sev sev-" + severity
    return ""


def _table(table: Table) -> str:
    out: List[str] = ["<figure>"]
    if not table.rows:
        out.append('<p class="empty">%s</p>' % esc(
            table.empty_note or "No data recorded for this table."))
        out.append("</figure>")
        return "".join(out)
    out.append("<table><caption>%s</caption><thead><tr>" % esc(table.caption))
    out.extend("<th scope=\"col\">%s</th>" % esc(c) for c in table.columns)
    out.append("</tr></thead><tbody>")
    for row in table.rows:
        out.append("<tr>")
        for index, cell in enumerate(row):
            classes = []
            if index in table.wide_columns:
                classes.append("wide")
            severity_class = _severity_class(cell) if index <= 1 else ""
            if severity_class:
                classes.append(severity_class)
            attr = ' class="%s"' % " ".join(classes) if classes else ""
            out.append("<td%s>%s</td>" % (attr, esc(cell)))
        out.append("</tr>")
    out.append("</tbody></table></figure>")
    return "".join(out)


def _bars(bars: Iterable[Bar]) -> str:
    items = list(bars)
    if not items:
        return ""
    out = ['<div class="bars">']
    for bar in items:
        colour = styles.severity_color(bar.severity) if bar.severity else \
            styles.COLOR["muted"]
        # width and colour come from the fixed severity vocabulary / a computed
        # percentage, never from assessment text.
        out.append(
            '<div class="bar"><span>%s</span>'
            '<span class="track"><span class="fill" style="width:%.1f%%;'
            'background:%s"></span></span>'
            '<span class="n">%s</span></div>'
            % (esc(bar.label), max(0.0, min(1.0, bar.fraction)) * 100.0,
               esc(colour), esc(bar.value_text)))
    out.append("</div>")
    return "".join(out)


def _section(index: int, section: Section) -> str:
    klass = ' class="page-break"' if section.page_break_before else ""
    out = ['<section id="%s"%s>' % (esc(section.section_id), klass)]
    out.append('<h2><span class="num">%d.</span>%s</h2>' % (index, esc(section.title)))
    if section.lead:
        out.append('<p class="lead">%s</p>' % esc(section.lead))
    if section.facts:
        out.append('<dl class="facts">')
        for fact in section.facts:
            note = '<span class="note">%s</span>' % esc(fact.note) if fact.note else ""
            out.append("<dt>%s</dt><dd>%s%s</dd>"
                       % (esc(fact.label), esc(fact.value), note))
        out.append("</dl>")
    for paragraph in section.paragraphs:
        out.append("<p>%s</p>" % esc(paragraph))
    out.append(_bars(section.bars))
    for table in section.tables:
        out.append(_table(table))
    for notice in section.notices:
        out.append('<div class="notice">%s</div>' % esc(notice))
    out.append("</section>")
    return "".join(out)


# --------------------------------------------------------------------- render
def render_html(document: ReportDocument) -> str:
    """Render a complete, standalone HTML document."""
    m = document.metadata
    posture_colour = styles.posture_color(document.overall_posture)
    withheld = document.overall_posture == "INSUFFICIENT_EVIDENCE"

    out: List[str] = []
    out.append("<!DOCTYPE html>")
    out.append('<html lang="en"><head><meta charset="utf-8">')
    out.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    out.append("<title>%s — %s — %s</title>"
               % (esc(document.title), esc(document.subtitle), esc(m.assessment_id)))
    out.append('<meta name="generator" content="%s %s">'
               % (esc(document.title), esc(m.renderer_version)))
    out.append("<style>%s</style></head><body>" % _css())
    out.append('<div class="wrap">')

    # masthead
    out.append('<header class="masthead">')
    out.append("<h1>%s</h1>" % esc(document.title))
    out.append("<p>%s</p>" % esc(document.subtitle))
    out.append('<div class="ids">')
    out.append("<span>Assessment <strong>%s</strong></span>" % esc(m.assessment_id))
    out.append("<span>Capture <strong>%s</strong></span>" % esc(m.capture_id))
    if m.run_id:
        out.append("<span>Run <strong>%s</strong></span>" % esc(m.run_id))
    out.append("<span>Analysed <strong>%s</strong></span>" % esc(m.generated_at))
    out.append("</div></header>")

    # verdict block: posture and coverage together, always (doc 22 §7)
    out.append('<div class="verdict">')
    out.append('<div><div class="k">Overall posture</div>'
               '<div class="v" style="color:%s">%s</div>%s</div>'
               % (esc(posture_colour), esc(document.overall_posture_label),
                  '<div class="note">band withheld: coverage below the assessment '
                  'floor</div>' if withheld else ""))
    out.append('<div><div class="k">Posture score</div>'
               '<div class="v small">%s</div></div>' % esc(document.score_text))
    out.append('<div><div class="k">Evidence coverage</div>'
               '<div class="v small">%s</div></div>' % esc(document.coverage_text))
    out.append('<div><div class="k">ML lane</div><div class="v small">%s</div></div>'
               % esc("Enabled" if m.ai_enabled else "Disabled"))
    out.append("</div>")

    if document.truncations:
        out.append('<div class="notice">Some content was truncated for rendering: '
                   + esc("; ".join(document.truncations)) + "</div>")

    out.append("<main>")
    for index, section in enumerate(document.sections, start=1):
        out.append(_section(index, section))
    out.append("</main>")

    out.append("<footer>")
    out.append("<p>%s · Forensic assessment · Assessment <code>%s</code></p>"
               % (esc(document.title), esc(m.assessment_id)))
    out.append("<p>Report schema %s · Renderer %s · Posture schema %s · "
               "Posture engine %s</p>"
               % (esc(m.report_schema_version), esc(m.renderer_version),
                  esc(m.posture_schema_version), esc(m.posture_engine_version)))
    out.append("<p>The timestamp shown is the time of analysis, not of report "
               "generation. This report is a rendering of the canonical assessment "
               "and introduces no security conclusion of its own.</p>")
    out.append("</footer></div></body></html>")
    return "".join(out)


def render(assessment: dict) -> str:
    """Convenience: project then render."""
    from securemailscope.reporting.projection import project
    return render_html(project(assessment))
