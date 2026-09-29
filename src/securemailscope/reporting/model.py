"""
Canonical report document model (Phase 9, doc 22 §4, ADR-0019).

`ReportDocument` is the single structure both renderers walk. It is a **presentation**
contract, not a security one: every value in it was copied out of
`PostureAssessment.to_dict()` and is carried as a string or an already-decided number.

Nothing in this module computes a severity, a score, a band, a certainty, an
observability, a recurrence or a priority. If a value is not in the canonical
assessment, there is no field here to hold it.

The sections exist so a renderer never has to decide what a report says — only how it
looks.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

#: Bumped when the report document shape changes. Deliberately independent of
#: POSTURE_SCHEMA_VERSION and POSTURE_ENGINE_VERSION, which describe the assessment.
REPORT_SCHEMA_VERSION = "1.0"
#: Bumped when a renderer's output changes for an unchanged assessment. Participates in
#: the regeneration decision (ADR-0021 Decision 4).
RENDERER_VERSION = "0.9.0"

REPORT_TITLE = "SecureMailScope"
REPORT_SUBTITLE = "Cryptographic Security Posture Assessment"


@dataclass(frozen=True)
class KeyValue:
    """One labelled fact. `note` carries a qualification that must not be dropped."""
    label: str
    value: str
    note: str = ""


@dataclass(frozen=True)
class Table:
    """A rendered table. Column count is fixed by `columns`; rows must match.

    `empty_note` is shown instead of the table when there are no rows, so a section can
    state an absence rather than silently vanishing.
    """
    caption: str
    columns: Tuple[str, ...]
    rows: Tuple[Tuple[str, ...], ...]
    empty_note: str = ""
    #: Column indices whose content is long-form and should be allowed to wrap wide.
    wide_columns: Tuple[int, ...] = ()

    def __post_init__(self) -> None:
        width = len(self.columns)
        for row in self.rows:
            if len(row) != width:
                raise ValueError(
                    "row has {0} cells, expected {1}: {2!r}".format(
                        len(row), width, row))


@dataclass(frozen=True)
class Bar:
    """One bar in an accessible distribution chart.

    `value_text` is mandatory: a chart whose numbers are not also readable as text is
    decoration, and doc 22 §8 forbids decoration that cannot be read as a table.
    """
    label: str
    value: float
    max_value: float
    value_text: str
    severity: str = ""

    @property
    def fraction(self) -> float:
        return (self.value / self.max_value) if self.max_value else 0.0


@dataclass
class Section:
    """One report section. Renderers walk these in order and add no content."""
    section_id: str
    title: str
    #: Shown under the title. Factual, derived from the assessment.
    lead: str = ""
    facts: List[KeyValue] = field(default_factory=list)
    tables: List[Table] = field(default_factory=list)
    bars: List[Bar] = field(default_factory=list)
    paragraphs: List[str] = field(default_factory=list)
    #: Rendered with visual emphasis. Used for limitations and withheld conclusions —
    #: the things a reader must not skim past.
    notices: List[str] = field(default_factory=list)
    #: Start this section on a new page in the PDF.
    page_break_before: bool = False

    @property
    def is_empty(self) -> bool:
        return not (self.facts or self.tables or self.bars or self.paragraphs
                    or self.notices)


@dataclass(frozen=True)
class ReportMetadata:
    """Identity and provenance. No filesystem path, no database path, no secret."""
    assessment_id: str
    capture_id: str
    run_id: Optional[str]
    #: The ANALYSIS time, taken from the assessment. Never a print time (ADR-0021).
    generated_at: str
    posture_schema_version: str
    posture_engine_version: str
    report_schema_version: str = REPORT_SCHEMA_VERSION
    renderer_version: str = RENDERER_VERSION
    ai_enabled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id, "capture_id": self.capture_id,
            "run_id": self.run_id, "generated_at": self.generated_at,
            "posture_schema_version": self.posture_schema_version,
            "posture_engine_version": self.posture_engine_version,
            "report_schema_version": self.report_schema_version,
            "renderer_version": self.renderer_version,
            "ai_enabled": self.ai_enabled,
        }


@dataclass
class ReportDocument:
    """The whole report, decided. Renderers choose presentation only."""
    metadata: ReportMetadata
    title: str = REPORT_TITLE
    subtitle: str = REPORT_SUBTITLE
    #: The headline verdict, verbatim from `overall_posture`.
    overall_posture: str = ""
    #: Human-readable posture label. Underscores become spaces; meaning is unchanged.
    overall_posture_label: str = ""
    score_text: str = ""
    coverage_text: str = ""
    sections: List[Section] = field(default_factory=list)
    #: Recorded when a limit in doc 22 §15 truncated content. Always surfaced.
    truncations: List[str] = field(default_factory=list)

    def section(self, section_id: str) -> Optional[Section]:
        for s in self.sections:
            if s.section_id == section_id:
                return s
        return None

    @property
    def section_ids(self) -> Tuple[str, ...]:
        return tuple(s.section_id for s in self.sections)

    def to_dict(self) -> Dict[str, Any]:
        """Structural view, used by tests and by the report metadata endpoint."""
        return {
            "metadata": self.metadata.to_dict(),
            "title": self.title, "subtitle": self.subtitle,
            "overall_posture": self.overall_posture,
            "score_text": self.score_text,
            "coverage_text": self.coverage_text,
            "sections": [s.section_id for s in self.sections],
            "truncations": list(self.truncations),
        }


#: Ordered section identifiers. The report renders in this order; a section with no
#: canonical data is omitted, EXCEPT the four in ALWAYS_PRESENT below.
SECTION_ORDER = (
    "executive-summary",
    "scope",
    "posture",
    "coverage",
    "protocol-posture",
    "prioritised-findings",
    "issue-detail",
    "standards",
    "remediation",
    "ml-transparency",
    "abstentions",
    "limitations",
    "provenance",
    "methodology",
)

#: Sections that render even when empty, stating the absence explicitly. Omitting any of
#: these would hide a limitation rather than merely omitting data (doc 22 §4).
ALWAYS_PRESENT = ("coverage", "ml-transparency", "abstentions", "limitations")
