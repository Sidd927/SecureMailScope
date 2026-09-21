"""
DashboardViewModel — the dashboard's data contract (doc 23 §3, §4).

One structure, produced in Python and consumed by ES modules over JSON. It is a
**presentation** contract: every security value in it was copied out of
`PostureAssessment.to_dict()` and carries its canonical spelling alongside its label.

Three properties the shape exists to hold:

1. **Canonical value and display label travel together.** Every enum field appears twice
   — `severity` (canonical, e.g. `MEDIUM`) and `severity_label` (display). The UI filters
   and compares on the canonical value and renders the label, so presentation can never
   become the thing the code reasons about.

2. **Nothing is dropped.** The projection reorganises; it does not summarise away. Tests
   assert every issue group, prioritised entry, abstention, limitation and standard in
   the assessment reaches the view model.

3. **Absence is a value.** `None` stays `None`; it is never coerced to `0`, `""` or
   `"unknown"`. A missing protocol, an empty frame list and a withheld score are each
   distinguishable from a present one.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

#: Bumped when the view-model shape changes. Independent of the posture schema, the
#: report schema and the backend schema — they describe different things.
DASHBOARD_SCHEMA_VERSION = "1.0"
PROJECTION_VERSION = "0.10.0"


@dataclass(frozen=True)
class Identity:
    """Which assessment this view describes. Shown on every screen."""
    assessment_id: str
    capture_id: str
    run_id: Optional[str]
    #: The ANALYSIS time, taken from the assessment — never a render time.
    generated_at: str
    posture_schema_version: str
    posture_engine_version: str
    ai_enabled: bool
    dashboard_schema_version: str = DASHBOARD_SCHEMA_VERSION
    projection_version: str = PROJECTION_VERSION


@dataclass(frozen=True)
class ScoreComponentRow:
    issue_class: str
    issue_class_label: str
    severity: Optional[str]
    severity_label: str
    recurrence: Optional[int]
    base_weight: Optional[float]
    recurrence_multiplier: Optional[float]
    penalty: Optional[float]
    explanation: str


@dataclass(frozen=True)
class Posture:
    """The headline verdict. `withheld` is a fact about the engine's decision, not a
    presentation choice: Phase 7 withholds the band below the coverage floor."""
    value: str
    label: str
    tone: str
    known: bool
    withheld: bool
    withheld_note: str
    score_value: Optional[float]
    score_text: str
    formula_id: Optional[str]
    starting_value: Optional[float]
    total_penalty: Optional[float]
    basis: str
    components: List[ScoreComponentRow] = field(default_factory=list)


@dataclass(frozen=True)
class Coverage:
    """Always rendered beside the posture. There is no view that separates them."""
    sessions_total: Optional[int]
    sessions_assessed: Optional[int]
    sessions_abstained: Optional[int]
    assessed_fraction: Optional[float]
    percent_text: str
    summary_text: str
    observation_counts: Dict[str, int] = field(default_factory=dict)
    observation_fractions: Dict[str, float] = field(default_factory=dict)
    completeness_counts: Dict[str, int] = field(default_factory=dict)
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    present: bool = True


@dataclass(frozen=True)
class Bar:
    """One row of a distribution. `value_text` is mandatory — a chart whose numbers
    cannot be read as text is decoration (doc 22 §8, carried into doc 23 §4b)."""
    key: str
    label: str
    value: float
    max_value: float
    value_text: str
    tone: str = "neutral"

    @property
    def fraction(self) -> float:
        return (self.value / self.max_value) if self.max_value else 0.0


@dataclass(frozen=True)
class Distribution:
    """A named group of bars, built from counts the assessment already computed."""
    id: str
    caption: str
    note: str
    bars: List[Bar] = field(default_factory=list)


@dataclass(frozen=True)
class ProtocolRow:
    protocol: str
    sessions: Optional[int]
    band: Optional[str]
    band_label: str
    band_tone: str
    score_value: Optional[float]
    score_text: str
    issue_classes: List[str] = field(default_factory=list)
    dimensions_assessed: List[str] = field(default_factory=list)
    dimensions_not_observable: List[str] = field(default_factory=list)
    abstentions: Optional[int] = None


@dataclass(frozen=True)
class Citation:
    standard: str
    section: str
    reason: str
    text: str


@dataclass(frozen=True)
class Remediation:
    observed: str
    why_it_matters: str
    recommended_action: str
    affected_scope: str
    verification: str
    citations: List[Citation] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class FindingRow:
    """One prioritised finding, in the order the assessment supplied it.

    Severity, priority and ML adjustment are three separate fields and are never merged
    into a single "risk" number: they answer different questions.
    """
    rank: Optional[int]
    priority_score: Optional[float]
    ml_adjustment: Optional[float]
    affected_sessions: Optional[int]
    affected_stream_keys: List[str]

    severity: Optional[str]
    severity_label: str
    severity_marker: str
    severity_tone: str
    severity_known: bool

    status: Optional[str]
    status_label: str
    certainty: Optional[str]
    certainty_label: str
    observability: Optional[str]
    observability_label: str

    issue_class: Optional[str]
    issue_class_label: str
    fact_kind: Optional[str]
    fact_kind_label: str
    dimension: Optional[str]
    dimension_label: str

    #: Canonical value. **Nullable** — verified on a real capture, where the ANOMALY
    #: entry carried `session.protocol = None`. Never coerced to a string.
    protocol: Optional[str]
    #: Filter key: the protocol, or the unattributed sentinel. Presentation only.
    protocol_key: str
    protocol_label: str

    title: str
    conclusion: str
    explanation: str
    penalising: bool

    stream_key: Optional[str]
    tcp_stream_id: Optional[int]
    frames: List[int] = field(default_factory=list)
    frames_text: str = ""
    source_rule_ids: List[str] = field(default_factory=list)
    citations: List[Citation] = field(default_factory=list)
    remediation: Optional[Remediation] = None
    contradictions: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    factors: Dict[str, float] = field(default_factory=dict)
    explanation_priority: str = ""


@dataclass(frozen=True)
class IssueGroupRow:
    issue_class: Optional[str]
    issue_class_label: str
    title: str
    severity: Optional[str]
    severity_label: str
    severity_marker: str
    severity_tone: str
    fact_kind: Optional[str]
    fact_kind_label: str
    dimension: Optional[str]
    dimension_label: str
    certainty: Optional[str]
    certainty_label: str
    recurrence: Optional[int]
    protocols: List[str] = field(default_factory=list)
    affected_stream_keys: List[str] = field(default_factory=list)
    penalising: bool = False
    finding_count: Optional[int] = None
    citations: List[Citation] = field(default_factory=list)
    remediation: Optional[Remediation] = None


@dataclass(frozen=True)
class AbstentionRow:
    """An explicit refusal to conclude. Neither a failure nor a pass."""
    reason: Optional[str]
    reason_label: str
    issue_class: Optional[str]
    issue_class_label: str
    what_could_not_be_concluded: str
    why: str
    resolved_by: str
    rule_id: str
    protocol: Optional[str]
    protocol_label: str
    stream_key: Optional[str]
    frames: List[int] = field(default_factory=list)


@dataclass(frozen=True)
class StandardRow:
    standard: str
    sections: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class Standards:
    standards: List[StandardRow] = field(default_factory=list)
    distinct_standards: Optional[int] = None
    #: Citations the registry could not map. A gap the engine reports about itself;
    #: surfaced rather than hidden (doc 23 §7).
    unmapped_citations: List[str] = field(default_factory=list)
    note: str = ""
    present: bool = True


@dataclass(frozen=True)
class MLPanel:
    """What the ML lane did, and what it is structurally unable to do."""
    enabled: bool
    role: str
    note: str
    facts: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    boundary_statement: str = ""


@dataclass(frozen=True)
class Provenance:
    rule_ids: List[str] = field(default_factory=list)
    source_counts: Dict[str, Any] = field(default_factory=dict)
    entries: Dict[str, Any] = field(default_factory=dict)
    note: str = ""


@dataclass(frozen=True)
class FilterOption:
    """One selectable value, with how many rows carry it. Built only from values
    actually present in this assessment."""
    value: str
    label: str
    count: int


@dataclass(frozen=True)
class Filters:
    """Options for the findings view. Every facet is a field verified present in the
    canonical schema (doc 23 §7). No facet is offered for a field that does not exist."""
    severity: List[FilterOption] = field(default_factory=list)
    status: List[FilterOption] = field(default_factory=list)
    certainty: List[FilterOption] = field(default_factory=list)
    observability: List[FilterOption] = field(default_factory=list)
    fact_kind: List[FilterOption] = field(default_factory=list)
    issue_class: List[FilterOption] = field(default_factory=list)
    dimension: List[FilterOption] = field(default_factory=list)
    protocol: List[FilterOption] = field(default_factory=list)


@dataclass
class DashboardViewModel:
    """Everything the four screens need, from one assessment."""
    identity: Identity
    posture: Posture
    coverage: Coverage
    distributions: List[Distribution] = field(default_factory=list)
    protocols: List[ProtocolRow] = field(default_factory=list)
    findings: List[FindingRow] = field(default_factory=list)
    issue_groups: List[IssueGroupRow] = field(default_factory=list)
    abstentions: List[AbstentionRow] = field(default_factory=list)
    standards: Optional[Standards] = None
    remediation: List[Remediation] = field(default_factory=list)
    ml: Optional[MLPanel] = None
    provenance: Optional[Provenance] = None
    limitations: List[str] = field(default_factory=list)
    filters: Optional[Filters] = None
    #: Statements the UI must show prominently — withheld bands, absent coverage.
    notices: List[str] = field(default_factory=list)
    #: Data this dashboard cannot show, stated rather than approximated (doc 23 §4c).
    unavailable: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-ready. `None` is preserved as `null`; nothing is coerced."""
        return asdict(self)
