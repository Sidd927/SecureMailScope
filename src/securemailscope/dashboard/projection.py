"""
Assessment -> DashboardViewModel (doc 23 §4, §5, ADR-0022 Decision 2).

**This module reorganises. It never reinterprets.**

Every severity, band, score, certainty, observability, recurrence, status, remediation
string and standards citation is copied out of the canonical document. The only numbers
computed here are presentation scaling factors — a bar's maximum, and counts of how many
rows carry a filter value — and neither is a security quantity.

What it must never do, and does not: derive a severity, threshold a score, decide that
something "is an attack" or "is safe", reorder `prioritised`, collapse
`NOT_OBSERVABLE` / `AMBIGUOUS` / `INSUFFICIENT_EVIDENCE`, or coerce a missing value into
a present one.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from securemailscope.dashboard import vocabulary as vocab
from securemailscope.dashboard.errors import MalformedAssessment
from securemailscope.dashboard.model import (
    AbstentionRow, Bar, Citation, Coverage, Distribution, DashboardViewModel,
    FilterOption, Filters, FindingRow, Identity, IssueGroupRow, MLPanel, Posture,
    ProtocolRow, Provenance, Remediation, ScoreComponentRow, StandardRow, Standards,
)

#: Keys that make a document a PostureAssessment. Absent -> refuse rather than guess.
REQUIRED_KEYS = ("assessment_id", "capture_id", "overall_posture", "versions")

#: Data the canonical contract does not carry. Stated in the UI, never approximated.
UNAVAILABLE = (
    "Per-session finding rows: the canonical assessment exposes issue groups and "
    "prioritised representatives, not one row per session.",
    "Packet-level and byte-level drill-down: the dashboard has no access to the "
    "capture and the API exposes no packet endpoint.",
    "Any attack probability, confidence percentage, compliance percentage or risk "
    "percentage: no phase of this system computes one.",
)

ML_BOUNDARY = (
    "The machine-learning lane contributes a bounded adjustment to the order in which "
    "findings are presented. It does not determine any security fact, does not set or "
    "change a severity, does not create a finding, and does not affect the posture "
    "score. Its adjustment is arithmetically smaller than the gap between severity "
    "tiers, so it cannot move a finding from one tier to another."
)


# --------------------------------------------------------------------- helpers
def _num(value: Any) -> Optional[float]:
    """Numbers stay numbers; anything else stays None. Never coerced to 0."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _str(value: Any, empty: str = "") -> str:
    """Render a scalar as text. Absence becomes `empty`, never the word 'None'."""
    if value is None:
        return empty
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, float):
        return ("%.2f" % value).rstrip("0").rstrip(".")
    return str(value)


def _list(value: Any) -> List[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _dict(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _percent(fraction: Optional[float]) -> str:
    return "%.1f%%" % (fraction * 100.0) if fraction is not None else "—"


def _citations(raw: Any) -> List[Citation]:
    out: List[Citation] = []
    for item in _list(raw):
        d = _dict(item)
        out.append(Citation(standard=_str(d.get("standard")),
                            section=_str(d.get("section")),
                            reason=_str(d.get("reason")),
                            text=_str(d.get("text"))))
    return out


def _remediation(raw: Any) -> Optional[Remediation]:
    d = _dict(raw)
    if not d:
        return None
    return Remediation(
        observed=_str(d.get("observed")),
        why_it_matters=_str(d.get("why_it_matters")),
        recommended_action=_str(d.get("recommended_action")),
        affected_scope=_str(d.get("affected_scope")),
        verification=_str(d.get("verification")),
        citations=_citations(d.get("citations")),
        limitations=[_str(x) for x in _list(d.get("limitations"))])


def _frames_text(frames: Sequence[Any], limit: int = 12) -> str:
    """Frame references, bounded. An empty list says so rather than showing nothing."""
    values = [str(f) for f in frames]
    if not values:
        return "no frame references recorded"
    if len(values) <= limit:
        return ", ".join(values)
    return "%s, … (%d total)" % (", ".join(values[:limit]), len(values))


# ------------------------------------------------------------------ projection
def project(assessment: Dict[str, Any]) -> DashboardViewModel:
    """Build the view model from a canonical assessment dictionary."""
    if not isinstance(assessment, dict):
        raise MalformedAssessment("assessment must be a mapping",
                                  detail={"type": type(assessment).__name__})
    missing = [k for k in REQUIRED_KEYS if k not in assessment]
    if missing:
        raise MalformedAssessment(
            "assessment is missing required canonical keys",
            detail={"missing": missing})

    notices: List[str] = []
    identity = _identity(assessment)
    posture = _posture(assessment, notices)
    coverage = _coverage(assessment, notices)
    findings = _findings(assessment)

    return DashboardViewModel(
        identity=identity,
        posture=posture,
        coverage=coverage,
        distributions=_distributions(assessment),
        protocols=_protocols(assessment),
        findings=findings,
        issue_groups=_issue_groups(assessment),
        abstentions=_abstentions(assessment),
        standards=_standards(assessment),
        remediation=[r for r in (_remediation(x)
                                 for x in _list(assessment.get("remediation_summary")))
                     if r is not None],
        ml=_ml(assessment),
        provenance=_provenance(assessment),
        limitations=[_str(x) for x in _list(assessment.get("limitations"))],
        filters=_filters(findings),
        notices=notices,
        unavailable=list(UNAVAILABLE),
    )


def _identity(a: Dict[str, Any]) -> Identity:
    versions = _dict(a.get("versions"))
    return Identity(
        assessment_id=_str(a.get("assessment_id")),
        capture_id=_str(a.get("capture_id")),
        run_id=a.get("run_id"),
        generated_at=_str(a.get("generated_at"), "not recorded"),
        posture_schema_version=_str(versions.get("schema"), "unknown"),
        posture_engine_version=_str(versions.get("engine"), "unknown"),
        ai_enabled=bool(a.get("ai_enabled")))


def _posture(a: Dict[str, Any], notices: List[str]) -> Posture:
    value = _str(a.get("overall_posture"))
    score = _dict(a.get("score"))
    score_value = _num(score.get("value"))
    withheld = value == "INSUFFICIENT_EVIDENCE"

    if withheld:
        notices.append(
            "The posture band is withheld. Evidence coverage is below the threshold at "
            "which this system is willing to grade a capture. A withheld band is not a "
            "passing result and must not be read as one.")

    components = []
    for raw in _list(score.get("components")):
        d = _dict(raw)
        issue_class = _str(d.get("issue_class"))
        severity = d.get("severity")
        components.append(ScoreComponentRow(
            issue_class=issue_class,
            issue_class_label=vocab.humanise(issue_class),
            severity=severity,
            severity_label=vocab.label("severity", severity),
            recurrence=_int(d.get("recurrence")),
            base_weight=_num(d.get("base_weight")),
            recurrence_multiplier=_num(d.get("recurrence_multiplier")),
            penalty=_num(d.get("penalty")),
            explanation=_str(d.get("explanation"))))

    return Posture(
        value=value,
        label=vocab.label("posture", value),
        tone=vocab.posture_tone(value),
        known=vocab.is_known("posture", value),
        withheld=withheld,
        withheld_note=("band withheld: evidence coverage below the assessment floor"
                       if withheld else ""),
        score_value=score_value,
        score_text=("%s / 100" % _str(score_value)) if score_value is not None
                   else "Not scored",
        formula_id=score.get("formula_id"),
        starting_value=_num(score.get("starting_value")),
        total_penalty=_num(score.get("total_penalty")),
        basis=_str(score.get("basis")),
        components=components)


def _coverage(a: Dict[str, Any], notices: List[str]) -> Coverage:
    c = _dict(a.get("coverage"))
    if not c:
        notices.append(
            "This assessment carries no coverage information. A posture claim cannot "
            "be qualified without it and should be treated with corresponding caution.")
        return Coverage(sessions_total=None, sessions_assessed=None,
                        sessions_abstained=None, assessed_fraction=None,
                        percent_text="—",
                        summary_text="No coverage information recorded",
                        present=False)

    fraction = _num(c.get("assessed_fraction"))
    total = _int(c.get("sessions_total"))
    assessed = _int(c.get("sessions_assessed"))
    return Coverage(
        sessions_total=total,
        sessions_assessed=assessed,
        sessions_abstained=_int(c.get("sessions_abstained")),
        assessed_fraction=fraction,
        percent_text=_percent(fraction),
        summary_text="%s (%s of %s sessions assessed)" % (
            _percent(fraction), _str(assessed, "?"), _str(total, "?")),
        observation_counts=_dict(c.get("observation_counts")),
        observation_fractions=_dict(c.get("observation_fractions")),
        completeness_counts=_dict(c.get("completeness_counts")),
        protocol_counts=_dict(c.get("protocol_counts")))


def _bars(counts: Dict[str, Any], vocabulary: str, *,
          order: Optional[Sequence[str]] = None,
          toned: bool = False) -> List[Bar]:
    """Turn existing counts into bar rows.

    `max_value` is a presentation scaling factor, not a security quantity: it exists so
    a bar has a width.
    """
    items = [(k, _num(v)) for k, v in counts.items()]
    items = [(k, v) for k, v in items if v is not None]
    if not items:
        return []
    if order:
        rank = {name: i for i, name in enumerate(order)}
        items.sort(key=lambda kv: (rank.get(kv[0], len(order)), kv[0]))
    else:
        items.sort(key=lambda kv: kv[0])
    peak = max(v for _k, v in items)
    return [Bar(key=k, label=vocab.label(vocabulary, k) or vocab.humanise(k),
                value=v, max_value=peak, value_text=_str(_int(v) if v.is_integer() else v),
                tone=vocab.tone(k) if toned else "neutral")
            for k, v in items]


def _distributions(a: Dict[str, Any]) -> List[Distribution]:
    risk = _dict(a.get("risk_summary"))
    out: List[Distribution] = []

    severity_bars = _bars(_dict(risk.get("by_severity")), "severity",
                          order=vocab.SEVERITY_ORDER, toned=True)
    if severity_bars:
        out.append(Distribution(
            id="by-severity", caption="Issue groups by severity",
            note="Counts of issue groups at each severity, as recorded by the "
                 "assessment.",
            bars=severity_bars))

    dimension_bars = _bars(_dict(risk.get("by_dimension")), "dimension")
    if dimension_bars:
        out.append(Distribution(
            id="by-dimension", caption="Issue groups by risk dimension",
            note="The analytical axis each condition sits on.",
            bars=dimension_bars))

    fact_kind_bars = _bars(_dict(risk.get("by_fact_kind")), "fact_kind")
    if fact_kind_bars:
        out.append(Distribution(
            id="by-fact-kind", caption="Findings by fact kind",
            note="Security issues, behavioural deviations, anomaly signals and "
                 "positive evidence are different kinds of fact and are never merged.",
            bars=fact_kind_bars))

    abstentions = _dict(risk.get("abstentions"))
    reason_bars = _bars(_dict(abstentions.get("by_reason")), "abstention_reason")
    if reason_bars:
        out.append(Distribution(
            id="abstentions-by-reason", caption="Abstentions by reason",
            note="Questions the assessment declined to answer. An abstention is "
                 "neither a failure nor a pass.",
            bars=reason_bars))
    return out


def _protocols(a: Dict[str, Any]) -> List[ProtocolRow]:
    out: List[ProtocolRow] = []
    for raw in _list(a.get("protocol_posture")):
        d = _dict(raw)
        score = _dict(d.get("score"))
        band = score.get("band")
        score_value = _num(score.get("value"))
        out.append(ProtocolRow(
            protocol=_str(d.get("protocol")),
            sessions=_int(d.get("sessions")),
            band=band,
            band_label=vocab.label("posture", band, empty="Not scored"),
            band_tone=vocab.posture_tone(band),
            score_value=score_value,
            score_text=_str(score_value, "—"),
            issue_classes=[_str(x) for x in _list(d.get("issue_classes"))],
            dimensions_assessed=[_str(x) for x in _list(d.get("dimensions_assessed"))],
            dimensions_not_observable=[
                _str(x) for x in _list(d.get("dimensions_not_observable"))],
            abstentions=_int(d.get("abstentions"))))
    return out


def _findings(a: Dict[str, Any]) -> List[FindingRow]:
    """Prioritised entries, in the order the assessment supplied. No sort is applied."""
    out: List[FindingRow] = []
    for raw in _list(a.get("prioritised")):
        entry = _dict(raw)
        finding = _dict(entry.get("representative_finding"))
        key = _dict(finding.get("key"))
        session = _dict(finding.get("session"))

        severity = finding.get("severity")
        issue_class = key.get("issue_class")
        fact_kind = key.get("fact_kind")
        dimension = finding.get("dimension")
        # Nullable by design: an ANOMALY entry carries no protocol. Preserved as None
        # and given an explicit key so a filter cannot silently drop it.
        protocol = session.get("protocol")
        frames = [f for f in _list(finding.get("frames"))]

        out.append(FindingRow(
            rank=_int(entry.get("rank")),
            priority_score=_num(entry.get("priority_score")),
            ml_adjustment=_num(entry.get("ml_adjustment")),
            affected_sessions=_int(entry.get("affected_sessions")),
            affected_stream_keys=[_str(x)
                                  for x in _list(entry.get("affected_stream_keys"))],
            severity=severity,
            severity_label=vocab.label("severity", severity),
            severity_marker=vocab.severity_marker(severity),
            severity_tone=vocab.tone(severity),
            severity_known=vocab.is_known("severity", severity),
            status=finding.get("status"),
            status_label=vocab.label("status", finding.get("status")),
            certainty=finding.get("certainty"),
            certainty_label=vocab.label("certainty", finding.get("certainty")),
            observability=finding.get("observability"),
            observability_label=vocab.label("observability",
                                            finding.get("observability")),
            issue_class=issue_class,
            issue_class_label=vocab.humanise(issue_class),
            fact_kind=fact_kind,
            fact_kind_label=vocab.label("fact_kind", fact_kind),
            dimension=dimension,
            dimension_label=vocab.label("dimension", dimension),
            protocol=protocol,
            protocol_key=_str(protocol) or vocab.PROTOCOL_UNATTRIBUTED,
            protocol_label=_str(protocol) or vocab.PROTOCOL_UNATTRIBUTED_LABEL,
            title=_str(finding.get("title")),
            conclusion=_str(finding.get("conclusion")),
            explanation=_str(finding.get("explanation")),
            penalising=bool(finding.get("penalising")),
            stream_key=session.get("stream_key"),
            tcp_stream_id=_int(session.get("tcp_stream_id")),
            frames=frames,
            frames_text=_frames_text(frames),
            source_rule_ids=[_str(x) for x in _list(finding.get("source_rule_ids"))],
            citations=_citations(finding.get("citations")),
            remediation=_remediation(finding.get("remediation")),
            contradictions=[_str(x) for x in _list(finding.get("contradictions"))],
            limitations=[_str(x) for x in _list(finding.get("limitations"))],
            factors={k: v for k, v in _dict(entry.get("factors")).items()
                     if isinstance(v, (int, float)) and not isinstance(v, bool)},
            explanation_priority=_str(entry.get("explanation"))))
    return out


def _issue_groups(a: Dict[str, Any]) -> List[IssueGroupRow]:
    out: List[IssueGroupRow] = []
    for raw in _list(a.get("issue_groups")):
        d = _dict(raw)
        severity = d.get("severity")
        issue_class = d.get("issue_class")
        out.append(IssueGroupRow(
            issue_class=issue_class,
            issue_class_label=vocab.humanise(issue_class),
            title=_str(d.get("title")),
            severity=severity,
            severity_label=vocab.label("severity", severity),
            severity_marker=vocab.severity_marker(severity),
            severity_tone=vocab.tone(severity),
            fact_kind=d.get("fact_kind"),
            fact_kind_label=vocab.label("fact_kind", d.get("fact_kind")),
            dimension=d.get("dimension"),
            dimension_label=vocab.label("dimension", d.get("dimension")),
            certainty=d.get("certainty"),
            certainty_label=vocab.label("certainty", d.get("certainty")),
            recurrence=_int(d.get("recurrence")),
            protocols=[_str(x) for x in _list(d.get("protocols"))],
            affected_stream_keys=[_str(x)
                                  for x in _list(d.get("affected_stream_keys"))],
            penalising=bool(d.get("penalising")),
            finding_count=_int(d.get("finding_count")),
            citations=_citations(d.get("citations")),
            remediation=_remediation(d.get("remediation"))))
    return out


def _abstentions(a: Dict[str, Any]) -> List[AbstentionRow]:
    out: List[AbstentionRow] = []
    for raw in _list(a.get("abstentions")):
        d = _dict(raw)
        protocol = d.get("protocol")
        issue_class = d.get("issue_class")
        out.append(AbstentionRow(
            reason=d.get("reason"),
            reason_label=vocab.label("abstention_reason", d.get("reason")),
            issue_class=issue_class,
            issue_class_label=vocab.humanise(issue_class),
            what_could_not_be_concluded=_str(d.get("what_could_not_be_concluded")),
            why=_str(d.get("why")),
            resolved_by=_str(d.get("resolved_by")),
            rule_id=_str(d.get("rule_id")),
            protocol=protocol,
            protocol_label=_str(protocol) or vocab.PROTOCOL_UNATTRIBUTED_LABEL,
            stream_key=d.get("stream_key"),
            frames=[f for f in _list(d.get("frames"))]))
    return out


def _standards(a: Dict[str, Any]) -> Standards:
    summary = _dict(a.get("standards_summary"))
    if not summary:
        return Standards(present=False)
    rows = [StandardRow(standard=_str(name),
                        sections=[_str(s) for s in _list(sections)])
            for name, sections in sorted(_dict(summary.get("standards")).items())]
    return Standards(
        standards=rows,
        distinct_standards=_int(summary.get("distinct_standards")),
        unmapped_citations=[_str(x) for x in _list(summary.get("unmapped_citations"))],
        note=_str(summary.get("note")))


def _ml(a: Dict[str, Any]) -> MLPanel:
    summary = a.get("model_summary")
    ai_enabled = bool(a.get("ai_enabled"))
    if not isinstance(summary, dict) or not summary:
        return MLPanel(
            enabled=ai_enabled, role="", note=(
                "The machine-learning lane was not used. Every conclusion in this "
                "assessment comes from deterministic rules and cross-session "
                "reasoning."), boundary_statement=ML_BOUNDARY)

    enabled = bool(summary.get("ai_enabled", ai_enabled))
    facts = {k: v for k, v in summary.items()
             if k not in ("limitations", "note", "role", "ai_enabled")}
    return MLPanel(
        enabled=enabled,
        role=_str(summary.get("role")),
        note=_str(summary.get("note")),
        facts=facts,
        limitations=[_str(x) for x in _list(summary.get("limitations"))],
        boundary_statement=ML_BOUNDARY)


def _provenance(a: Dict[str, Any]) -> Provenance:
    p = _dict(a.get("provenance"))
    return Provenance(
        rule_ids=[_str(x) for x in _list(p.get("rule_ids"))],
        source_counts=_dict(p.get("source_counts")),
        entries={k: v for k, v in p.items()
                 if k not in ("rule_ids", "source_counts", "note")},
        note=_str(p.get("note")))


def _options(rows: Sequence[FindingRow], value_attr: str,
             label_attr: str) -> List[FilterOption]:
    """Filter options built only from values actually present in this assessment."""
    counts: Dict[str, int] = {}
    labels: Dict[str, str] = {}
    for row in rows:
        value = getattr(row, value_attr)
        if value is None:
            continue
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
        labels.setdefault(key, getattr(row, label_attr) or key)
    return [FilterOption(value=k, label=labels[k], count=counts[k])
            for k in sorted(counts)]


def _filters(rows: Sequence[FindingRow]) -> Filters:
    severity = _options(rows, "severity", "severity_label")
    severity.sort(key=lambda o: vocab.severity_index(o.value))
    return Filters(
        severity=severity,
        status=_options(rows, "status", "status_label"),
        certainty=_options(rows, "certainty", "certainty_label"),
        observability=_options(rows, "observability", "observability_label"),
        fact_kind=_options(rows, "fact_kind", "fact_kind_label"),
        issue_class=_options(rows, "issue_class", "issue_class_label"),
        dimension=_options(rows, "dimension", "dimension_label"),
        # protocol_key is never None, so unattributed findings get their own option
        # instead of vanishing from the facet.
        protocol=_options(rows, "protocol_key", "protocol_label"))
