"""
Assessment -> ReportDocument projection (doc 22 §4, §5, ADR-0019 Decision 1).

**This module reorders, groups, labels and formats. It never reinterprets.**

Every severity, band, score, certainty, observability, recurrence, remediation string
and standards citation is copied out of the canonical document as-is. No arithmetic is
performed on any of them. The prioritised list is rendered in the order the assessment
supplies; no sort key is applied to it.

`fused_findings` is not part of `PostureAssessment.to_dict()`. The projection therefore
builds its detail from `issue_groups` and the `prioritised[].representative_finding`
entries, and **fabricates no per-session finding rows** (doc 22 §5).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from securemailscope.reporting import styles
from securemailscope.reporting.errors import MalformedAssessment
from securemailscope.reporting.model import (
    ALWAYS_PRESENT, Bar, KeyValue, ReportDocument, ReportMetadata, Section, Table,
)

#: Keys the canonical document must carry. Absence means the input is not a
#: PostureAssessment, and the projection refuses rather than guessing (doc 22 §16).
REQUIRED_KEYS = ("assessment_id", "capture_id", "overall_posture", "versions")

#: Limits (doc 22 §15). Truncation is always disclosed in the document.
MAX_REPORT_FINDINGS = 500
MAX_EVIDENCE_CHARS = 2000

NOT_PRESENT = "Not present in assessment"


# --------------------------------------------------------------------- helpers
def _text(value: Any, fallback: str = "") -> str:
    """Render any canonical value as display text without changing its meaning."""
    if value is None:
        return fallback
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, float):
        return ("%.2f" % value).rstrip("0").rstrip(".")
    return str(value)


def _clip(value: str, limit: int, truncations: List[str], what: str) -> str:
    """Bound one field, recording the fact. Silent truncation is forbidden."""
    if len(value) <= limit:
        return value
    truncations.append(
        "{0} truncated to {1} characters (original {2})".format(what, limit, len(value)))
    return value[:limit] + " […truncated]"


def _pct(fraction: Optional[float]) -> str:
    if fraction is None:
        return NOT_PRESENT
    return "%.1f%%" % (fraction * 100.0)


def _join(values: Sequence[str], empty: str = "—") -> str:
    kept = [v for v in values if v]
    return " · ".join(kept) if kept else empty


# ------------------------------------------------------------------ projection
def project(assessment: Dict[str, Any]) -> ReportDocument:
    """Build the report document from a canonical assessment dictionary."""
    if not isinstance(assessment, dict):
        raise MalformedAssessment("assessment must be a mapping",
                                  detail={"type": type(assessment).__name__})
    missing = [k for k in REQUIRED_KEYS if k not in assessment]
    if missing:
        raise MalformedAssessment(
            "assessment is missing required canonical keys",
            detail={"missing": missing})

    truncations: List[str] = []
    versions = assessment.get("versions") or {}
    posture = _text(assessment.get("overall_posture"))

    metadata = ReportMetadata(
        assessment_id=_text(assessment.get("assessment_id")),
        capture_id=_text(assessment.get("capture_id")),
        run_id=assessment.get("run_id"),
        generated_at=_text(assessment.get("generated_at"), "not recorded"),
        posture_schema_version=_text(versions.get("schema"), "unknown"),
        posture_engine_version=_text(versions.get("engine"), "unknown"),
        ai_enabled=bool(assessment.get("ai_enabled")),
    )

    score = assessment.get("score") or {}
    coverage = assessment.get("coverage") or {}
    score_text = (_text(score.get("value")) + " / 100") if score.get("value") is not None \
        else "Not scored"
    coverage_text = _coverage_text(coverage)

    doc = ReportDocument(
        metadata=metadata,
        overall_posture=posture,
        overall_posture_label=styles.posture_label(posture),
        score_text=score_text,
        coverage_text=coverage_text,
    )

    builders = (
        _executive_summary, _scope, _posture, _coverage, _protocol_posture,
        _prioritised, _issue_detail, _standards, _remediation, _ml_transparency,
        _abstentions, _limitations, _provenance, _methodology,
    )
    for build in builders:
        section = build(assessment, doc, truncations)
        if section is None:
            continue
        if section.is_empty and section.section_id not in ALWAYS_PRESENT:
            continue
        doc.sections.append(section)

    doc.truncations = truncations
    return doc


def _coverage_text(coverage: Dict[str, Any]) -> str:
    if not coverage:
        return NOT_PRESENT
    fraction = coverage.get("assessed_fraction")
    assessed = coverage.get("sessions_assessed")
    total = coverage.get("sessions_total")
    if fraction is None and total is None:
        return NOT_PRESENT
    return "{0} ({1} of {2} sessions assessed)".format(
        _pct(fraction), _text(assessed, "?"), _text(total, "?"))


# ------------------------------------------------------------------- sections
def _executive_summary(a: Dict[str, Any], doc: ReportDocument,
                       trunc: List[str]) -> Section:
    """Posture and coverage in one block. There is no layout separating them (§7)."""
    coverage = a.get("coverage") or {}
    score = a.get("score") or {}
    protocols = sorted((coverage.get("protocol_counts") or {}).keys())
    groups = a.get("issue_groups") or []
    penalising = [g for g in groups if g.get("penalising")]

    section = Section(
        section_id="executive-summary",
        title="Executive summary",
        facts=[
            KeyValue("Overall posture", doc.overall_posture_label,
                     "withheld: evidence coverage below the assessment floor"
                     if doc.overall_posture == "INSUFFICIENT_EVIDENCE" else ""),
            KeyValue("Posture score", doc.score_text,
                     _text(score.get("formula_id"), "")),
            KeyValue("Evidence coverage", doc.coverage_text),
            KeyValue("Protocols observed", _join(protocols, "None observed")),
            KeyValue("Issue groups", "{0} total · {1} penalising the score".format(
                len(groups), len(penalising))),
            KeyValue("Abstentions", _text(len(a.get("abstentions") or []))),
            KeyValue("ML lane", "Enabled" if doc.metadata.ai_enabled else "Disabled"),
        ],
    )

    # Factual narrative, assembled only from values present in the assessment.
    total = coverage.get("sessions_total")
    assessed = coverage.get("sessions_assessed")
    if total is not None:
        section.paragraphs.append(
            "{0} session(s) were reconstructed from the capture; {1} were assessed and "
            "{2} were abstained from.".format(
                _text(total), _text(assessed, "0"),
                _text(coverage.get("sessions_abstained"), "0")))
    if penalising:
        worst = min(penalising, key=lambda g: styles.severity_rank(
            _text(g.get("severity"))))
        section.paragraphs.append(
            "{0} issue group(s) penalise the posture score. The highest severity "
            "recorded is {1}.".format(len(penalising), _text(worst.get("severity"))))
    elif groups:
        section.paragraphs.append(
            "No issue group penalises the posture score. Groups present are "
            "informational or positive evidence.")
    else:
        section.paragraphs.append(
            "No issue groups were produced for this capture.")

    if doc.overall_posture == "INSUFFICIENT_EVIDENCE":
        section.notices.append(
            "The posture band is withheld. Evidence coverage is below the threshold at "
            "which this system is willing to grade a capture. A withheld band is not a "
            "passing result and must not be read as one.")
    return section


def _scope(a: Dict[str, Any], doc: ReportDocument, trunc: List[str]) -> Section:
    coverage = a.get("coverage") or {}
    protocol_counts = coverage.get("protocol_counts") or {}
    rows = tuple((proto, _text(count))
                 for proto, count in sorted(protocol_counts.items()))
    section = Section(
        section_id="scope", title="Assessment scope",
        lead="What this assessment covers, and what it structurally cannot.",
        facts=[
            KeyValue("Analysis type", "Passive PCAP analysis"),
            KeyValue("Capture identifier (SHA-256)", doc.metadata.capture_id or NOT_PRESENT),
            KeyValue("Analysis timestamp", doc.metadata.generated_at,
                     "time of analysis, not of report generation"),
        ],
        tables=[Table(
            caption="Sessions per protocol",
            columns=("Protocol", "Sessions"),
            rows=rows,
            empty_note="No protocol sessions were recorded in this assessment.")],
    )
    section.paragraphs.append(
        "SecureMailScope observes traffic that was already captured. It does not "
        "connect to any server, hold any private key, decrypt any session, or read "
        "message content. Anything that cannot be determined from the captured bytes "
        "is reported as not observable rather than inferred.")
    return section


def _posture(a: Dict[str, Any], doc: ReportDocument, trunc: List[str]) -> Section:
    score = a.get("score") or {}
    risk = a.get("risk_summary") or {}
    section = Section(section_id="posture", title="Overall security posture",
                      page_break_before=True)
    section.facts.append(KeyValue("Posture", doc.overall_posture_label))
    section.facts.append(KeyValue("Score", doc.score_text))
    section.facts.append(KeyValue("Evidence coverage", doc.coverage_text))
    if score.get("formula_id"):
        section.facts.append(KeyValue("Scoring formula", _text(score.get("formula_id"))))
    if score.get("basis"):
        section.paragraphs.append(_text(score.get("basis")))

    components = score.get("components") or []
    if components:
        section.tables.append(Table(
            caption="Score decomposition",
            columns=("Issue class", "Severity", "Recurrence", "Weight",
                     "Recurrence multiplier", "Penalty"),
            rows=tuple(
                (styles.humanise(_text(c.get("issue_class"))),
                 _text(c.get("severity")),
                 _text(c.get("recurrence")),
                 _text(c.get("base_weight")),
                 _text(c.get("recurrence_multiplier")),
                 "-" + _text(c.get("penalty")))
                for c in components),
            empty_note="No penalties were applied."))
        section.paragraphs.append(
            "The score starts at {0} and each penalty above is subtracted from it. "
            "Only observed issues penalise; compliant observations earn no credit, and "
            "missing evidence neither penalises nor rewards.".format(
                _text(score.get("starting_value"), "100")))

    counts = risk.get("by_severity") or risk.get("severity_counts") or {}
    if isinstance(counts, dict) and counts:
        peak = max((v for v in counts.values() if isinstance(v, (int, float))),
                   default=0)
        for severity in styles.SEVERITY_ORDER:
            if severity in counts:
                section.bars.append(Bar(
                    label=severity, value=float(counts[severity]),
                    max_value=float(peak or 1),
                    value_text=_text(counts[severity]), severity=severity))

    section.notices.append(
        "The severity weights and band thresholds behind this score are transparent "
        "engineering policy, not a calibrated measurement derived from incident data.")
    return section


def _coverage(a: Dict[str, Any], doc: ReportDocument, trunc: List[str]) -> Section:
    coverage = a.get("coverage") or {}
    section = Section(
        section_id="coverage", title="Evidence coverage",
        lead="How much of the captured traffic the analysis could actually assess.")
    if not coverage:
        section.notices.append(
            "This assessment carries no coverage information. A posture claim cannot be "
            "qualified without it and should be treated with corresponding caution.")
        return section

    section.facts = [
        KeyValue("Sessions total", _text(coverage.get("sessions_total"), "0")),
        KeyValue("Sessions assessed", _text(coverage.get("sessions_assessed"), "0")),
        KeyValue("Sessions abstained", _text(coverage.get("sessions_abstained"), "0")),
        KeyValue("Assessed fraction", _pct(coverage.get("assessed_fraction"))),
    ]

    observations = coverage.get("observation_counts") or {}
    fractions = coverage.get("observation_fractions") or {}
    if observations:
        section.tables.append(Table(
            caption="Evidence states observed across all fields",
            columns=("Evidence state", "Count", "Share"),
            rows=tuple(
                (state.replace("_", " "), _text(count),
                 _pct(fractions.get(state)) if state in fractions else "—")
                for state, count in sorted(observations.items())),
            empty_note="No evidence-state counts recorded."))

    completeness = coverage.get("completeness_counts") or {}
    if completeness:
        section.tables.append(Table(
            caption="Session completeness",
            columns=("Completeness", "Sessions"),
            rows=tuple((k.replace("_", " "), _text(v))
                       for k, v in sorted(completeness.items())),
            empty_note=""))

    section.paragraphs.append(
        "Coverage is reported beside the posture score and is never folded into it. A "
        "score computed over a small share of the traffic and the same score computed "
        "over nearly all of it are different claims.")
    if doc.overall_posture == "INSUFFICIENT_EVIDENCE":
        section.notices.append(
            "Coverage was insufficient for this system to issue a posture band.")
    return section


def _protocol_posture(a: Dict[str, Any], doc: ReportDocument,
                      trunc: List[str]) -> Section:
    entries = a.get("protocol_posture") or []
    if not entries:
        return Section(section_id="protocol-posture", title="Protocol posture")
    rows = []
    for entry in entries:
        score = entry.get("score") or {}
        rows.append((
            _text(entry.get("protocol")),
            _text(entry.get("sessions")),
            styles.posture_label(_text(score.get("band"))) if score else "Not scored",
            _text(score.get("value")) if score.get("value") is not None else "—",
            _join([d.replace("_", " ") for d in entry.get("dimensions_assessed") or []]),
            _join([d.replace("_", " ")
                   for d in entry.get("dimensions_not_observable") or []]),
            _text(entry.get("abstentions"), "0"),
        ))
    return Section(
        section_id="protocol-posture", title="Protocol posture",
        lead="Posture per protocol, across the dimensions the evidence supports.",
        tables=[Table(
            caption="Per-protocol posture",
            columns=("Protocol", "Sessions", "Band", "Score", "Dimensions assessed",
                     "Not observable", "Abstentions"),
            rows=tuple(rows), wide_columns=(4, 5),
            empty_note="No per-protocol posture recorded.")])


def _prioritised(a: Dict[str, Any], doc: ReportDocument, trunc: List[str]) -> Section:
    """Rendered in the order the assessment supplies. No sort key is applied (§5)."""
    entries = a.get("prioritised") or []
    section = Section(
        section_id="prioritised-findings", title="Prioritised findings",
        lead="Investigative priority, as ranked by the assessment. This ordering is "
             "not a severity ranking.",
        page_break_before=True)
    if not entries:
        return section

    if len(entries) > MAX_REPORT_FINDINGS:
        trunc.append("prioritised findings truncated to {0} of {1}".format(
            MAX_REPORT_FINDINGS, len(entries)))
        entries = entries[:MAX_REPORT_FINDINGS]

    rows = []
    for entry in entries:
        finding = entry.get("representative_finding") or {}
        key = finding.get("key") or {}
        severity = _text(finding.get("severity"))
        rows.append((
            _text(entry.get("rank")),
            styles.severity_marker(severity) + " " + severity,
            styles.humanise(_text(key.get("issue_class"))),
            styles.STATUS_LABEL.get(_text(finding.get("status")),
                                    _text(finding.get("status"))),
            styles.CERTAINTY_LABEL.get(_text(finding.get("certainty")),
                                       _text(finding.get("certainty"))),
            _text(entry.get("affected_sessions"), "1"),
            _text(entry.get("priority_score")),
            _text(entry.get("ml_adjustment"), "0"),
        ))
    section.tables.append(Table(
        caption="Findings in investigative priority order",
        columns=("Rank", "Severity", "Issue", "Status", "Certainty",
                 "Sessions", "Priority", "ML adj."),
        rows=tuple(rows),
        empty_note="No prioritised findings."))

    section.paragraphs.append(
        "Severity states how serious a condition is. Priority states the order in which "
        "an analyst should work. The ML column shows any bounded adjustment the anomaly "
        "lane contributed to the ordering; it cannot move a finding across a severity "
        "tier and it never changes a severity.")
    return section


def _issue_detail(a: Dict[str, Any], doc: ReportDocument, trunc: List[str]) -> Section:
    """Per-issue-group detail.

    Renders groups and the prioritised representatives. Per-session findings are NOT
    part of `to_dict()` and are therefore not invented here.
    """
    groups = a.get("issue_groups") or []
    section = Section(section_id="issue-detail", title="Detailed findings",
                      page_break_before=True)
    if not groups:
        return section

    if len(groups) > MAX_REPORT_FINDINGS:
        trunc.append("issue groups truncated to {0} of {1}".format(
            MAX_REPORT_FINDINGS, len(groups)))
        groups = groups[:MAX_REPORT_FINDINGS]

    # Representative findings, keyed by issue class, for evidence and frame references.
    reps: Dict[str, Dict[str, Any]] = {}
    for entry in a.get("prioritised") or []:
        finding = entry.get("representative_finding") or {}
        issue_class = (finding.get("key") or {}).get("issue_class")
        if issue_class and issue_class not in reps:
            reps[issue_class] = finding

    rows = []
    for group in groups:
        issue_class = _text(group.get("issue_class"))
        finding = reps.get(issue_class, {})
        frames = finding.get("frames") or []
        frame_text = ", ".join(str(f) for f in frames[:12])
        if len(frames) > 12:
            frame_text += ", … (%d total)" % len(frames)
        citations = group.get("citations") or []
        rows.append((
            styles.severity_marker(_text(group.get("severity"))) + " "
            + _text(group.get("severity")),
            _clip(_text(group.get("title")) or styles.humanise(issue_class),
                  MAX_EVIDENCE_CHARS, trunc, "issue title"),
            styles.humanise(_text(group.get("fact_kind"))),
            styles.humanise(_text(group.get("dimension"))),
            styles.CERTAINTY_LABEL.get(_text(group.get("certainty")),
                                       _text(group.get("certainty"))),
            styles.OBSERVABILITY_LABEL.get(_text(finding.get("observability")),
                                           _text(finding.get("observability"), "—")),
            _text(group.get("recurrence"), "0"),
            _join([_text(c.get("standard")) for c in citations], "—"),
            frame_text or "—",
            "Yes" if group.get("penalising") else "No",
        ))

    section.tables.append(Table(
        caption="Issue groups with evidence and standards basis",
        columns=("Severity", "Issue", "Fact kind", "Dimension", "Certainty",
                 "Observability", "Recurrence", "Standard", "Frames", "Penalising"),
        rows=tuple(rows), wide_columns=(1, 8),
        empty_note="No issue groups."))

    # Conclusions and explanations, verbatim from the representative findings.
    for group in groups:
        issue_class = _text(group.get("issue_class"))
        finding = reps.get(issue_class)
        if not finding:
            continue
        conclusion = _text(finding.get("conclusion"))
        explanation = _text(finding.get("explanation"))
        if conclusion:
            section.paragraphs.append(
                "{0} — {1}".format(
                    _text(group.get("title")) or styles.humanise(issue_class),
                    _clip(conclusion, MAX_EVIDENCE_CHARS, trunc, "conclusion")))
        if explanation:
            section.paragraphs.append(
                _clip(explanation, MAX_EVIDENCE_CHARS, trunc, "explanation"))
        for contradiction in finding.get("contradictions") or []:
            section.notices.append(
                "Contradictory evidence recorded: " + _clip(
                    _text(contradiction), MAX_EVIDENCE_CHARS, trunc, "contradiction"))

    section.paragraphs.append(
        "Recurrence counts the sessions in which a condition was observed. Findings are "
        "grouped by condition, so one misconfiguration seen many times is one issue "
        "with a recurrence count, not many issues.")
    return section


def _standards(a: Dict[str, Any], doc: ReportDocument, trunc: List[str]) -> Section:
    summary = a.get("standards_summary") or {}
    section = Section(
        section_id="standards", title="Standards basis",
        lead="Standards cited by the rules that produced these findings.")
    if not summary:
        return section

    rows: List[Tuple[str, ...]] = []
    by_standard = summary.get("by_standard") if isinstance(summary, dict) else None
    if isinstance(by_standard, dict):
        for standard, detail in sorted(by_standard.items()):
            if isinstance(detail, dict):
                rows.append((standard, _text(detail.get("count"), "—"),
                             _join([_text(s) for s in detail.get("sections") or []])))
            else:
                rows.append((standard, _text(detail), "—"))
    else:
        for key, value in sorted(summary.items()):
            if isinstance(value, (str, int, float)):
                rows.append((str(key), _text(value), "—"))

    section.tables.append(Table(
        caption="Standards cited in this assessment",
        columns=("Standard", "Citations", "Sections"),
        rows=tuple(rows), wide_columns=(2,),
        empty_note="No standards were cited."))
    section.notices.append(
        "A standard appearing here means a rule cited it as the basis for an "
        "observation. It is not a statement of compliance or certification against that "
        "standard.")
    return section


def _remediation(a: Dict[str, Any], doc: ReportDocument, trunc: List[str]) -> Section:
    items = a.get("remediation_summary") or []
    section = Section(
        section_id="remediation", title="Remediation guidance",
        lead="Rule-bound guidance carried from the assessment, in its own words.",
        page_break_before=True)
    if not items:
        return section

    rows = []
    for item in items:
        rows.append((
            _clip(_text(item.get("observed")), MAX_EVIDENCE_CHARS, trunc, "observed"),
            _clip(_text(item.get("why_it_matters")), MAX_EVIDENCE_CHARS, trunc, "rationale"),
            _clip(_text(item.get("recommended_action")), MAX_EVIDENCE_CHARS, trunc, "action"),
            _text(item.get("affected_scope"), "—"),
            _clip(_text(item.get("verification")), MAX_EVIDENCE_CHARS, trunc, "verification"),
            _join([_text(c.get("standard")) for c in item.get("citations") or []], "—"),
        ))
    section.tables.append(Table(
        caption="Recommended actions",
        columns=("Observed", "Why it matters", "Recommended action",
                 "Affected scope", "Verification", "Standard"),
        rows=tuple(rows), wide_columns=(0, 1, 2, 4),
        empty_note="No remediation guidance is available for the issue classes found."))

    for item in items:
        for limitation in item.get("limitations") or []:
            section.notices.append(_clip(_text(limitation), MAX_EVIDENCE_CHARS,
                                         trunc, "remediation limitation"))

    section.notices.append(
        "This system does not verify that remediation was performed or that it "
        "succeeded. Each recommendation above includes its own verification step, which "
        "must be carried out and confirmed independently.")
    return section


def _ml_transparency(a: Dict[str, Any], doc: ReportDocument,
                     trunc: List[str]) -> Section:
    summary = a.get("model_summary")
    section = Section(
        section_id="ml-transparency", title="AI / ML transparency",
        lead="What the machine-learning lane did, and what it is not permitted to do.")

    if not summary:
        section.facts.append(KeyValue("ML lane", "Disabled"))
        section.paragraphs.append(
            "The machine-learning lane was not used. Every conclusion in this report "
            "comes from deterministic rules and cross-session reasoning.")
        return section

    if not summary.get("ai_enabled", doc.metadata.ai_enabled):
        section.facts.append(KeyValue("ML lane", "Disabled"))
        if summary.get("note"):
            section.paragraphs.append(_text(summary.get("note")))
        else:
            section.paragraphs.append(
                "The machine-learning lane was not used. Every conclusion in this "
                "report comes from deterministic rules and cross-session reasoning.")
        return section

    section.facts.append(KeyValue("ML lane", "Enabled"))
    role = _text(summary.get("role"))
    if role:
        section.facts.append(KeyValue("Role", role))
    for key, label in (("model_id", "Model"), ("model_version", "Model version"),
                       ("feature_schema_version", "Feature schema"),
                       ("sessions_scored", "Sessions scored"),
                       ("model_artifact_hash", "Model artifact hash")):
        if summary.get(key) is not None:
            section.facts.append(KeyValue(label, _text(summary.get(key))))

    section.paragraphs.append(
        "The machine-learning lane contributes a bounded adjustment to the order in "
        "which findings are presented. It does not determine any security fact, does "
        "not set or change a severity, does not create a finding, and does not affect "
        "the posture score. Its adjustment is arithmetically smaller than the gap "
        "between severity tiers, so it cannot move a finding from one tier to another.")

    for limitation in summary.get("limitations") or []:
        section.notices.append(_text(limitation))
    section.notices.append(
        "An anomaly score is a statistical distance from a learned normal. It is not a "
        "vulnerability, not an attack, and not evidence of one.")
    return section


def _abstentions(a: Dict[str, Any], doc: ReportDocument, trunc: List[str]) -> Section:
    entries = a.get("abstentions") or []
    section = Section(
        section_id="abstentions", title="Abstentions and observability limits",
        lead="Questions this assessment declined to answer, and what would settle them.",
        page_break_before=True)

    if not entries:
        section.paragraphs.append(
            "The assessment recorded no abstentions. Every question the rule set asked "
            "of this capture could be answered from the available evidence.")
        return section

    rows = []
    for entry in entries:
        frames = entry.get("frames") or []
        rows.append((
            styles.ABSTENTION_LABEL.get(_text(entry.get("reason")),
                                        _text(entry.get("reason"))),
            styles.humanise(_text(entry.get("issue_class"))),
            _clip(_text(entry.get("what_could_not_be_concluded")),
                  MAX_EVIDENCE_CHARS, trunc, "abstention statement"),
            _clip(_text(entry.get("why")), MAX_EVIDENCE_CHARS, trunc, "abstention reason"),
            _clip(_text(entry.get("resolved_by")), MAX_EVIDENCE_CHARS, trunc,
                  "abstention resolution"),
            _text(entry.get("protocol"), "—"),
            ", ".join(str(f) for f in frames[:8]) or "—",
        ))
    section.tables.append(Table(
        caption="Abstentions",
        columns=("Reason", "Issue class", "Could not conclude", "Why",
                 "Would be resolved by", "Protocol", "Frames"),
        rows=tuple(rows), wide_columns=(2, 3, 4),
        empty_note=""))

    section.notices.append(
        "An abstention is neither a failure nor a pass. It records that the evidence "
        "did not support a conclusion. Treating any row above as compliant, or as a "
        "detected problem, misreads it.")
    return section


def _limitations(a: Dict[str, Any], doc: ReportDocument, trunc: List[str]) -> Section:
    limitations = a.get("limitations") or []
    section = Section(
        section_id="limitations", title="Assessment limitations",
        lead="Constraints that bound what this assessment can support.")
    if not limitations:
        section.notices.append(
            "This assessment carries no recorded limitations. That is unusual and "
            "should be verified against the engine version that produced it.")
        return section
    for limitation in limitations:
        section.notices.append(_clip(_text(limitation), MAX_EVIDENCE_CHARS,
                                     trunc, "limitation"))
    return section


def _provenance(a: Dict[str, Any], doc: ReportDocument, trunc: List[str]) -> Section:
    provenance = a.get("provenance") or {}
    section = Section(
        section_id="provenance", title="Evidence and provenance",
        lead="What was analysed, by which engine, and on what evidence.",
        page_break_before=True,
        facts=[
            KeyValue("Assessment identifier", doc.metadata.assessment_id),
            KeyValue("Capture identifier (SHA-256)", doc.metadata.capture_id),
            KeyValue("Analysis run identifier", _text(doc.metadata.run_id, "not recorded")),
            KeyValue("Analysis timestamp", doc.metadata.generated_at),
            KeyValue("Posture schema version", doc.metadata.posture_schema_version),
            KeyValue("Posture engine version", doc.metadata.posture_engine_version),
            KeyValue("Report schema version", doc.metadata.report_schema_version),
            KeyValue("Renderer version", doc.metadata.renderer_version),
        ])

    rows = []
    for key, value in sorted(provenance.items()):
        if isinstance(value, (dict, list)):
            rows.append((styles.humanise(str(key)),
                         _clip(_text(value), 400, trunc, "provenance entry")))
        else:
            rows.append((styles.humanise(str(key)), _text(value)))
    if rows:
        section.tables.append(Table(
            caption="Engine provenance",
            columns=("Item", "Value"), rows=tuple(rows), wide_columns=(1,),
            empty_note=""))

    section.paragraphs.append(
        "Every conclusion in this report traces to specific frames in the capture, to "
        "the rule that examined them, and to the standard that rule cited. The capture "
        "identifier above is the SHA-256 of the analysed bytes; a capture that hashes "
        "differently is a different capture and this assessment does not describe it.")
    return section


def _methodology(a: Dict[str, Any], doc: ReportDocument, trunc: List[str]) -> Section:
    """Describes only stages this assessment actually exercised (doc 22 §2)."""
    coverage = a.get("coverage") or {}
    protocols = sorted((coverage.get("protocol_counts") or {}).keys())
    stages = [
        "Capture validation and SHA-256 identity",
        "Packet dissection",
        "TCP stream and protocol session reconstruction",
        "Deterministic security analysis against versioned, standards-bound rules",
        "Cross-session reasoning",
    ]
    if doc.metadata.ai_enabled:
        stages.append("Machine-learning secondary prioritisation signal")
    stages.extend([
        "Evidence fusion, deduplication and contradiction handling",
        "Risk classification, posture scoring, prioritisation and remediation",
    ])

    section = Section(
        section_id="methodology", title="Methodology",
        lead="The stages that produced this assessment.",
        facts=[
            KeyValue("Input", "Packet capture (PCAP)"),
            KeyValue("Protocols assessed", _join(protocols, "None observed")),
            KeyValue("Output", "Canonical posture assessment"),
        ])
    for index, stage in enumerate(stages, start=1):
        section.paragraphs.append("{0}. {1}".format(index, stage))
    if not doc.metadata.ai_enabled:
        section.paragraphs.append(
            "The machine-learning lane was not exercised for this assessment.")
    return section
