"""
Risk classification and aggregation (A-01, Phase 7).

Turns per-session fused findings into the population-level view the posture score and
the analyst both need: issue groups, risk summary, per-protocol posture and evidence
coverage.

Classification here is **rule- and evidence-driven, not heuristic**. Every severity
originates from a Phase-4 or Phase-5 rule; this module never assigns, raises or lowers
one. What it adds is scope: how many sessions a condition affects, which protocols, how
certain the supporting evidence was, and which analytical dimension it sits on.

The aggregation rules exist to stop two opposite failures:

* a single severe finding being averaged away by a large benign population, and
* one isolated anomaly defining the posture of an entire infrastructure.

Both are addressed by grouping on issue class and scoring the group, with recurrence as
a damped multiplier rather than as a count.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

from securemailscope.analysis.model import FindingStatus, Severity
from securemailscope.posture import remediation as remediation_templates
from securemailscope.posture import scoring
from securemailscope.posture.model import (
    Abstention, EvidenceCertainty, EvidenceCoverage, FactKind, FusedFinding, IssueClass,
    IssueGroup, ProtocolPosture, RiskDimension, StandardCitation,
)
from securemailscope.session.model import SessionEvidence

_SEVERITY_ORDER = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
                   Severity.HIGH: 3, Severity.CRITICAL: 4}
_CERTAINTY_ORDER = {EvidenceCertainty.UNDETERMINED: 0, EvidenceCertainty.UNCERTAIN: 1,
                    EvidenceCertainty.PROBABLE: 2, EvidenceCertainty.CONFIRMED: 3}

#: Dimensions that cannot be assessed passively at all, with the reason. Listed so the
#: per-protocol view can say "not observable" instead of leaving a silent gap that reads
#: as "fine".
NOT_OBSERVABLE_DIMENSIONS: Dict[RiskDimension, str] = {
    RiskDimension.CERTIFICATE_TRUST:
        "certificate chain, expiry and key strength are not recoverable from a passive "
        "capture of a TLS 1.3 or resumed session (RFC 8446 SS2, SS2.2)",
}


def group_findings(fused: Sequence[FusedFinding]) -> Tuple[IssueGroup, ...]:
    """Group fused findings by issue class and fact kind.

    Fact kind is part of the grouping key so a base security issue and a behavioural
    deviation about the same condition remain two groups. Merging them would make a
    deviation contribute to the score as though it were a standards-bound weakness.
    """
    buckets: Dict[Tuple[str, str], List[FusedFinding]] = defaultdict(list)
    for finding in fused:
        buckets[(finding.key.issue_class.value, finding.key.fact_kind.value)].append(
            finding)

    groups: List[IssueGroup] = []
    for (issue_value, kind_value), members in buckets.items():
        issue_class = IssueClass(issue_value)
        fact_kind = FactKind(kind_value)
        severity = max((m.severity for m in members),
                       key=lambda s: _SEVERITY_ORDER[s])
        certainty = min((m.certainty for m in members),
                        key=lambda c: _CERTAINTY_ORDER[c])
        streams = tuple(sorted({m.stream_key for m in members if m.stream_key}))
        protocols = tuple(sorted({m.protocol for m in members if m.protocol}))
        citations: Dict[Tuple[str, str], StandardCitation] = {}
        for member in members:
            for citation in member.citations:
                citations.setdefault((citation.standard, citation.text), citation)
        ordered_citations = tuple(sorted(citations.values(),
                                         key=lambda c: (c.standard, c.section, c.text)))

        guidance = None
        if any(m.penalising for m in members):
            scope = (f"{len(streams)} session(s)"
                     + (f" over {', '.join(protocols)}" if protocols else ""))
            # Reuse a member's remediation where fusion already built one, so group and
            # session guidance cannot drift apart.
            existing = next((m.remediation for m in members if m.remediation), None)
            guidance = existing or remediation_templates.guidance_for(
                issue_class, ordered_citations, scope)

        groups.append(IssueGroup(
            issue_class=issue_class, fact_kind=fact_kind,
            dimension=members[0].dimension, severity=severity,
            title=members[0].title,
            findings=tuple(sorted(members, key=lambda m: str(m.stream_key))),
            affected_stream_keys=streams, protocols=protocols, certainty=certainty,
            remediation=guidance, citations=ordered_citations))

    groups.sort(key=lambda g: (-_SEVERITY_ORDER[g.severity], -g.recurrence,
                               g.issue_class.value, g.fact_kind.value))
    return tuple(groups)


def abstention_summary(abstentions: Sequence[Abstention]) -> Dict[str, object]:
    """Grouped view of what could not be concluded.

    The full abstention list is retained on the assessment -- nothing is discarded. This
    is the readable form: an analyst needs "certificate observability could not be
    assessed on 30 sessions", not thirty identical rows.
    """
    by_reason = Counter(a.reason.value for a in abstentions)
    by_class = Counter(a.issue_class.value for a in abstentions)
    resolutions: Dict[str, str] = {}
    for abstention in abstentions:
        resolutions.setdefault(abstention.reason.value, abstention.resolved_by)
    return {
        "total": len(abstentions),
        "by_reason": dict(sorted(by_reason.items())),
        "by_issue_class": dict(sorted(by_class.items())),
        "affected_sessions": len({a.stream_key for a in abstentions if a.stream_key}),
        "how_to_resolve": dict(sorted(resolutions.items())),
    }


def risk_summary(groups: Sequence[IssueGroup],
                 fused: Sequence[FusedFinding]) -> Dict[str, object]:
    """Population risk picture. Counts, never a second opinion on severity."""
    penalising = [g for g in groups if g.penalising]
    by_severity = Counter(g.severity.value for g in penalising)
    by_dimension = Counter(g.dimension.value for g in penalising)
    by_kind = Counter(g.fact_kind.value for g in groups)
    affected = {s for g in penalising for s in g.affected_stream_keys}
    highest = (max(penalising, key=lambda g: _SEVERITY_ORDER[g.severity]).severity.value
               if penalising else None)
    return {
        "issue_groups": len(penalising),
        "highest_severity": highest,
        "by_severity": dict(sorted(by_severity.items())),
        "by_dimension": dict(sorted(by_dimension.items())),
        "by_fact_kind": dict(sorted(by_kind.items())),
        "affected_sessions": len(affected),
        "behavioural_deviations": sum(
            1 for g in groups if g.fact_kind is FactKind.BEHAVIOURAL_DEVIATION),
        "anomaly_signals": sum(
            1 for g in groups if g.fact_kind is FactKind.ANOMALY_SIGNAL),
        "positive_evidence": sum(
            1 for f in fused if f.key.fact_kind is FactKind.POSITIVE_EVIDENCE),
        "note": ("a behavioural deviation is a difference from a baseline, not a "
                 "vulnerability; an anomaly signal is a prioritisation input and "
                 "neither asserts nor implies an attack"),
    }


def build_coverage(sessions: Sequence[SessionEvidence],
                   fused: Sequence[FusedFinding],
                   abstentions: Sequence[Abstention]) -> EvidenceCoverage:
    """How much of the traffic the analysis could actually see.

    `sessions_assessed` counts sessions for which at least one conclusion (issue,
    positive evidence or deviation) was reached -- not sessions that merely existed.
    """
    concluded = {f.stream_key for f in fused
                 if f.key.fact_kind in (FactKind.BASE_SECURITY_ISSUE,
                                        FactKind.BEHAVIOURAL_DEVIATION,
                                        FactKind.POSITIVE_EVIDENCE)}
    abstained_only = {a.stream_key for a in abstentions} - concluded

    observation_counts: Counter = Counter()
    for session in sessions:
        for field_name in ("starttls_advertised", "starttls_requested",
                           "starttls_accepted", "tls_transition",
                           "tls_negotiated_version", "tls_cipher_suite",
                           "plaintext_continuation", "auth_activity"):
            observation_counts[getattr(session, field_name).state.value] += 1

    return EvidenceCoverage(
        sessions_total=len(sessions),
        sessions_assessed=len([s for s in sessions if s.stream_key in concluded]),
        sessions_abstained=len([s for s in sessions if s.stream_key in abstained_only]),
        observation_counts=dict(observation_counts),
        completeness_counts=dict(Counter(s.completeness.value for s in sessions)),
        protocol_counts=dict(Counter(s.protocol or "unidentified" for s in sessions)),
    )


def protocol_posture(sessions: Sequence[SessionEvidence],
                     fused: Sequence[FusedFinding],
                     abstentions: Sequence[Abstention],
                     formula_id: str = scoring.SELECTED_FORMULA
                     ) -> Tuple[ProtocolPosture, ...]:
    """Per-protocol posture, scored on that protocol's own findings only.

    A protocol with no assessable session gets `INSUFFICIENT_EVIDENCE`, not a clean
    score: SMTP being fine says nothing about POP3.
    """
    protocols = sorted({s.protocol for s in sessions if s.protocol})
    out: List[ProtocolPosture] = []
    for protocol in protocols:
        members = [f for f in fused if f.protocol == protocol]
        proto_sessions = [s for s in sessions if s.protocol == protocol]
        groups = group_findings(members)
        coverage = build_coverage(
            proto_sessions, members,
            [a for a in abstentions if a.protocol == protocol])
        score = scoring.compute_score(groups, coverage, formula_id)
        assessed = sorted({g.dimension.value for g in groups})
        not_observable = sorted(
            d.value for d in NOT_OBSERVABLE_DIMENSIONS
            if any(f.dimension is d for f in members))
        out.append(ProtocolPosture(
            protocol=protocol, sessions=len(proto_sessions), score=score,
            issue_classes=tuple(sorted({g.issue_class.value for g in groups
                                        if g.penalising})),
            dimensions_assessed=tuple(assessed),
            dimensions_not_observable=tuple(not_observable),
            abstentions=len([a for a in abstentions if a.protocol == protocol])))
    return tuple(out)
