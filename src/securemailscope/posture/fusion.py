"""
Evidence fusion (Phase 7).

Combines the three lanes into coherent facts **without flattening provenance**:

    SecurityFinding[] + CrossSessionFinding[] + MLAnomalyResult[]  ->  FusedFinding[]

The hard problems this module exists to solve:

1. **Deduplication.** The lanes overlap. Concatenating them would let one underlying
   condition be counted as three weaknesses, and the posture score would then measure
   how many rules fired rather than how insecure the service is. Fusion groups on a
   content-derived `IssueKey`, never on a `finding_id` (which is unique per instance and
   so can never detect a duplicate).

2. **Not over-merging.** A base security issue, a behavioural deviation and an anomaly
   signal are different analytical facts about the same session. They are *related*, not
   identical. Collapsing a deviation into an issue would silently upgrade "this differs
   from before" into "this is a vulnerability", which is the exact overclaim the project
   exists to avoid. `FactKind` is part of the key, so they never merge.

3. **Contradictions.** When two sources disagree, fusion records the disagreement and
   keeps the *less* certain reading. It never picks the reassuring one.

Fusion adds no security conclusion of its own. Every severity, status and standard on a
`FusedFinding` came from a rule; this module only decides what belongs together.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from securemailscope.analysis.model import (
    EvidenceRef, FindingStatus, SecurityFinding, Severity,
)
from securemailscope.crosssession.model import CrossSessionFinding, Deviation
from securemailscope.ml.contract import AnomalyBand, MLAnomalyResult
from securemailscope.posture import remediation as remediation_templates
from securemailscope.posture import standards as standards_registry
from securemailscope.posture.model import (
    ISSUE_DIMENSION, RULE_ISSUE_CLASS, Abstention, AbstentionReason, EvidenceCertainty,
    FactKind, FusedFinding, IssueClass, IssueKey, MLSignal, Observability, Relation,
    RiskDimension, SourceLane, SourceRef, certainty_from_refs,
    observability_from_status,
)

#: Statuses that are refusals to conclude rather than conclusions. Each maps to the
#: abstention reason an analyst needs in order to act on it.
_ABSTAINING_STATUS: Dict[FindingStatus, AbstentionReason] = {
    FindingStatus.AMBIGUOUS: AbstentionReason.AMBIGUOUS_EVIDENCE,
    FindingStatus.INSUFFICIENT_EVIDENCE: AbstentionReason.INSUFFICIENT_CAPTURE,
    FindingStatus.NOT_OBSERVABLE: AbstentionReason.NOT_OBSERVABLE,
}

#: What additional evidence would resolve each abstention. Generic advice is useless
#: here; an analyst needs to know which capture to take next.
_RESOLUTION: Dict[AbstentionReason, str] = {
    AbstentionReason.AMBIGUOUS_EVIDENCE:
        "capture sessions from a different client to the same endpoint, or obtain the "
        "server configuration; the observed bytes alone support more than one reading",
    AbstentionReason.INSUFFICIENT_CAPTURE:
        "re-capture the full session including connection setup and teardown",
    AbstentionReason.NOT_OBSERVABLE:
        "not resolvable by passive capture; this fact is structurally hidden from an "
        "observer without key material",
    AbstentionReason.INSUFFICIENT_HISTORY:
        "capture more sessions from the same client to the same endpoint so a baseline "
        "can be established",
    AbstentionReason.CONTRADICTORY_EVIDENCE:
        "re-capture without packet loss; the current capture supports conflicting "
        "readings of the same fact",
    AbstentionReason.NOT_COMPARABLE:
        "capture sessions sharing the same client, endpoint, protocol and TLS mode",
    AbstentionReason.UNSUPPORTED_PROTOCOL_VARIANT:
        "not currently supported by the analysis rules; record the variant for a future "
        "rule",
}

_SEVERITY_ORDER = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
                   Severity.HIGH: 3, Severity.CRITICAL: 4}

_CERTAINTY_ORDER = {EvidenceCertainty.UNDETERMINED: 0, EvidenceCertainty.UNCERTAIN: 1,
                    EvidenceCertainty.PROBABLE: 2, EvidenceCertainty.CONFIRMED: 3}


def _issue_class(rule_id: str) -> IssueClass:
    return RULE_ISSUE_CLASS.get(rule_id, IssueClass.UNCLASSIFIED)


def _fact_kind(status: FindingStatus, lane: SourceLane) -> FactKind:
    if status is FindingStatus.COMPLIANT:
        return FactKind.POSITIVE_EVIDENCE
    if status in _ABSTAINING_STATUS:
        return FactKind.ABSTENTION
    if status is FindingStatus.INFORMATIONAL:
        return FactKind.POSITIVE_EVIDENCE
    # OBSERVED_ISSUE: a cross-session lane issue is a behavioural fact, not a
    # standards-bound weakness, and the two must never share a key.
    return (FactKind.BEHAVIOURAL_DEVIATION if lane is SourceLane.CROSS_SESSION
            else FactKind.BASE_SECURITY_ISSUE)


class FusionResult:
    """Fused findings plus the abstentions that were deliberately not fused into them."""

    __slots__ = ("findings", "abstentions", "duplicate_count", "contradiction_count")

    def __init__(self, findings: Sequence[FusedFinding],
                 abstentions: Sequence[Abstention],
                 duplicate_count: int = 0, contradiction_count: int = 0) -> None:
        self.findings: Tuple[FusedFinding, ...] = tuple(findings)
        self.abstentions: Tuple[Abstention, ...] = tuple(abstentions)
        self.duplicate_count = duplicate_count
        self.contradiction_count = contradiction_count

    def to_dict(self) -> dict:
        return {"findings": [f.to_dict() for f in self.findings],
                "abstentions": [a.to_dict() for a in self.abstentions],
                "duplicate_sources_merged": self.duplicate_count,
                "contradictions_recorded": self.contradiction_count}


class FusionEngine:
    """Deterministic, order-independent fusion."""

    def fuse(self,
             findings: Sequence[SecurityFinding] = (),
             cross_findings: Sequence[CrossSessionFinding] = (),
             ml_results: Sequence[MLAnomalyResult] = ()) -> FusionResult:
        buckets: Dict[Tuple, List[SourceRef]] = defaultdict(list)
        meta: Dict[Tuple, Dict[str, object]] = {}
        abstentions: List[Abstention] = []
        duplicates = 0

        for finding in findings:
            key, source, info = self._from_deterministic(finding)
            if key is None:
                abstentions.append(info)            # type: ignore[arg-type]
                continue
            if buckets[key.as_tuple()]:
                duplicates += 1
            buckets[key.as_tuple()].append(source)
            meta.setdefault(key.as_tuple(), info)   # type: ignore[arg-type]

        for cross in cross_findings:
            key, source, info = self._from_cross(cross)
            if key is None:
                abstentions.append(info)            # type: ignore[arg-type]
                continue
            if buckets[key.as_tuple()]:
                duplicates += 1
            buckets[key.as_tuple()].append(source)
            meta.setdefault(key.as_tuple(), info)   # type: ignore[arg-type]

        ml_by_session = {r.session_key: r for r in ml_results if r.scored}

        fused: List[FusedFinding] = []
        contradictions = 0
        fused.extend(self._anomaly_facts(ml_results))
        for key_tuple in sorted(buckets, key=lambda k: tuple(str(x) for x in k)):
            sources = buckets[key_tuple]
            info = meta[key_tuple]
            finding, had_contradiction = self._assemble(info, sources, ml_by_session)
            contradictions += 1 if had_contradiction else 0
            fused.append(finding)

        # Deterministic, stable ordering that does not depend on input order.
        fused.sort(key=lambda f: (-_SEVERITY_ORDER[f.severity],
                                  f.key.issue_class.value, f.key.fact_kind.value,
                                  str(f.stream_key)))
        abstentions.sort(key=lambda a: (a.issue_class.value, a.reason.value,
                                        str(a.stream_key), a.rule_id))
        return FusionResult(fused, abstentions, duplicates, contradictions)


    # ---- anomaly facts ------------------------------------------------------
    def _anomaly_facts(self, ml_results: Sequence[MLAnomalyResult]) -> List[FusedFinding]:
        """Represent an ANOMALOUS session as its own fact, distinct from any issue.

        Without this, a session that no rule flagged but the model found unusual would
        vanish from the assessment entirely. It is deliberately a separate `FactKind`
        with `INFORMATIONAL` status: the class invariant makes it structurally incapable
        of penalising the score or asserting a weakness.
        """
        out: List[FusedFinding] = []
        for result in ml_results:
            if result.band is not AnomalyBand.ANOMALOUS:
                continue
            signal = MLSignal.from_result(result)
            source = SourceRef(
                lane=SourceLane.ML, finding_id=f"ml:{result.session_key}",
                rule_id=result.model_id, relation=Relation.PRIORITIZES,
                stream_key=result.session_key, detail=result.basis)
            out.append(FusedFinding(
                key=IssueKey(IssueClass.ANOMALY, FactKind.ANOMALY_SIGNAL,
                             result.session_key),
                title="Session is statistically unlike the learned normal",
                conclusion=("This session's feature vector is an outlier relative to the "
                            "model's training population. This is not a vulnerability, "
                            "not an attack, and not evidence of either."),
                explanation=result.basis,
                severity=Severity.INFO, status=FindingStatus.INFORMATIONAL,
                certainty=EvidenceCertainty.UNDETERMINED,
                observability=Observability.OBSERVABLE,
                dimension=RiskDimension.BEHAVIOURAL_CONSISTENCY,
                capture_id=result.capture_id, stream_key=result.session_key,
                sources=(source,), ml_signal=signal,
                limitations=signal.limitations))
        return out

    # ---- lane adapters ------------------------------------------------------
    def _from_deterministic(self, finding: SecurityFinding):
        issue_class = _issue_class(finding.rule_id)
        if finding.status in _ABSTAINING_STATUS:
            reason = _ABSTAINING_STATUS[finding.status]
            return None, None, Abstention(
                reason=reason, issue_class=issue_class,
                what_could_not_be_concluded=finding.title,
                why=finding.conclusion,
                resolved_by=_RESOLUTION[reason],
                rule_id=finding.rule_id, stream_key=finding.stream_key,
                protocol=finding.protocol, frames=finding.all_frames)

        kind = _fact_kind(finding.status, SourceLane.DETERMINISTIC)
        key = IssueKey(issue_class, kind, finding.stream_key)
        source = SourceRef(
            lane=SourceLane.DETERMINISTIC, finding_id=finding.finding_id,
            rule_id=finding.rule_id, relation=Relation.SUPPORTS,
            status=finding.status, severity=finding.severity,
            stream_key=finding.stream_key, frames=finding.all_frames,
            evidence_refs=finding.evidence_refs, standards=finding.standards,
            detail=finding.conclusion)
        info = {
            "key": key, "title": finding.title, "conclusion": finding.conclusion,
            "explanation": finding.explanation, "severity": finding.severity,
            "status": finding.status, "capture_id": finding.capture_id,
            "stream_key": finding.stream_key, "protocol": finding.protocol,
            "tcp_stream_id": finding.tcp_stream_id,
            "limitations": tuple(finding.limitations),
            "rule_remediation": finding.remediation,
        }
        return key, source, info

    def _from_cross(self, cross: CrossSessionFinding):
        issue_class = _issue_class(cross.rule_id)
        if cross.status in _ABSTAINING_STATUS:
            reason = _ABSTAINING_STATUS[cross.status]
            # A cross-session abstention usually means "no usable baseline", which is a
            # different question from "the bytes were ambiguous"; name it precisely.
            if cross.deviation is Deviation.NOT_ASSESSED and not cross.baseline:
                reason = AbstentionReason.INSUFFICIENT_HISTORY
            return None, None, Abstention(
                reason=reason, issue_class=issue_class,
                what_could_not_be_concluded=cross.title, why=cross.conclusion,
                resolved_by=_RESOLUTION[reason], rule_id=cross.rule_id,
                stream_key=cross.subject_stream_key, protocol=cross.protocol,
                frames=tuple(sorted({f for r in cross.evidence_refs for f in r.frames})))

        kind = _fact_kind(cross.status, SourceLane.CROSS_SESSION)
        key = IssueKey(issue_class, kind, cross.subject_stream_key)
        relation = (Relation.ENRICHES if kind is FactKind.BEHAVIOURAL_DEVIATION
                    else Relation.CONTEXTUALIZES)
        source = SourceRef(
            lane=SourceLane.CROSS_SESSION, finding_id=cross.finding_id,
            rule_id=cross.rule_id, relation=relation, status=cross.status,
            severity=cross.severity, deviation=cross.deviation,
            stream_key=cross.subject_stream_key,
            frames=tuple(sorted({f for r in cross.evidence_refs for f in r.frames})),
            evidence_refs=cross.evidence_refs, standards=cross.standards,
            detail=cross.conclusion)
        info = {
            "key": key, "title": cross.title, "conclusion": cross.conclusion,
            "explanation": cross.explanation, "severity": cross.severity,
            "status": cross.status, "capture_id": cross.capture_id,
            "stream_key": cross.subject_stream_key, "protocol": cross.protocol,
            "tcp_stream_id": cross.tcp_stream_id,
            "limitations": tuple(cross.limitations), "rule_remediation": None,
        }
        return key, source, info

    # ---- assembly -----------------------------------------------------------
    def _assemble(self, info: Dict[str, object], sources: List[SourceRef],
                  ml_by_session: Dict[Optional[str], MLAnomalyResult]):
        key: IssueKey = info["key"]                 # type: ignore[assignment]
        # Order sources deterministically, then mark repeats as duplicates while keeping
        # every one of them: provenance is never thrown away to make a count tidy.
        sources = sorted(sources, key=lambda s: (s.lane.value, s.rule_id, s.finding_id))
        marked: List[SourceRef] = []
        seen_rules: set = set()
        for source in sources:
            relation = source.relation
            if source.rule_id in seen_rules:
                relation = Relation.DUPLICATES
            seen_rules.add(source.rule_id)
            marked.append(SourceRef(
                lane=source.lane, finding_id=source.finding_id, rule_id=source.rule_id,
                relation=relation, status=source.status, severity=source.severity,
                deviation=source.deviation, stream_key=source.stream_key,
                frames=source.frames, evidence_refs=source.evidence_refs,
                standards=source.standards, detail=source.detail))

        statuses = {s.status for s in marked if s.status is not None}
        contradiction_notes: List[str] = []
        status: FindingStatus = info["status"]      # type: ignore[assignment]
        severity: Severity = info["severity"]       # type: ignore[assignment]

        # Sources disagreeing about the outcome is not a tie to be broken. Keep the less
        # certain reading and say so -- the Phase-4 fail-closed philosophy applied at the
        # fusion boundary.
        if len(statuses) > 1:
            contradiction_notes.append(
                "contributing sources disagree on the analytic outcome: "
                + ", ".join(sorted(s.value for s in statuses))
                + "; the less certain reading is retained")
            if FindingStatus.OBSERVED_ISSUE in statuses:
                status = FindingStatus.OBSERVED_ISSUE
                severity = max((s.severity for s in marked
                                if s.severity is not None and
                                s.status is FindingStatus.OBSERVED_ISSUE),
                               key=lambda s: _SEVERITY_ORDER[s])
            else:
                status = FindingStatus.AMBIGUOUS
                severity = Severity.INFO
        elif status is FindingStatus.OBSERVED_ISSUE:
            # Same outcome from several rules: take the worst severity asserted.
            severity = max((s.severity for s in marked if s.severity is not None),
                           key=lambda s: _SEVERITY_ORDER[s])

        all_refs: Tuple[EvidenceRef, ...] = tuple(
            r for s in marked for r in s.evidence_refs)
        certainty = certainty_from_refs(all_refs)
        if contradiction_notes and certainty is EvidenceCertainty.CONFIRMED:
            # Contradicted evidence is not confirmed evidence, whatever the refs say.
            certainty = EvidenceCertainty.UNCERTAIN
        observability = observability_from_status(status, all_refs)

        citations = standards_registry.resolve_all(
            text for s in marked for text in s.standards)

        ml_signal = None
        result = ml_by_session.get(info["stream_key"])  # type: ignore[arg-type]
        if result is not None:
            ml_signal = MLSignal.from_result(result)
            marked.append(SourceRef(
                lane=SourceLane.ML, finding_id=f"ml:{result.session_key}",
                rule_id=result.model_id, relation=Relation.PRIORITIZES,
                stream_key=result.session_key, detail=result.basis))

        scope = (f"session {info['stream_key']}"
                 + (f" ({info['protocol']})" if info["protocol"] else ""))
        guidance = None
        if status is FindingStatus.OBSERVED_ISSUE:
            guidance = remediation_templates.guidance_for(
                key.issue_class, citations, scope,
                info.get("rule_remediation"),                      # type: ignore[arg-type]
                extra_limitations=tuple(contradiction_notes))

        fused = FusedFinding(
            key=key, title=info["title"],                          # type: ignore[arg-type]
            conclusion=info["conclusion"],                         # type: ignore[arg-type]
            explanation=info["explanation"],                       # type: ignore[arg-type]
            severity=severity, status=status, certainty=certainty,
            observability=observability,
            dimension=ISSUE_DIMENSION.get(key.issue_class,
                                          RiskDimension.CRYPTO_CONFIGURATION),
            capture_id=info["capture_id"],                         # type: ignore[arg-type]
            stream_key=info["stream_key"],                         # type: ignore[arg-type]
            protocol=info["protocol"],                             # type: ignore[arg-type]
            tcp_stream_id=info["tcp_stream_id"],                   # type: ignore[arg-type]
            sources=tuple(marked), citations=citations, ml_signal=ml_signal,
            remediation=guidance,
            limitations=tuple(info["limitations"]),                # type: ignore[arg-type]
            contradictions=tuple(contradiction_notes))
        return fused, bool(contradiction_notes)
