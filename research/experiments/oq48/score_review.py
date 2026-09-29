"""
OQ-48: empirical review of the three posture scoring formulations (Phase-7 A-03).

A score nobody compared alternatives for is an assertion. This runs all three candidates
over the real corpora and over purpose-built property probes, and reports the evidence
ADR-0016 rests on.

Corpora: OQ-28 (generator A, 25 captures) and the Phase-6 generators B and C (35
captures). Every capture goes through the real pipeline, so the groups being scored are
the groups the product produces.

Properties measured:
  monotonicity          adding a confirmed HIGH issue must not improve the score
  duplicate resistance  re-reporting the same condition must not move the score
  recurrence behaviour  more affected sessions must not improve the score, and must not
                        let capture length dominate
  severe sensitivity    one CRITICAL among many benign sessions must still register
  missing evidence      a capture in which nothing was established must not score well
  spread                a formula that maps every capture to one band is useless
"""
from __future__ import annotations

import json
import os
import statistics
import sys
from collections import Counter
from typing import Dict, List, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "src"))

from securemailscope.analysis import SecurityAnalysisEngine  # noqa: E402
from securemailscope.analysis.model import (  # noqa: E402
    EvidenceRef, FindingStatus, SecurityFinding, Severity,
)
from securemailscope.crosssession import CrossSessionEngine  # noqa: E402
from securemailscope.evidence.states import EvidenceState  # noqa: E402
from securemailscope.ingest import analyze_capture  # noqa: E402
from securemailscope.posture import risk as risk_module  # noqa: E402
from securemailscope.posture import scoring  # noqa: E402
from securemailscope.posture.fusion import FusionEngine  # noqa: E402
from securemailscope.posture.model import PostureBand  # noqa: E402
from securemailscope.session import reconstruct_sessions  # noqa: E402

CORPORA = {
    "A_oq28": os.path.join(HERE, "..", "oq28", "pcaps"),
    "B_gen": os.path.join(HERE, "..", "oq36", "corpus", "genB"),
    "C_gen": os.path.join(HERE, "..", "oq36", "corpus", "genC"),
}
RESULTS = os.path.join(HERE, "results")
FORMULAS = list(scoring.FORMULAS)


# ------------------------------------------------------------------ helpers
def _ref(state: EvidenceState = EvidenceState.OBSERVED) -> Tuple[EvidenceRef, ...]:
    return (EvidenceRef("tls_negotiated_version", "TLS1.0", state, (1,), "probe"),)


def probe_finding(rule_id: str, severity: Severity, stream: str,
                  status: FindingStatus = FindingStatus.OBSERVED_ISSUE,
                  finding_id: str = "") -> SecurityFinding:
    """Synthetic finding for the property probes. Never used for corpus scoring."""
    return SecurityFinding(
        finding_id=finding_id or f"{rule_id}:{stream}",
        rule_id=rule_id, title="probe", status=status, severity=severity,
        conclusion="probe", explanation="probe",
        standards=("RFC 8996 (BCP 195) SS4-5: probe",),
        capture_id="probe", tcp_stream_id=int(stream.split(":")[-1]),
        protocol="smtp", stream_key=stream, evidence_refs=_ref())


def score_findings(findings: Sequence[SecurityFinding], formula: str) -> float:
    fused = FusionEngine().fuse(findings, (), ()).findings
    groups = risk_module.group_findings(fused)
    return scoring.compute_score(groups, None, formula).value


def score_band(findings: Sequence[SecurityFinding], formula: str) -> str:
    fused = FusionEngine().fuse(findings, (), ()).findings
    groups = risk_module.group_findings(fused)
    return scoring.compute_score(groups, None, formula).band.value


# ------------------------------------------------------------ corpus scoring
def corpus_scores() -> Dict[str, Dict[str, List[float]]]:
    out: Dict[str, Dict[str, List[float]]] = {f: {} for f in FORMULAS}
    bands: Dict[str, Counter] = {f: Counter() for f in FORMULAS}
    for corpus, directory in CORPORA.items():
        for formula in FORMULAS:
            out[formula].setdefault(corpus, [])
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".pcap"):
                continue
            run, frames = analyze_capture(os.path.join(directory, name))
            sessions = reconstruct_sessions(frames, run.capture.capture_id)
            if not sessions:
                continue
            findings = SecurityAnalysisEngine().analyse(
                sessions, run.capture.capture_id).findings
            cross = CrossSessionEngine().analyse(
                sessions, run.capture.capture_id).findings
            fused = FusionEngine().fuse(findings, cross, ()).findings
            groups = risk_module.group_findings(fused)
            coverage = risk_module.build_coverage(sessions, fused, ())
            for formula in FORMULAS:
                score = scoring.compute_score(groups, coverage, formula)
                out[formula][corpus].append(score.value)
                bands[formula][score.band.value] += 1
    return {"scores": out, "bands": {f: dict(sorted(c.items()))
                                     for f, c in bands.items()}}


# ------------------------------------------------------------------- probes
def property_probes() -> Dict[str, Dict[str, object]]:
    results: Dict[str, Dict[str, object]] = {}
    for formula in FORMULAS:
        base = [probe_finding("SEC-STLS-001", Severity.MEDIUM, "c:1")]

        # monotonicity: adding a confirmed HIGH must not improve the score
        with_high = base + [probe_finding("SEC-PLAIN-001", Severity.HIGH, "c:2")]
        mono = score_findings(with_high, formula) <= score_findings(base, formula)

        # duplicate resistance: the same condition reported three times, including one
        # with different provenance, must not move the score
        dup = [
            probe_finding("SEC-TLS-001", Severity.HIGH, "c:1", finding_id="a"),
            probe_finding("SEC-TLS-001", Severity.HIGH, "c:1", finding_id="b"),
            probe_finding("SEC-TLS-001", Severity.HIGH, "c:1", finding_id="c"),
        ]
        single = [probe_finding("SEC-TLS-001", Severity.HIGH, "c:1", finding_id="a")]
        dup_delta = abs(score_findings(dup, formula) - score_findings(single, formula))

        # recurrence: 1 -> 10 -> 100 affected sessions
        recurrence = {
            n: score_findings(
                [probe_finding("SEC-TLS-001", Severity.HIGH, f"c:{i}")
                 for i in range(n)], formula)
            for n in (1, 10, 100)
        }
        recurrence_monotone = (recurrence[1] >= recurrence[10] >= recurrence[100])
        # capture-length domination: does going 10 -> 100 sessions cost more than a
        # whole extra HIGH issue would?
        length_domination = (recurrence[10] - recurrence[100]) > 20.0

        # one severe finding among many benign sessions must still register
        severe = [probe_finding("SEC-TLS-001", Severity.CRITICAL, "c:0")]
        severe += [probe_finding("SEC-TLS-002", Severity.INFO, f"c:{i}",
                                 FindingStatus.COMPLIANT) for i in range(1, 60)]
        severe_score = score_findings(severe, formula)

        # long tail: 8 MEDIUM issue classes at once
        tail = [probe_finding(rule, Severity.MEDIUM, f"c:{i}")
                for i, rule in enumerate(
                    ["SEC-STLS-001", "SEC-PLAIN-002", "CS-TLS-001", "SEC-TLS-001",
                     "SEC-PLAIN-001", "CS-STARTTLS-001", "SEC-STLS-002",
                     "SEC-TLS-002"])]
        tail_score = score_findings(tail, formula)

        # nothing established at all
        empty_score = score_findings([], formula)

        results[formula] = {
            "monotonic_on_new_high": mono,
            "duplicate_delta": round(dup_delta, 4),
            "duplicate_resistant": dup_delta == 0.0,
            "recurrence_scores": {str(k): round(v, 2) for k, v in recurrence.items()},
            "recurrence_monotone": recurrence_monotone,
            "capture_length_dominates": length_domination,
            "one_critical_among_59_benign": round(severe_score, 2),
            "critical_still_registers": severe_score < 75.0,
            "eight_medium_issues": round(tail_score, 2),
            "tail_collapses_to_zero": tail_score <= 0.0,
            "empty_evidence_score": round(empty_score, 2),
            "empty_evidence_band": score_band([], formula),
        }
    return results


def main() -> None:
    os.makedirs(RESULTS, exist_ok=True)
    corpus = corpus_scores()
    probes = property_probes()

    summary: Dict[str, object] = {"formulas": {}, "selected": scoring.SELECTED_FORMULA}
    for formula in FORMULAS:
        flat = [v for values in corpus["scores"][formula].values() for v in values]
        summary["formulas"][formula] = {          # type: ignore[index]
            "corpus": {
                "captures": len(flat),
                "mean": round(statistics.mean(flat), 2) if flat else None,
                "median": round(statistics.median(flat), 2) if flat else None,
                "min": round(min(flat), 2) if flat else None,
                "max": round(max(flat), 2) if flat else None,
                "at_zero": sum(1 for v in flat if v == 0.0),
                "at_hundred": sum(1 for v in flat if v == 100.0),
                "distinct_values": len({round(v, 2) for v in flat}),
                "bands": corpus["bands"][formula],
            },
            "properties": probes[formula],
        }

    with open(os.path.join(RESULTS, "score-review.json"), "w") as fh:
        json.dump(summary, fh, indent=1, sort_keys=True)

    print(f"{'formula':20s} {'mean':>6s} {'min':>6s} {'max':>6s} {'=0':>4s} {'=100':>5s} "
          f"{'vals':>5s} | {'dup':>5s} {'mono':>5s} {'rec':>5s} {'len!':>5s} "
          f"{'crit':>6s} {'tail':>6s}")
    print("-" * 104)
    for formula in FORMULAS:
        c = summary["formulas"][formula]["corpus"]      # type: ignore[index]
        p = summary["formulas"][formula]["properties"]  # type: ignore[index]
        print(f"{formula:20s} {c['mean']:6.1f} {c['min']:6.1f} {c['max']:6.1f} "
              f"{c['at_zero']:4d} {c['at_hundred']:5d} {c['distinct_values']:5d} | "
              f"{'ok' if p['duplicate_resistant'] else 'FAIL':>5s} "
              f"{'ok' if p['monotonic_on_new_high'] else 'FAIL':>5s} "
              f"{'ok' if p['recurrence_monotone'] else 'FAIL':>5s} "
              f"{'YES' if p['capture_length_dominates'] else 'no':>5s} "
              f"{p['one_critical_among_59_benign']:6.1f} "
              f"{p['eight_medium_issues']:6.1f}")
    print("\n  len! = capture length dominates the score (bad)")
    for formula in FORMULAS:
        p = summary["formulas"][formula]["properties"]   # type: ignore[index]
        print(f"  {formula}: no-evidence band = {p['empty_evidence_band']} "
              f"(value {p['empty_evidence_score']}); recurrence 1/10/100 = "
              f"{p['recurrence_scores']}")
    print("  crit = score with one CRITICAL among 59 benign sessions")
    print("  tail = score with eight simultaneous MEDIUM issue classes")
    for formula in FORMULAS:
        print(f"\n{formula} bands: "
              f"{json.dumps(summary['formulas'][formula]['corpus']['bands'])}")
    print(f"\nwrote {os.path.join(RESULTS, 'score-review.json')}")


if __name__ == "__main__":
    main()
