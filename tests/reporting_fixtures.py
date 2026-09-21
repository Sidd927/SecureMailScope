"""
Shared Phase-9 fixtures: synthetic canonical assessments (doc 22 §17).

These are hand-built documents shaped exactly like `PostureAssessment.to_dict()`. They
exist so renderer tests can exercise cases a real capture will not conveniently produce
— a withheld band, an abstention-heavy assessment, hostile text, a very large finding
set — without inventing new security semantics.

The end-to-end tests use real captures; these cover the shapes.
"""
from __future__ import annotations

from typing import Any, Dict, List

#: Text that must never become markup or an instruction.
HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(1)>'
HOSTILE_ATTR = '" onclick="alert(1)'
HOSTILE_PATH = "../../../../etc/passwd"


def base_assessment(**overrides: Any) -> Dict[str, Any]:
    """A complete, realistic canonical assessment with one penalising issue."""
    doc: Dict[str, Any] = {
        "assessment_id": "a1b2c3d4e5f60718",
        "capture_id": "f" * 64,
        "run_id": "0" * 32,
        "generated_at": "2026-09-21T10:00:00Z",
        "versions": {"schema": "1.0", "engine": "0.7.0"},
        "ai_enabled": False,
        "overall_posture": "ADEQUATE",
        "score": {
            "value": 88.0, "band": "ADEQUATE", "formula_id": "F2-group-damped",
            "starting_value": 100.0, "total_penalty": 12.0,
            "basis": "score = 100 minus the sum of penalties for observed issues",
            "components": [{
                "issue_class": "NO_TLS_PROTECTION", "severity": "MEDIUM",
                "recurrence": 1, "base_weight": 12.0, "recurrence_multiplier": 1.0,
                "penalty": 12.0,
                "explanation": "one session with no transport protection",
            }],
        },
        "coverage": {
            "sessions_total": 4, "sessions_assessed": 3, "sessions_abstained": 1,
            "assessed_fraction": 0.75,
            "observation_counts": {"OBSERVED": 40, "AMBIGUOUS": 3,
                                   "NOT_OBSERVABLE": 5, "UNKNOWN": 2},
            "observation_fractions": {"OBSERVED": 0.8, "AMBIGUOUS": 0.06,
                                      "NOT_OBSERVABLE": 0.1, "UNKNOWN": 0.04},
            "completeness_counts": {"COMPLETE": 3, "TRUNCATED": 1},
            "protocol_counts": {"SMTP": 2, "IMAP": 1, "POP3": 1},
        },
        "risk_summary": {"by_severity": {"MEDIUM": 1, "INFO": 2}},
        "issue_groups": [
            {
                "issue_class": "NO_TLS_PROTECTION", "fact_kind": "BASE_SECURITY_ISSUE",
                "dimension": "PLAINTEXT_EXPOSURE", "severity": "MEDIUM",
                "title": "Session carried no transport protection",
                "certainty": "CONFIRMED", "recurrence": 1,
                "affected_stream_keys": ["tcp-0"], "protocols": ["SMTP"],
                "penalising": True,
                "citations": [{"standard": "RFC 3207", "section": "2",
                               "reason": "STARTTLS not negotiated",
                               "text": "RFC 3207 §2"}],
                "remediation": None, "finding_count": 1,
            },
            {
                "issue_class": "STARTTLS_ADVERTISEMENT",
                "fact_kind": "BASE_SECURITY_ISSUE",
                "dimension": "UPGRADE_INTEGRITY", "severity": "INFO",
                "title": "STARTTLS advertisement observed",
                "certainty": "CONFIRMED", "recurrence": 2,
                "affected_stream_keys": ["tcp-1", "tcp-2"], "protocols": ["IMAP"],
                "penalising": False, "citations": [], "remediation": None,
                "finding_count": 2,
            },
        ],
        "prioritised": [{
            "rank": 1, "priority_score": 72.5, "affected_sessions": 1,
            "affected_stream_keys": ["tcp-0"],
            "factors": {"severity": 60.0, "recurrence": 12.5},
            "ml_adjustment": 0.0,
            "explanation": "MEDIUM severity observed in one session",
            "representative_finding": {
                "key": {"issue_class": "NO_TLS_PROTECTION",
                        "fact_kind": "BASE_SECURITY_ISSUE", "scope_key": "tcp-0"},
                "title": "Session carried no transport protection",
                "conclusion": "Authentication credentials traversed the network without "
                              "transport encryption.",
                "explanation": "No STARTTLS command was issued and no TLS handshake was "
                               "observed on this stream.",
                "severity": "MEDIUM", "status": "OBSERVED_ISSUE",
                "certainty": "CONFIRMED", "observability": "OBSERVABLE",
                "dimension": "PLAINTEXT_EXPOSURE", "penalising": True,
                "session": {"capture_id": "f" * 64, "stream_key": "tcp-0",
                            "protocol": "SMTP", "tcp_stream_id": 0},
                "frames": [4, 7, 9], "source_rule_ids": ["SEC-PLAIN-002"],
                "sources": [], "citations": [{"standard": "RFC 3207", "section": "2",
                                              "reason": "no upgrade",
                                              "text": "RFC 3207 §2"}],
                "ml_signal": None, "remediation": None,
                "limitations": [], "contradictions": [],
            },
        }],
        "abstentions": [{
            "reason": "NOT_OBSERVABLE", "issue_class": "CERTIFICATE_OBSERVABILITY",
            "what_could_not_be_concluded": "Certificate chain validity",
            "why": "The handshake was encrypted under TLS 1.3, so the certificate is "
                   "not visible to passive capture.",
            "resolved_by": "An active connection to the server, or a capture of a "
                           "TLS 1.2 handshake.",
            "rule_id": "SEC-TLS-003", "stream_key": "tcp-1", "protocol": "IMAP",
            "frames": [21, 22],
        }],
        "protocol_posture": [{
            "protocol": "SMTP", "sessions": 2,
            "score": {"value": 88.0, "band": "ADEQUATE",
                      "formula_id": "F2-group-damped", "starting_value": 100.0,
                      "total_penalty": 12.0, "components": [], "basis": ""},
            "issue_classes": ["NO_TLS_PROTECTION"],
            "dimensions_assessed": ["PLAINTEXT_EXPOSURE"],
            "dimensions_not_observable": ["CERTIFICATE_TRUST"], "abstentions": 0,
        }],
        "standards_summary": {
            "by_standard": {"RFC 3207": {"count": 1, "sections": ["2"]}},
        },
        "remediation_summary": [{
            "observed": "SMTP session completed without transport encryption",
            "why_it_matters": "Credentials and message content are readable by anyone "
                              "positioned on the path.",
            "recommended_action": "Enable STARTTLS on the submission service and "
                                  "require it for authentication.",
            "affected_scope": "1 session (tcp-0)",
            "verification": "Re-capture a submission session and confirm a TLS "
                            "handshake follows the STARTTLS command.",
            "citations": [{"standard": "RFC 3207", "section": "2",
                           "reason": "upgrade path", "text": "RFC 3207 §2"}],
            "limitations": ["This system does not verify that remediation succeeded."],
        }],
        "model_summary": {
            "ai_enabled": False,
            "note": "ML lane disabled; posture computed from deterministic and "
                    "cross-session evidence only",
        },
        "provenance": {
            "fusion_inputs": 3, "deterministic_findings": 2,
            "cross_session_findings": 0, "ml_results": 0,
        },
        "limitations": [
            "Severity weights and band thresholds are engineering policy, not a "
            "calibrated measurement.",
            "Recurrence counts sessions, so NAT-collapsed populations under-count "
            "affected systems.",
            "Certificate posture is observability only.",
        ],
    }
    doc.update(overrides)
    return doc


def insufficient_evidence() -> Dict[str, Any]:
    """Coverage below the floor: the band is withheld and there is no score."""
    doc = base_assessment()
    doc["assessment_id"] = "b" * 16
    doc["overall_posture"] = "INSUFFICIENT_EVIDENCE"
    doc["score"] = None
    doc["coverage"] = {
        "sessions_total": 6, "sessions_assessed": 1, "sessions_abstained": 5,
        "assessed_fraction": 0.1667,
        "observation_counts": {"NOT_OBSERVABLE": 30, "UNKNOWN": 12},
        "observation_fractions": {"NOT_OBSERVABLE": 0.71, "UNKNOWN": 0.29},
        "completeness_counts": {"TRUNCATED": 5, "COMPLETE": 1},
        "protocol_counts": {"IMAP": 6},
    }
    doc["issue_groups"] = []
    doc["prioritised"] = []
    doc["remediation_summary"] = []
    doc["risk_summary"] = {}
    doc["protocol_posture"] = []
    doc["standards_summary"] = {}
    return doc


def empty_assessment() -> Dict[str, Any]:
    """A valid capture that yielded nothing at all."""
    return {
        "assessment_id": "c" * 16, "capture_id": "0" * 64, "run_id": None,
        "generated_at": "2026-09-21T11:00:00Z",
        "versions": {"schema": "1.0", "engine": "0.7.0"}, "ai_enabled": False,
        "overall_posture": "INSUFFICIENT_EVIDENCE", "score": None,
        "coverage": {"sessions_total": 0, "sessions_assessed": 0,
                     "sessions_abstained": 0, "assessed_fraction": 0.0,
                     "observation_counts": {}, "observation_fractions": {},
                     "completeness_counts": {}, "protocol_counts": {}},
        "risk_summary": {}, "issue_groups": [], "prioritised": [], "abstentions": [],
        "protocol_posture": [], "standards_summary": {}, "remediation_summary": [],
        "model_summary": None, "provenance": {}, "limitations": [],
    }


def critical_assessment() -> Dict[str, Any]:
    """A CRITICAL finding with contradictions and a not-observable dimension."""
    doc = base_assessment()
    doc["assessment_id"] = "d" * 16
    doc["overall_posture"] = "CRITICAL"
    doc["score"]["value"] = 45.0
    doc["score"]["band"] = "CRITICAL"
    doc["issue_groups"][0]["severity"] = "CRITICAL"
    doc["issue_groups"][0]["recurrence"] = 12
    # Contradictory evidence drops certainty while the issue is retained — severity is
    # never reduced because certainty fell (Phase-7 three-dimension separation).
    doc["issue_groups"][0]["certainty"] = "UNCERTAIN"
    doc["prioritised"][0]["representative_finding"]["severity"] = "CRITICAL"
    doc["prioritised"][0]["representative_finding"]["certainty"] = "UNCERTAIN"
    doc["prioritised"][0]["representative_finding"]["observability"] = \
        "PARTIALLY_OBSERVABLE"
    doc["prioritised"][0]["representative_finding"]["contradictions"] = [
        "One source reported a completed upgrade while another observed cleartext "
        "authentication on the same stream; the issue is retained and certainty is "
        "reduced."]
    doc["risk_summary"] = {"by_severity": {"CRITICAL": 1, "INFO": 2}}
    return doc


def ai_enabled_assessment() -> Dict[str, Any]:
    """Same security content, ML lane on. Score and band must be unchanged."""
    doc = base_assessment()
    doc["assessment_id"] = "e" * 16
    doc["ai_enabled"] = True
    doc["prioritised"][0]["ml_adjustment"] = 2.5
    doc["model_summary"] = {
        "ai_enabled": True,
        "role": "secondary prioritisation signal only",
        "model_id": "robust-z-sum", "model_version": "1.0",
        "feature_schema_version": "1.0", "sessions_scored": 4,
        "model_artifact_hash": "9" * 16,
        "limitations": [
            "secondary prioritisation signal only; ADR-0015 records zero unique true "
            "detections on every held-out split",
            "an anomaly is a statistical deviation from learned normal, not a "
            "vulnerability and not an attack",
        ],
    }
    doc["limitations"] = doc["limitations"] + [
        "the ML lane is a secondary prioritisation signal only",
        "an anomaly score is a distance from a learned normal",
        "the model was trained on synthetic corpora",
    ]
    return doc


def hostile_assessment() -> Dict[str, Any]:
    """Every analyst-visible string carries markup or a traversal attempt."""
    doc = base_assessment()
    doc["assessment_id"] = "9" * 16
    group = doc["issue_groups"][0]
    group["title"] = HOSTILE
    finding = doc["prioritised"][0]["representative_finding"]
    finding["conclusion"] = HOSTILE
    finding["explanation"] = HOSTILE_ATTR
    doc["abstentions"][0]["why"] = HOSTILE
    doc["abstentions"][0]["resolved_by"] = HOSTILE_PATH
    doc["limitations"] = [HOSTILE, HOSTILE_ATTR, HOSTILE_PATH]
    doc["remediation_summary"][0]["recommended_action"] = HOSTILE
    doc["coverage"]["protocol_counts"] = {HOSTILE: 1}
    doc["provenance"] = {"note": HOSTILE}
    return doc


def large_assessment(groups: int = 120, abstentions: int = 80) -> Dict[str, Any]:
    """Many issue groups, prioritised entries and abstentions."""
    doc = base_assessment()
    doc["assessment_id"] = "7" * 16
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    issue_groups: List[Dict[str, Any]] = []
    prioritised: List[Dict[str, Any]] = []
    for i in range(groups):
        severity = severities[i % len(severities)]
        issue_class = "ISSUE_CLASS_%03d" % i
        issue_groups.append({
            "issue_class": issue_class, "fact_kind": "BASE_SECURITY_ISSUE",
            "dimension": "PLAINTEXT_EXPOSURE", "severity": severity,
            "title": "Synthetic issue %d with a deliberately long title that must wrap "
                     "across columns without clipping" % i,
            "certainty": "CONFIRMED", "recurrence": (i % 9) + 1,
            "affected_stream_keys": ["tcp-%d" % i], "protocols": ["SMTP"],
            "penalising": severity != "INFO",
            "citations": [{"standard": "RFC 3207", "section": "2",
                           "reason": "synthetic", "text": "RFC 3207 §2"}],
            "remediation": None, "finding_count": 1,
        })
        prioritised.append({
            "rank": i + 1, "priority_score": 100.0 - i, "affected_sessions": 1,
            "affected_stream_keys": ["tcp-%d" % i], "factors": {}, "ml_adjustment": 0.0,
            "explanation": "synthetic",
            "representative_finding": {
                "key": {"issue_class": issue_class,
                        "fact_kind": "BASE_SECURITY_ISSUE", "scope_key": "tcp-%d" % i},
                "title": "Synthetic issue %d" % i,
                "conclusion": "Synthetic conclusion %d. %s" % (i, "word " * 40),
                "explanation": "Synthetic explanation %d." % i,
                "severity": severity, "status": "OBSERVED_ISSUE",
                "certainty": "CONFIRMED", "observability": "OBSERVABLE",
                "dimension": "PLAINTEXT_EXPOSURE", "penalising": severity != "INFO",
                "session": {}, "frames": list(range(i, i + 20)),
                "source_rule_ids": ["SEC-PLAIN-002"], "sources": [],
                "citations": [], "ml_signal": None, "remediation": None,
                "limitations": [], "contradictions": [],
            },
        })
    doc["issue_groups"] = issue_groups
    doc["prioritised"] = prioritised
    doc["abstentions"] = [{
        "reason": "AMBIGUOUS_EVIDENCE", "issue_class": "ISSUE_CLASS_%03d" % i,
        "what_could_not_be_concluded": "Synthetic question %d" % i,
        "why": "Synthetic reason %d. %s" % (i, "detail " * 20),
        "resolved_by": "Synthetic resolution %d" % i,
        "rule_id": "SEC-STLS-002", "stream_key": "tcp-%d" % i, "protocol": "IMAP",
        "frames": [i],
    } for i in range(abstentions)]
    return doc
