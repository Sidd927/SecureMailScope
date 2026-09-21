"""
Phase-10 tests: assessment -> DashboardViewModel (doc 23 §4, §5, §10).

The contract these defend is *semantic losslessness*: the projection reorganises the
canonical assessment and must not summarise any of it away, soften a verdict, coerce an
absent value into a present one, or reorder what the engine already ordered.
"""
import pytest

from securemailscope.dashboard import project, vocabulary as vocab
from securemailscope.dashboard.errors import MalformedAssessment
from securemailscope.dashboard.model import (
    DASHBOARD_SCHEMA_VERSION, PROJECTION_VERSION,
)
from tests.reporting_fixtures import (
    ai_enabled_assessment, base_assessment, critical_assessment, empty_assessment,
    hostile_assessment, insufficient_evidence, large_assessment,
)

ALL_FIXTURES = [
    base_assessment, insufficient_evidence, empty_assessment, critical_assessment,
    ai_enabled_assessment, hostile_assessment,
]


def _anomaly_assessment():
    """A prioritised entry whose `session.protocol` is null.

    Verified against a real capture: the ANOMALY entry carries `protocol: None` while
    the base issue carries "smtp" (doc 23 §7).
    """
    a = base_assessment()
    anomaly = {
        "rank": 2, "priority_score": 30.0, "affected_sessions": 1,
        "affected_stream_keys": ["tcp-1"], "factors": {}, "ml_adjustment": 2.0,
        "explanation": "statistically unlike the learned normal",
        "representative_finding": {
            "key": {"issue_class": "ANOMALY", "fact_kind": "ANOMALY_SIGNAL",
                    "scope_key": "tcp-1"},
            "title": "Anomaly signal", "conclusion": "", "explanation": "",
            "severity": "INFO", "status": "INSUFFICIENT_EVIDENCE",
            "certainty": "UNDETERMINED", "observability": "OBSERVABLE",
            "dimension": "BEHAVIOURAL_CONSISTENCY", "penalising": False,
            # no protocol, and no frames — both legitimate
            "session": {"capture_id": "f" * 64, "stream_key": "tcp-1",
                        "protocol": None, "tcp_stream_id": 1},
            "frames": [], "source_rule_ids": [], "sources": [], "citations": [],
            "ml_signal": None, "remediation": None, "limitations": [],
            "contradictions": [],
        },
    }
    a["prioritised"] = a["prioritised"] + [anomaly]
    a["issue_groups"] = a["issue_groups"] + [{
        "issue_class": "ANOMALY", "fact_kind": "ANOMALY_SIGNAL",
        "dimension": "BEHAVIOURAL_CONSISTENCY", "severity": "INFO",
        "title": "Anomaly signal", "certainty": "UNDETERMINED", "recurrence": 1,
        "affected_stream_keys": ["tcp-1"], "protocols": [], "penalising": False,
        "citations": [], "remediation": None, "finding_count": 1}]
    return a


# ------------------------------------------------------------------- identity
def test_identity_carries_versions_and_ids():
    vm = project(base_assessment())
    i = vm.identity
    assert i.assessment_id == "a1b2c3d4e5f60718"
    assert i.capture_id == "f" * 64
    assert i.posture_engine_version == "0.7.0"
    assert i.dashboard_schema_version == DASHBOARD_SCHEMA_VERSION
    assert i.projection_version == PROJECTION_VERSION
    # dashboard versions are distinct from the assessment's own
    assert i.dashboard_schema_version != i.posture_engine_version


def test_generated_at_is_the_analysis_time_not_now():
    assert project(base_assessment()).identity.generated_at == "2026-09-21T10:00:00Z"


def test_projection_is_deterministic():
    assert project(base_assessment()).to_dict() == project(base_assessment()).to_dict()


# -------------------------------------------------------------------- refusal
@pytest.mark.parametrize("bad", [None, [], "assessment", 42, 3.5])
def test_non_mapping_refused(bad):
    with pytest.raises(MalformedAssessment):
        project(bad)


def test_missing_canonical_key_refused_not_guessed():
    a = base_assessment()
    del a["overall_posture"]
    with pytest.raises(MalformedAssessment) as exc:
        project(a)
    assert "overall_posture" in exc.value.detail["missing"]
    assert exc.value.http_status == 422


# -------------------------------------------------- semantic losslessness
@pytest.mark.parametrize("builder", ALL_FIXTURES)
def test_nothing_is_dropped(builder):
    a = builder()
    vm = project(a)
    assert len(vm.findings) == len(a["prioritised"])
    assert len(vm.issue_groups) == len(a["issue_groups"])
    assert len(vm.abstentions) == len(a["abstentions"])
    assert len(vm.limitations) == len(a["limitations"])
    assert len(vm.remediation) == len(a["remediation_summary"])
    assert len(vm.protocols) == len(a["protocol_posture"])


def test_limitations_are_verbatim():
    a = base_assessment()
    assert project(a).limitations == a["limitations"]


def test_standards_and_unmapped_citations_survive():
    a = base_assessment()
    a["standards_summary"] = {
        "standards": {"RFC 3207": ["2"], "RFC 8314": ["3"]},
        "distinct_standards": 2,
        "unmapped_citations": ["RFC 8446 SS2 (handshake message flow)"],
        "note": "every citation originates from a rule"}
    s = project(a).standards
    assert [r.standard for r in s.standards] == ["RFC 3207", "RFC 8314"]
    assert s.distinct_standards == 2
    # a gap the engine reports about itself must reach the UI
    assert s.unmapped_citations == ["RFC 8446 SS2 (handshake message flow)"]


def test_provenance_rule_ids_survive():
    a = base_assessment()
    a["provenance"] = {"rule_ids": ["SEC-PLAIN-002", "SEC-TLS-001"],
                       "source_counts": {"deterministic_findings": 2},
                       "note": "n", "contradictions_recorded": 0}
    p = project(a).provenance
    assert p.rule_ids == ["SEC-PLAIN-002", "SEC-TLS-001"]
    assert p.source_counts == {"deterministic_findings": 2}
    assert "contradictions_recorded" in p.entries


# ------------------------------------------------------------ no recomputation
def test_score_and_band_copied_verbatim():
    a = base_assessment()
    vm = project(a)
    assert vm.posture.value == a["overall_posture"]
    assert vm.posture.score_value == a["score"]["value"]
    assert vm.posture.formula_id == a["score"]["formula_id"]


def test_findings_keep_canonical_order():
    """The assessment already decided the order; the projection must not sort."""
    a = large_assessment(groups=12, abstentions=0)
    ranks = [f.rank for f in project(a).findings]
    assert ranks == [e["rank"] for e in a["prioritised"]]
    severities = [f.severity for f in project(a).findings]
    assert severities != sorted(severities, key=vocab.severity_index)


def test_severity_is_never_altered():
    a = critical_assessment()
    vm = project(a)
    assert vm.findings[0].severity == "CRITICAL"
    # low certainty must not soften severity (Phase-7 three-dimension separation)
    assert vm.findings[0].certainty == "UNCERTAIN"
    assert vm.issue_groups[0].severity == "CRITICAL"


def test_bar_max_is_presentation_only():
    a = base_assessment()
    a["risk_summary"] = {"by_severity": {"MEDIUM": 1, "INFO": 3}}
    bars = {b.key: b for b in project(a).distributions[0].bars}
    assert bars["MEDIUM"].value == 1.0 and bars["INFO"].value == 3.0
    assert bars["MEDIUM"].max_value == 3.0        # scaling factor, not a security value
    assert bars["MEDIUM"].value_text == "1"


def test_severity_bars_ordered_by_severity_not_alphabetically():
    a = base_assessment()
    a["risk_summary"] = {"by_severity": {"INFO": 1, "CRITICAL": 2, "MEDIUM": 3}}
    assert [b.key for b in project(a).distributions[0].bars] == \
        ["CRITICAL", "MEDIUM", "INFO"]


# ------------------------------------------------------------- vocabulary
def test_insufficient_evidence_is_never_softened():
    vm = project(insufficient_evidence())
    assert vm.posture.value == "INSUFFICIENT_EVIDENCE"
    assert vm.posture.label == "INSUFFICIENT EVIDENCE"
    assert vm.posture.withheld is True
    assert vm.posture.score_value is None
    assert vm.posture.score_text == "Not scored"
    assert vm.posture.tone == "insufficient_evidence"   # its own tone, not a severity
    joined = " ".join(vm.notices).lower()
    assert "withheld" in joined and "not a passing result" in joined
    for forbidden in ("unknown", "safe", "secure", "pass"):
        assert forbidden not in vm.posture.label.lower()


def test_evidence_states_stay_distinct():
    a = base_assessment()
    a["prioritised"][0]["representative_finding"]["status"] = "AMBIGUOUS"
    a["prioritised"][0]["representative_finding"]["observability"] = "NOT_OBSERVABLE"
    a["prioritised"][0]["representative_finding"]["severity"] = "INFO"
    row = project(a).findings[0]
    assert row.status == "AMBIGUOUS" and row.status_label == "AMBIGUOUS"
    assert row.observability == "NOT_OBSERVABLE"
    assert row.observability_label == "NOT OBSERVABLE"
    assert row.status_label != row.observability_label


def test_severity_has_a_text_marker():
    assert project(critical_assessment()).findings[0].severity_marker == "[!!!]"


def test_fact_kinds_are_labelled_distinctly():
    a = _anomaly_assessment()
    kinds = {f.fact_kind: f.fact_kind_label for f in project(a).findings}
    assert kinds["BASE_SECURITY_ISSUE"] == "Security issue"
    assert kinds["ANOMALY_SIGNAL"] == "Anomaly signal"


# ---------------------------------------------------- unknown / missing values
def test_unknown_severity_renders_rather_than_defaulting():
    a = base_assessment()
    a["prioritised"][0]["representative_finding"]["severity"] = "CATACLYSMIC"
    row = project(a).findings[0]
    assert row.severity == "CATACLYSMIC"
    assert row.severity_label == "Cataclysmic"     # humanised, not replaced
    assert row.severity_known is False             # flagged as unrecognised
    assert row.severity_tone == "unknown"          # never styled as a known severity
    assert row.severity_marker == "[?  ]"


def test_unknown_posture_band_does_not_crash_or_become_a_pass():
    a = base_assessment()
    a["overall_posture"] = "SOMETHING_NEW"
    vm = project(a)
    assert vm.posture.value == "SOMETHING_NEW"
    assert vm.posture.known is False
    assert vm.posture.tone == "unknown"
    assert vm.posture.withheld is False


@pytest.mark.parametrize("vocabulary", ["severity", "status", "certainty",
                                        "observability", "fact_kind", "posture",
                                        "dimension", "abstention_reason"])
def test_unknown_values_never_raise(vocabulary):
    assert vocab.label(vocabulary, "TOTALLY_NEW_VALUE") == "Totally new value"
    assert vocab.is_known(vocabulary, "TOTALLY_NEW_VALUE") is False
    assert vocab.label(vocabulary, None) == ""
    assert vocab.label("no_such_vocabulary", "X") == "X"


def test_missing_optional_fields_stay_none():
    a = base_assessment()
    f = a["prioritised"][0]["representative_finding"]
    f["certainty"] = None
    f["observability"] = None
    a["score"] = None
    row = project(a).findings[0]
    assert row.certainty is None and row.certainty_label == ""
    assert row.observability is None
    vm = project(a)
    assert vm.posture.score_value is None and vm.posture.score_text == "Not scored"


def test_absent_coverage_is_flagged_not_zeroed():
    a = base_assessment()
    a["coverage"] = {}
    vm = project(a)
    assert vm.coverage.present is False
    assert vm.coverage.sessions_total is None     # not coerced to 0
    assert vm.coverage.assessed_fraction is None
    assert any("no coverage information" in n.lower() for n in vm.notices)


def test_empty_assessment_projects_without_inventing_anything():
    vm = project(empty_assessment())
    assert vm.findings == [] and vm.issue_groups == [] and vm.abstentions == []
    assert vm.distributions == []
    assert vm.posture.value == "INSUFFICIENT_EVIDENCE"
    assert vm.coverage.sessions_total == 0        # genuinely zero here, and present
    assert vm.coverage.present is True


def test_zero_is_distinguishable_from_absent():
    a = base_assessment()
    a["coverage"]["sessions_abstained"] = 0
    vm = project(a)
    assert vm.coverage.sessions_abstained == 0
    a["coverage"].pop("sessions_abstained")
    assert project(a).coverage.sessions_abstained is None


# ------------------------------------------------- nullable protocol (doc 23 §7)
def test_null_protocol_is_preserved_and_labelled():
    vm = project(_anomaly_assessment())
    anomaly = [f for f in vm.findings if f.fact_kind == "ANOMALY_SIGNAL"][0]
    assert anomaly.protocol is None                       # canonical value preserved
    assert anomaly.protocol_key == vocab.PROTOCOL_UNATTRIBUTED
    assert anomaly.protocol_label == "Not attributed to a protocol"


def test_protocol_filter_option_includes_unattributed_findings():
    """A naive facet would silently drop findings with no protocol."""
    vm = project(_anomaly_assessment())
    options = {o.value: o for o in vm.filters.protocol}
    assert vocab.PROTOCOL_UNATTRIBUTED in options
    assert options[vocab.PROTOCOL_UNATTRIBUTED].count == 1
    assert "smtp" in options or "SMTP" in options
    # every finding is reachable through exactly one protocol option
    assert sum(o.count for o in vm.filters.protocol) == len(vm.findings)


def test_empty_frames_say_so():
    vm = project(_anomaly_assessment())
    anomaly = [f for f in vm.findings if f.fact_kind == "ANOMALY_SIGNAL"][0]
    assert anomaly.frames == []
    assert anomaly.frames_text == "no frame references recorded"


def test_frames_are_bounded_but_counted():
    a = base_assessment()
    a["prioritised"][0]["representative_finding"]["frames"] = list(range(50))
    row = project(a).findings[0]
    assert row.frames == list(range(50))          # nothing dropped from the data
    assert "50 total" in row.frames_text          # display is bounded


# ------------------------------------------------------------------- filters
def test_filter_options_only_reflect_present_values():
    vm = project(base_assessment())
    severities = {o.value for o in vm.filters.severity}
    assert severities == {f.severity for f in vm.findings if f.severity}
    assert all(o.count > 0 for o in vm.filters.severity)


def test_severity_options_are_severity_ordered():
    a = large_assessment(groups=10, abstentions=0)
    values = [o.value for o in project(a).filters.severity]
    assert values == sorted(values, key=vocab.severity_index)


def test_every_offered_facet_exists_in_the_canonical_schema():
    """doc 23 §7: no facet may be offered for a field the contract lacks."""
    a = _anomaly_assessment()
    vm = project(a)
    finding = a["prioritised"][0]["representative_finding"]
    assert "severity" in finding and "status" in finding
    assert "certainty" in finding and "observability" in finding
    assert "dimension" in finding
    assert "fact_kind" in finding["key"] and "issue_class" in finding["key"]
    assert "protocol" in finding["session"]
    # and the view model offers exactly those eight facets
    assert sorted(vm.filters.__dataclass_fields__.keys()) == sorted([
        "severity", "status", "certainty", "observability", "fact_kind",
        "issue_class", "dimension", "protocol"])


# ------------------------------------------------------------------------ ML
def test_ml_disabled_states_it_plainly():
    ml = project(base_assessment()).ml
    assert ml.enabled is False
    assert "deterministic" in ml.note.lower()
    assert ml.role == ""


def test_ml_enabled_preserves_role_verbatim():
    ml = project(ai_enabled_assessment()).ml
    assert ml.enabled is True
    assert ml.role == "secondary prioritisation signal only"
    assert ml.facts["model_id"] == "robust-z-sum"
    assert len(ml.limitations) == 2
    assert "does not determine any security fact" in ml.boundary_statement
    assert "cannot move a finding from one tier" in ml.boundary_statement


def test_ml_panel_never_claims_detection():
    ml = project(ai_enabled_assessment()).ml
    blob = " ".join([ml.role, ml.note, ml.boundary_statement] + ml.limitations).lower()
    for forbidden in ("detected the attack", "ai detected", "found malicious",
                      "confirmed an intrusion", "detected tls stripping"):
        assert forbidden not in blob


def test_missing_model_summary_does_not_imply_ml_ran():
    a = base_assessment()
    a["model_summary"] = None
    ml = project(a).ml
    assert ml.enabled is False and ml.role == ""


# ---------------------------------------------------------------- unavailable
def test_unavailable_data_is_declared():
    vm = project(base_assessment())
    joined = " ".join(vm.unavailable).lower()
    assert "per-session finding rows" in joined
    assert "packet-level" in joined
    assert "percentage" in joined


# --------------------------------------------------------- hostile / large
def test_hostile_strings_are_carried_as_data():
    """The projection stores them verbatim; escaping is the renderer's job."""
    vm = project(hostile_assessment())
    assert vm.limitations[0].startswith("<script>")
    assert vm.issue_groups[0].title.startswith("<script>")


def test_hostile_strings_never_reach_a_tone_or_key():
    a = base_assessment()
    a["prioritised"][0]["representative_finding"]["severity"] = '"><script>x</script>'
    row = project(a).findings[0]
    assert row.severity_tone == "unknown"         # no assessment text in a CSS class
    assert "<" not in row.severity_tone


def test_large_assessment_projects_completely():
    a = large_assessment(groups=300, abstentions=200)
    vm = project(a)
    assert len(vm.findings) == 300 and len(vm.abstentions) == 200
    assert len(vm.issue_groups) == 300


@pytest.mark.parametrize("builder", ALL_FIXTURES)
def test_view_model_is_json_serialisable(builder):
    import json
    payload = json.dumps(project(builder()).to_dict())
    assert len(payload) > 0
    assert json.loads(payload)["identity"]["assessment_id"]
