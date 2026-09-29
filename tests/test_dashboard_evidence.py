"""
Phase-10 tests: the Evidence & provenance screen (doc 23 §7 Screen 4).

This is the screen where the product's honesty is most visible, so these tests are
mostly about what it must NOT do: soften an absence, invent a standards mapping,
rewrite the engine's resolution guidance, or fabricate drill-down the canonical
contract does not carry.
"""
import json
import os
import re

import pytest

fastapi = pytest.importorskip("fastapi", reason="backend extra not installed")
pytest.importorskip("httpx", reason="httpx required by TestClient")
from fastapi.testclient import TestClient                        # noqa: E402

from securemailscope.backend.api import create_app                # noqa: E402
from securemailscope.backend.lifecycle import JobState            # noqa: E402
from securemailscope.backend.repository import RunRecord          # noqa: E402
from securemailscope.backend.service import AnalysisService       # noqa: E402
from securemailscope.dashboard import project                     # noqa: E402
from securemailscope.dissect import TsharkAdapter                 # noqa: E402
from tests.reporting_fixtures import (                            # noqa: E402
    base_assessment, empty_assessment, hostile_assessment, insufficient_evidence,
    large_assessment,
)

EVIDENCE_JS = "src/securemailscope/dashboard/static/views/evidence.js"
STARTTLS = "research/experiments/oq33r/out/postfix_smtp_starttls_upgrade.pcap"


def _tshark():
    try:
        TsharkAdapter().version()
        return True
    except Exception:
        return False


needs_real = pytest.mark.skipif(
    not _tshark() or not os.path.isfile(STARTTLS),
    reason="tshark or OQ-33r captures absent")


def _source():
    with open(EVIDENCE_JS, encoding="utf-8") as fh:
        return fh.read()


def _prose():
    """Source as it reads at runtime, for searching authored copy.

    Joins JS string concatenation (`'foo ' + 'bar'` is one string at runtime) and
    unescapes `\'`, which appears inside single-quoted literals. Searching raw source
    would miss both and report false failures.
    """
    joined = re.sub(r"'\s*\+\s*'", "", _source())
    return joined.replace("\\'", "'")


def _seeded(tmp_path, assessment=None):
    assessment = assessment or base_assessment()
    svc = AnalysisService(str(tmp_path / "data"))
    run = svc.repo.create_run(RunRecord.new())
    svc.repo.store_assessment(assessment)
    for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING,
                   JobState.FINALIZING):
        svc.repo.transition(run, target, capture_id=assessment["capture_id"])
    svc.repo.transition(run, JobState.COMPLETED,
                        assessment_id=assessment["assessment_id"])
    return svc, run.run_id, assessment


def _client(svc):
    return TestClient(create_app(service=svc), raise_server_exceptions=False)


# ------------------------------------------------------------ evidence states
def test_all_six_evidence_states_are_known_to_the_screen():
    """The six states Phase 1 defined must each have their own meaning here."""
    source = _source()
    for state in ("OBSERVED", "INFERRED", "AMBIGUOUS", "INCOMPLETE", "UNKNOWN",
                  "NOT_OBSERVABLE"):
        assert state in source, state


def test_evidence_states_are_never_collapsed():
    prose = _prose()
    assert "three different reasons for not knowing" in prose
    assert "none of them is evidence that a thing is safe" in prose


def test_unknown_evidence_state_is_labelled_not_dropped():
    source = _source()
    assert "a state this console version does not recognise" in source


def test_evidence_states_reach_the_view_model(tmp_path):
    svc, run_id, a = _seeded(tmp_path)
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()
    assert vm["coverage"]["observation_counts"] == a["coverage"]["observation_counts"]
    assert "NOT_OBSERVABLE" in vm["coverage"]["observation_counts"]
    assert "AMBIGUOUS" in vm["coverage"]["observation_counts"]


def test_absent_coverage_is_stated_not_zeroed(tmp_path):
    a = base_assessment()
    a["coverage"] = {}
    svc, run_id, _ = _seeded(tmp_path, a)
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()
    assert vm["coverage"]["present"] is False
    assert vm["coverage"]["sessions_total"] is None
    assert "no coverage information" in _prose()


# ----------------------------------------------------------------- abstentions
def test_abstentions_render_reason_why_and_resolution():
    source = _source()
    for field in ("a.reason_label", "a.issue_class_label",
                  "a.what_could_not_be_concluded", "a.why", "a.resolved_by",
                  "a.protocol_label", "a.frames"):
        assert field in source, field


def test_resolution_guidance_is_not_rewritten():
    """`resolved_by` is the engine's wording and is rendered, not paraphrased."""
    prose = _prose()
    assert "the assessment's own wording" in prose
    assert "text(a.resolved_by, '—')" in _source()


def test_abstention_is_neither_failure_nor_pass():
    assert "neither a failure nor a pass" in _prose()
    assert "Treating any row above as compliant" in _prose()


def test_abstentions_survive_to_the_view_model(tmp_path):
    svc, run_id, a = _seeded(tmp_path)
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()
    assert len(vm["abstentions"]) == len(a["abstentions"])
    row = vm["abstentions"][0]
    assert row["reason"] == "NOT_OBSERVABLE"
    assert row["reason_label"] == "Not observable"
    assert row["resolved_by"] == a["abstentions"][0]["resolved_by"]


def test_no_abstentions_states_the_absence():
    assert "recorded no abstentions" in _prose()


def test_abstention_heavy_assessment_renders_every_row(tmp_path):
    a = large_assessment(groups=5, abstentions=60)
    svc, run_id, _ = _seeded(tmp_path, a)
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()
    assert len(vm["abstentions"]) == 60


# ------------------------------------------------------------------ standards
def test_standards_render_sections_and_distinct_count():
    source = _source()
    assert "row.sections" in source
    assert "s.distinct_standards" in source


def test_unmapped_citations_are_surfaced_not_hidden(tmp_path):
    a = base_assessment()
    a["standards_summary"] = {
        "standards": {"RFC 3207": ["2"]}, "distinct_standards": 1,
        "unmapped_citations": ["RFC 8446 SS2 (handshake message flow)"],
        "note": "n"}
    svc, run_id, _ = _seeded(tmp_path, a)
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()
    assert vm["standards"]["unmapped_citations"] == \
        ["RFC 8446 SS2 (handshake message flow)"]
    prose = _prose()
    assert "Unmapped citations" in prose
    assert "could not map them to" in prose
    assert "suppressing it would make the coverage above look" in prose


def test_no_standards_mapping_is_invented():
    """The screen renders the registry's mapping; it never builds one."""
    source = _source()
    assert "RFC 3207" not in source
    assert "NIST" not in source
    assert "RFC 8446" not in source


def test_standards_disclaim_compliance():
    assert "not a statement of compliance or certification" in _prose()


# ----------------------------------------------------------------- provenance
def test_provenance_renders_identity_rules_and_counts():
    source = _source()
    for field in ("id.assessment_id", "id.capture_id", "id.run_id",
                  "id.generated_at", "id.posture_engine_version",
                  "id.posture_schema_version", "p.rule_ids", "p.source_counts",
                  "p.entries"):
        assert field in source, field


def test_provenance_reaches_the_view_model(tmp_path):
    a = base_assessment()
    a["provenance"] = {"rule_ids": ["SEC-PLAIN-002", "SEC-TLS-001"],
                       "source_counts": {"deterministic_findings": 2},
                       "contradictions_recorded": 0, "note": "n"}
    svc, run_id, _ = _seeded(tmp_path, a)
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()
    assert vm["provenance"]["rule_ids"] == ["SEC-PLAIN-002", "SEC-TLS-001"]
    assert vm["provenance"]["source_counts"]["deterministic_findings"] == 2
    assert "contradictions_recorded" in vm["provenance"]["entries"]


def test_capture_id_meaning_is_stated():
    assert "a capture that hashes differently is a different capture" in \
        _prose().lower()


# ------------------------------------------------------- artifact integrity
@needs_real
def test_artifact_integrity_is_reported(tmp_path):
    svc = AnalysisService(str(tmp_path / "data"))
    run = svc.submit_path(STARTTLS).run
    client = _client(svc)
    body = client.get("/api/v1/analyses/%s/artifacts?verify=true" % run.run_id).json()
    assert body["items"]
    assert body["items"][0]["integrity"] == "OK"
    assert len(body["items"][0]["sha256"]) == 64
    assert "relative_path" not in body["items"][0]


def test_artifact_panel_explains_how_integrity_is_established():
    prose = _prose()
    assert "re-reading each stored artifact" in prose
    assert "reported as a mismatch rather than served as intact" in prose


def test_artifact_failure_does_not_take_the_screen_down():
    source = _source()
    assert "artifactError" in source
    assert "The assessment itself is unaffected." in _prose()


# --------------------------------------------------------------- unavailable
def test_unavailable_evidence_is_declared_not_faked():
    prose = _prose()
    assert "Session timelines" in prose
    assert "absences in the canonical assessment, not omissions in this view" in prose
    assert "an approximation here would be indistinguishable from evidence" in prose


def test_no_fabricated_drilldown_ui():
    """No packet link, no timeline widget, no per-session row."""
    source = _source()
    for forbidden in ("packet/", "/packets", "timeline(", "drawTimeline",
                      "sessionRows", "fetchPackets"):
        assert forbidden not in source, forbidden


def test_unavailable_list_reaches_the_view_model(tmp_path):
    svc, run_id, _ = _seeded(tmp_path)
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()
    joined = " ".join(vm["unavailable"]).lower()
    assert "per-session finding rows" in joined
    assert "packet-level" in joined


# --------------------------------------------------------------- limitations
def test_limitations_are_rendered_verbatim_and_not_summarised():
    prose = _prose()
    assert "the engine's own words and are not summarised here" in prose


def test_limitations_reach_the_view_model(tmp_path):
    svc, run_id, a = _seeded(tmp_path)
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()
    assert vm["limitations"] == a["limitations"]


def test_insufficient_evidence_notice_appears_on_this_screen(tmp_path):
    svc, run_id, _ = _seeded(tmp_path, insufficient_evidence())
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()
    assert any("withheld" in n.lower() for n in vm["notices"])
    assert "vm.notices" in _source()


def test_absent_limitations_are_flagged_as_unusual():
    assert "That is unusual and should be verified" in _prose()


# ------------------------------------------------------------------ security
def test_evidence_view_obeys_the_dom_boundary():
    stripped = re.sub(r"/\*.*?\*/", "", _source(), flags=re.S)
    stripped = re.sub(r"^\s*//.*$", "", stripped, flags=re.M)
    for forbidden in (".innerHTML", ".outerHTML", ".insertAdjacentHTML",
                      "document.write", "eval(", "new Function("):
        assert forbidden not in stripped, forbidden


def test_evidence_view_builds_no_urls_from_data():
    source = _source()
    assert "href" not in source
    assert "src:" not in source


def test_evidence_view_performs_no_security_arithmetic():
    stripped = re.sub(r"/\*.*?\*/", "", _source(), flags=re.S)
    for pattern in (r"severity\s*[=!]==\s*['\"]", r"score\s*[<>]",
                    r"if\s*\(\s*\w*risk\w*"):
        assert not re.search(pattern, stripped, re.I), pattern


@pytest.mark.parametrize("field,path", [
    ("limitations", ["limitations"]),
    ("abstention why", ["abstentions", 0, "why"]),
    ("abstention resolution", ["abstentions", 0, "resolved_by"]),
    ("provenance note", ["provenance", "note"]),
])
def test_hostile_strings_survive_as_data(tmp_path, field, path):
    payload = '<script>alert(1)</script><img src=x onerror=alert(1)>'
    a = base_assessment()
    a["limitations"] = [payload]
    a["abstentions"][0]["why"] = payload
    a["abstentions"][0]["resolved_by"] = payload
    a["provenance"] = {"note": payload, "rule_ids": [payload],
                       "source_counts": {payload: 1}}
    a["standards_summary"] = {"standards": {payload: [payload]},
                              "distinct_standards": 1,
                              "unmapped_citations": [payload], "note": payload}
    svc, run_id, _ = _seeded(tmp_path, a)
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()

    node = vm
    for key in path:
        node = node[key]
    assert payload in (node if isinstance(node, str) else json.dumps(node))


def test_hostile_provenance_and_standards_reach_no_class_or_url(tmp_path):
    payload = '"><script>alert(1)</script>'
    a = base_assessment()
    a["provenance"] = {"rule_ids": [payload], "source_counts": {payload: 1},
                       "note": payload}
    a["standards_summary"] = {"standards": {payload: [payload]},
                              "distinct_standards": 1, "unmapped_citations": [payload],
                              "note": payload}
    svc, run_id, _ = _seeded(tmp_path, a)
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()
    # data preserved verbatim
    assert vm["provenance"]["rule_ids"] == [payload]
    assert vm["standards"]["standards"][0]["standard"] == payload
    # and the screen never puts these into a class or a URL
    source = _source()
    assert "className: `" not in source           # no template-built class names
    assert "href" not in source


def test_long_identifiers_do_not_break_the_model(tmp_path):
    a = base_assessment()
    a["provenance"] = {"rule_ids": ["R" * 500], "source_counts": {}, "note": "x" * 5000}
    svc, run_id, _ = _seeded(tmp_path, a)
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()
    assert vm["provenance"]["rule_ids"] == ["R" * 500]
    assert len(vm["provenance"]["note"]) == 5000


def test_empty_assessment_renders_every_mandatory_section(tmp_path):
    svc, run_id, _ = _seeded(tmp_path, empty_assessment())
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()
    assert vm["abstentions"] == []
    assert vm["limitations"] == []
    assert vm["standards"]["present"] is False
    assert vm["unavailable"]


# --------------------------------------------------------------- real capture
@needs_real
def test_real_capture_evidence_matches_the_assessment(tmp_path):
    svc = AnalysisService(str(tmp_path / "data"))
    run = svc.submit_path(STARTTLS, ai_enabled=True).run
    client = _client(svc)
    vm = client.get("/api/v1/analyses/%s/dashboard" % run.run_id).json()
    canonical = client.get(
        "/api/v1/analyses/%s/assessment" % run.run_id).json()["assessment"]

    assert len(vm["abstentions"]) == len(canonical["abstentions"])
    assert vm["limitations"] == canonical["limitations"]
    assert vm["coverage"]["observation_counts"] == \
        canonical["coverage"]["observation_counts"]
    assert vm["provenance"]["rule_ids"] == canonical["provenance"]["rule_ids"]
    # this capture genuinely abstains on certificate observability
    reasons = {a["reason"] for a in vm["abstentions"]}
    assert reasons, "real capture should record abstentions"
    assert all(a["resolved_by"] for a in vm["abstentions"])
