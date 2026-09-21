"""
Phase-10 tests: the Overview screen and its view-model endpoint (doc 23 §6, §7, §10).

The screen itself is JavaScript, so these tests defend the two things that decide what
it can possibly show: the endpoint that feeds it, and the projection's semantics for the
cases the screen must get right — a withheld band, no findings, an anomaly signal,
unknown enums, hostile text.

A separate test drives a **real PCAP** end to end so the screen is not validated only
against hand-built fixtures.
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
from securemailscope.dashboard import vocabulary as vocab         # noqa: E402
from securemailscope.dissect import TsharkAdapter                 # noqa: E402
from tests.reporting_fixtures import (                            # noqa: E402
    ai_enabled_assessment, base_assessment, critical_assessment, empty_assessment,
    hostile_assessment, insufficient_evidence, large_assessment,
)

PCAP_DIR = "research/experiments/oq33r/out"
STARTTLS = os.path.join(PCAP_DIR, "postfix_smtp_starttls_upgrade.pcap")
OVERVIEW_JS = "src/securemailscope/dashboard/static/views/overview.js"


def _js_prose(path=OVERVIEW_JS):
    """Source with JS string concatenation joined, so a wrapped literal is searchable.

    `'foo ' + 'bar'` in source is the single string `foo bar` at runtime; a naive
    substring search over raw source would miss it and report a false failure.
    """
    source = open(path, encoding="utf-8").read()
    return re.sub(r"'\s*\+\s*'", "", source)


def _tshark():
    try:
        TsharkAdapter().version()
        return True
    except Exception:
        return False


needs_real = pytest.mark.skipif(
    not _tshark() or not os.path.isfile(STARTTLS),
    reason="tshark or OQ-33r captures absent")


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


def _vm(tmp_path, assessment=None):
    svc, run_id, a = _seeded(tmp_path, assessment)
    return _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json(), run_id, a


# ------------------------------------------------------- view-model endpoint
def test_endpoint_returns_the_projection(tmp_path):
    vm, _run_id, assessment = _vm(tmp_path)
    assert vm == json.loads(json.dumps(project(assessment).to_dict()))


def test_endpoint_adds_no_field_the_assessment_lacks(tmp_path):
    """doc 23 §6: the view model is derived, never enriched."""
    vm, _run_id, assessment = _vm(tmp_path)
    assert vm["posture"]["value"] == assessment["overall_posture"]
    assert vm["posture"]["score_value"] == assessment["score"]["value"]
    assert len(vm["findings"]) == len(assessment["prioritised"])
    assert vm["limitations"] == assessment["limitations"]


def test_assessment_endpoint_remains_canonical(tmp_path):
    svc, run_id, assessment = _seeded(tmp_path)
    client = _client(svc)
    canonical = client.get("/api/v1/analyses/%s/assessment" % run_id).json()
    assert canonical["assessment"] == assessment
    # the view model does not replace it
    assert client.get("/api/v1/analyses/%s/dashboard" % run_id).status_code == 200


def test_view_model_is_not_stored(tmp_path):
    """Derived per request; no artefact, no table."""
    svc, run_id, _ = _seeded(tmp_path)
    _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id)
    assert svc.repo.list_artifacts(run_id) == []


def test_unknown_run_is_404(tmp_path):
    svc, _, _ = _seeded(tmp_path)
    r = _client(svc).get("/api/v1/analyses/%s/dashboard" % ("a" * 32))
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "NOT_FOUND"


@pytest.mark.parametrize("hostile", ["../../etc/passwd", "' OR 1=1--", "zz", "%00"])
def test_hostile_run_id_rejected(tmp_path, hostile):
    svc, _, _ = _seeded(tmp_path)
    r = _client(svc).get("/api/v1/analyses/%s/dashboard" % hostile)
    assert r.status_code in (400, 404)
    assert "passwd" not in r.text and "Traceback" not in r.text


def test_malformed_assessment_is_422_not_a_partial_view(tmp_path):
    broken = {"assessment_id": "x" * 16, "capture_id": "y" * 64}
    svc = AnalysisService(str(tmp_path / "d"))
    run = svc.repo.create_run(RunRecord.new())
    svc.repo.store_assessment(broken)
    for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING,
                   JobState.FINALIZING):
        svc.repo.transition(run, target, capture_id=broken["capture_id"])
    svc.repo.transition(run, JobState.COMPLETED, assessment_id=broken["assessment_id"])
    r = _client(svc).get("/api/v1/analyses/%s/dashboard" % run.run_id)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "MALFORMED_ASSESSMENT"


# ------------------------------------------- the states the screen must render
def test_normal_posture_has_everything_the_screen_needs(tmp_path):
    vm, _, _ = _vm(tmp_path)
    assert vm["posture"]["label"] == "ADEQUATE"
    assert vm["posture"]["score_text"] == "88 / 100"
    assert "75.0%" in vm["coverage"]["summary_text"]
    assert vm["protocols"] and vm["distributions"] and vm["findings"]
    assert vm["ml"] is not None and vm["identity"]["assessment_id"]


def test_insufficient_evidence_is_not_a_failure_and_not_a_pass(tmp_path):
    vm, _, _ = _vm(tmp_path, insufficient_evidence())
    assert vm["posture"]["value"] == "INSUFFICIENT_EVIDENCE"
    assert vm["posture"]["label"] == "INSUFFICIENT EVIDENCE"
    assert vm["posture"]["withheld"] is True
    assert vm["posture"]["score_value"] is None
    assert vm["posture"]["score_text"] == "Not scored"
    # its own tone: not a severity colour in either direction
    assert vm["posture"]["tone"] == "insufficient_evidence"
    assert vm["posture"]["tone"] not in ("critical", "strong", "weak", "adequate")
    joined = " ".join(vm["notices"]).lower()
    assert "withheld" in joined and "not a passing result" in joined


def test_no_findings_is_not_rendered_as_secure(tmp_path):
    vm, _, _ = _vm(tmp_path, empty_assessment())
    assert vm["findings"] == []
    blob = json.dumps(vm).lower()
    # the projection must not have manufactured reassurance
    for forbidden in ('"secure"', '"safe"', '"healthy"', '"pass"', '"clean"'):
        assert forbidden not in blob
    # and the screen's own copy for this case says so — asserted against the source
    assert "not a statement that the infrastructure is secure" in _js_prose()


def test_multiple_findings_and_top_slice(tmp_path):
    vm, _, _ = _vm(tmp_path, large_assessment(groups=12, abstentions=3))
    assert len(vm["findings"]) == 12
    ranks = [f["rank"] for f in vm["findings"]]
    assert ranks == sorted(ranks)          # canonical order preserved
    source = _js_prose()
    assert "const TOP_FINDINGS = 5" in source
    assert "View all" in source            # the rest remain reachable


def test_multiple_protocols_carry_not_observable_dimensions(tmp_path):
    a = base_assessment()
    a["protocol_posture"] = [
        {"protocol": "smtp", "sessions": 2,
         "score": {"value": 88.0, "band": "ADEQUATE"},
         "issue_classes": ["NO_TLS_PROTECTION"],
         "dimensions_assessed": ["PLAINTEXT_EXPOSURE"],
         "dimensions_not_observable": ["CERTIFICATE_TRUST"], "abstentions": 0},
        {"protocol": "imap", "sessions": 1, "score": None,
         "issue_classes": [], "dimensions_assessed": [],
         "dimensions_not_observable": ["CERTIFICATE_TRUST", "CRYPTO_CONFIGURATION"],
         "abstentions": 3},
    ]
    vm, _, _ = _vm(tmp_path, a)
    assert len(vm["protocols"]) == 2
    imap = [p for p in vm["protocols"] if p["protocol"] == "imap"][0]
    assert imap["band"] is None and imap["band_label"] == "Not scored"
    assert len(imap["dimensions_not_observable"]) == 2
    assert "Absence of an observed issue is not evidence that a protocol is secure" \
        in _js_prose()


def test_anomaly_signal_is_not_presented_as_an_attack(tmp_path):
    a = base_assessment()
    a["risk_summary"] = {"by_fact_kind": {"ANOMALY_SIGNAL": 2,
                                          "BASE_SECURITY_ISSUE": 1}}
    vm, _, _ = _vm(tmp_path, a)
    kinds = [d for d in vm["distributions"] if d["id"] == "by-fact-kind"][0]
    labels = {b["key"]: b["label"] for b in kinds["bars"]}
    assert labels["ANOMALY_SIGNAL"] == "Anomaly signal"
    blob = json.dumps(vm).lower()
    for forbidden in ("attack detected", "intrusion", "malicious", "attacker",
                      "compromise"):
        assert forbidden not in blob


def test_ai_disabled_and_enabled(tmp_path):
    off, _, _ = _vm(tmp_path, base_assessment())
    assert off["ml"]["enabled"] is False
    assert "deterministic" in off["ml"]["note"].lower()

    on, _, _ = _vm(tmp_path / "b", ai_enabled_assessment())
    assert on["ml"]["enabled"] is True
    assert on["ml"]["role"] == "secondary prioritisation signal only"
    assert len(on["ml"]["limitations"]) == 2
    assert "does not determine any security fact" in on["ml"]["boundary_statement"]


def test_abstentions_reach_the_overview(tmp_path):
    vm, _, a = _vm(tmp_path)
    assert len(vm["abstentions"]) == len(a["abstentions"])
    assert vm["abstentions"][0]["reason_label"] == "Not observable"
    assert vm["abstentions"][0]["resolved_by"]


def test_unknown_enum_values_do_not_break_the_view_model(tmp_path):
    a = base_assessment()
    a["overall_posture"] = "QUANTUM_UNSAFE"
    a["prioritised"][0]["representative_finding"]["severity"] = "APOCALYPTIC"
    a["prioritised"][0]["representative_finding"]["status"] = "NEW_STATUS"
    vm, _, _ = _vm(tmp_path, a)
    assert vm["posture"]["value"] == "QUANTUM_UNSAFE"
    assert vm["posture"]["known"] is False
    assert vm["posture"]["tone"] == "unknown"
    row = vm["findings"][0]
    assert row["severity"] == "APOCALYPTIC"
    assert row["severity_known"] is False
    assert row["severity_tone"] == "unknown"
    assert row["status_label"] == "New status"


def test_missing_optional_fields(tmp_path):
    a = base_assessment()
    a["score"] = None
    a["protocol_posture"] = []
    a["risk_summary"] = {}
    a["model_summary"] = None
    a["standards_summary"] = {}
    vm, _, _ = _vm(tmp_path, a)
    assert vm["posture"]["score_value"] is None
    assert vm["protocols"] == [] and vm["distributions"] == []
    assert vm["ml"]["enabled"] is False
    assert vm["standards"]["present"] is False


def test_long_identifiers_and_text_are_carried_whole(tmp_path):
    a = base_assessment()
    long_title = "A " + ("very " * 200) + "long issue title"
    a["issue_groups"][0]["title"] = long_title
    a["prioritised"][0]["representative_finding"]["title"] = long_title
    vm, _, _ = _vm(tmp_path, a)
    assert vm["findings"][0]["title"] == long_title      # nothing truncated silently
    assert len(vm["identity"]["capture_id"]) == 64


# --------------------------------------------------------- hostile content
def test_hostile_strings_survive_as_data_and_reach_no_class(tmp_path):
    vm, _, _ = _vm(tmp_path, hostile_assessment())
    assert vm["limitations"][0].startswith("<script>")
    for row in vm["findings"]:
        assert re.match(r"^[a-z_]+$", row["severity_tone"])
        assert "<" not in row["severity_tone"]
    assert re.match(r"^[a-z_]+$", vm["posture"]["tone"])


def test_hostile_protocol_name_cannot_become_a_class(tmp_path):
    a = base_assessment()
    a["protocol_posture"] = [{
        "protocol": '"><script>alert(1)</script>', "sessions": 1,
        "score": {"value": 50.0, "band": '"><img src=x onerror=alert(1)>'},
        "issue_classes": [], "dimensions_assessed": [],
        "dimensions_not_observable": [], "abstentions": 0}]
    vm, _, _ = _vm(tmp_path, a)
    row = vm["protocols"][0]
    assert row["protocol"] == '"><script>alert(1)</script>'    # data preserved
    assert row["band_tone"] == "unknown"                        # class is safe
    assert re.match(r"^[a-z_]+$", row["band_tone"])


def test_overview_source_obeys_the_dom_boundary():
    """The screen must build nodes, never markup (doc 23 §11)."""
    source = open(OVERVIEW_JS, encoding="utf-8").read()
    stripped = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    stripped = re.sub(r"^\s*//.*$", "", stripped, flags=re.M)
    for forbidden in (".innerHTML", ".outerHTML", ".insertAdjacentHTML",
                      "document.write", "eval(", "new Function("):
        assert forbidden not in stripped, forbidden
    # hrefs come only from the validated helper or a hash route
    assert "reportUrl(runId, format)" in source
    assert "href: `#/run/${runId}/findings`" in source


def test_overview_performs_no_security_arithmetic():
    """doc 23 §5: no threshold, no bucketing, no comparison on a security value."""
    source = open(OVERVIEW_JS, encoding="utf-8").read()
    stripped = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    stripped = re.sub(r"^\s*//.*$", "", stripped, flags=re.M)
    for pattern in (r"score\s*[<>]",
                    r"severity\s*[=!]==\s*['\"]",
                    r"if\s*\(\s*\w*score\w*\s*[<>]",
                    r"\bMath\.(max|min|round)\s*\(\s*\w*(score|severity)"):
        assert not re.search(pattern, stripped, re.I), pattern


def test_overview_never_reorders_canonical_findings():
    """doc 23 §5: the assessment decided the order.

    Display-ordering a list of evidence-state LABELS is presentation and is allowed;
    sorting `findings`, `prioritised` or `protocols` is not.
    """
    source = open(OVERVIEW_JS, encoding="utf-8").read()
    for collection in ("findings", "prioritised", "protocols", "issue_groups",
                       "abstentions"):
        assert not re.search(r"%s[^;\n]*\.sort\(" % collection, source), collection
    # the top slice is taken from the canonical order, unsorted
    assert "vm.findings.slice(0, TOP_FINDINGS)" in source
    # the only sort present operates on Object.entries of a counts map
    sorts = re.findall(r"(\w+)\.sort\(", source)
    assert sorts == ["states"], sorts


# ------------------------------------------------ real PCAP end to end (§33)
@needs_real
def test_real_pcap_reaches_the_overview_view_model(tmp_path):
    """Validated against a real Postfix capture, not only UI fixtures."""
    svc = AnalysisService(str(tmp_path / "data"))
    run = svc.submit_path(STARTTLS, ai_enabled=True).run
    client = _client(svc)

    vm = client.get("/api/v1/analyses/%s/dashboard" % run.run_id).json()
    canonical = client.get(
        "/api/v1/analyses/%s/assessment" % run.run_id).json()["assessment"]

    # identity matches the real analysis
    assert vm["identity"]["assessment_id"] == canonical["assessment_id"]
    assert vm["identity"]["capture_id"] == run.capture_id
    assert vm["identity"]["ai_enabled"] is True

    # posture, score and coverage are the canonical ones
    assert vm["posture"]["value"] == canonical["overall_posture"]
    assert vm["posture"]["score_value"] == canonical["score"]["value"]
    assert vm["coverage"]["sessions_total"] == \
        canonical["coverage"]["sessions_total"]

    # the screen has real content to render
    assert vm["protocols"], "real capture should yield protocol posture"
    assert vm["distributions"], "real capture should yield distributions"
    assert vm["abstentions"], "this capture abstains on certificate observability"
    assert vm["limitations"]

    # the ML lane declares itself honestly
    assert vm["ml"]["enabled"] is True
    assert vm["ml"]["role"] == "secondary prioritisation signal only"
    blob = json.dumps(vm).lower()
    for forbidden in ("attack detected", "intrusion", "malicious traffic"):
        assert forbidden not in blob


@needs_real
def test_real_pcap_overview_matches_report_and_json(tmp_path):
    """The console, the report and the canonical JSON agree for one run."""
    svc = AnalysisService(str(tmp_path / "data"))
    run = svc.submit_path(STARTTLS).run
    client = _client(svc)

    vm = client.get("/api/v1/analyses/%s/dashboard" % run.run_id).json()
    report_json = client.get(
        "/api/v1/analyses/%s/reports/json" % run.run_id).json()
    html = client.get("/api/v1/analyses/%s/reports/html" % run.run_id).text

    assert vm["posture"]["value"] == report_json["overall_posture"]
    assert vm["identity"]["assessment_id"] == report_json["assessment_id"]
    assert report_json["overall_posture"].replace("_", " ") in re.sub(
        r"<[^>]+>", " ", html)


@needs_real
def test_real_pcap_with_no_ai_reports_ml_disabled(tmp_path):
    svc = AnalysisService(str(tmp_path / "data"))
    run = svc.submit_path(STARTTLS, ai_enabled=False).run
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run.run_id).json()
    assert vm["identity"]["ai_enabled"] is False
    assert vm["ml"]["enabled"] is False
    assert vm["ml"]["role"] == ""
