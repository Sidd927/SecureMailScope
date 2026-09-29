"""
Phase-10 tests: the Findings screen and its filter logic (doc 23 §7 Screen 3).

The filter logic is JavaScript, so these tests **execute the shipped module in Node**
against real view-model data rather than reimplementing it in Python. A Python copy of
the logic would pass while the code an analyst runs failed.

`filtering.js` is deliberately free of DOM imports so this is possible; if a future
change makes it depend on a browser, `test_filtering_module_stays_dom_free` fails.
"""
import json
import os
import re
import shutil
import subprocess

import pytest

fastapi = pytest.importorskip("fastapi", reason="backend extra not installed")
pytest.importorskip("httpx", reason="httpx required by TestClient")
from fastapi.testclient import TestClient                        # noqa: E402

from securemailscope.backend.api import create_app                # noqa: E402
from securemailscope.backend.lifecycle import JobState            # noqa: E402
from securemailscope.backend.repository import RunRecord          # noqa: E402
from securemailscope.backend.service import AnalysisService       # noqa: E402
from securemailscope.dashboard import project, vocabulary as vocab  # noqa: E402
from securemailscope.dissect import TsharkAdapter                 # noqa: E402
from tests.reporting_fixtures import (                            # noqa: E402
    base_assessment, critical_assessment, empty_assessment, hostile_assessment,
    large_assessment,
)

STATIC = "src/securemailscope/dashboard/static"
FILTERING_JS = os.path.join(STATIC, "filtering.js")
FINDINGS_JS = os.path.join(STATIC, "views/findings.js")
STARTTLS = "research/experiments/oq33r/out/postfix_smtp_starttls_upgrade.pcap"

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")


def _tshark():
    try:
        TsharkAdapter().version()
        return True
    except Exception:
        return False


needs_real = pytest.mark.skipif(
    not _tshark() or not os.path.isfile(STARTTLS),
    reason="tshark or OQ-33r captures absent")


def _source(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def run_filter(findings, selections, tmp_path):
    """Execute the SHIPPED filtering module in Node and return the visible ranks.

    Also returns the input array as Node saw it afterwards, so mutation of the
    canonical list is detectable rather than assumed absent.
    """
    payload = tmp_path / "payload.json"
    payload.write_text(json.dumps({"findings": findings, "state": selections}),
                       encoding="utf-8")
    script = tmp_path / "run.mjs"
    module = os.path.abspath(FILTERING_JS)
    script.write_text(
        "import { applyFilters, activeCount } from %s;\n"
        "import { readFileSync } from 'node:fs';\n"
        "const input = JSON.parse(readFileSync(%s, 'utf8'));\n"
        "const before = JSON.stringify(input.findings);\n"
        "const visible = applyFilters(input.findings, input.state);\n"
        "const after = JSON.stringify(input.findings);\n"
        "process.stdout.write(JSON.stringify({\n"
        "  visible: visible.map(r => r.rank),\n"
        "  input_unchanged: before === after,\n"
        "  returned_new_array: visible !== input.findings,\n"
        "  active: activeCount(input.state),\n"
        "}));\n" % (json.dumps(module), json.dumps(str(payload))),
        encoding="utf-8")
    result = subprocess.run([NODE, str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _vm_findings(assessment):
    return json.loads(json.dumps(project(assessment).to_dict()))["findings"]


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


def _anomaly_assessment():
    """Base assessment plus an anomaly entry with `session.protocol = None`."""
    a = base_assessment()
    a["prioritised"] = a["prioritised"] + [{
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
            "session": {"capture_id": "f" * 64, "stream_key": "tcp-1",
                        "protocol": None, "tcp_stream_id": 1},
            "frames": [], "source_rule_ids": [], "sources": [], "citations": [],
            "ml_signal": None, "remediation": None, "limitations": [],
            "contradictions": [],
        }}]
    return a


# --------------------------------------------------- module hygiene
def test_filtering_module_stays_dom_free():
    """It must remain executable without a browser, or these tests stop being real."""
    source = _source(FILTERING_JS)
    for forbidden in ("document", "window", "./dom.js", "./api.js", "./app.js",
                      "localStorage"):
        assert forbidden not in source, forbidden


def test_findings_view_uses_the_shared_filter_module():
    """The screen must not carry a second, divergent copy of the logic."""
    source = _source(FINDINGS_JS)
    assert "from '../filtering.js'" in source
    assert "function applyFilters" not in source


def test_findings_view_obeys_the_dom_boundary():
    source = _source(FINDINGS_JS)
    stripped = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    stripped = re.sub(r"^\s*//.*$", "", stripped, flags=re.M)
    for forbidden in (".innerHTML", ".outerHTML", ".insertAdjacentHTML",
                      "document.write", "eval(", "new Function("):
        assert forbidden not in stripped, forbidden


def test_findings_view_never_sorts_or_mutates():
    source = _source(FINDINGS_JS)
    for forbidden in (".sort(", ".reverse(", ".splice(", "findings.push(",
                      "vm.findings ="):
        assert forbidden not in source, forbidden


def test_findings_view_performs_no_security_arithmetic():
    source = _source(FINDINGS_JS)
    stripped = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    for pattern in (r"severity\s*[=!]==\s*['\"]", r"score\s*[<>]",
                    r"priority_score\s*[<>]"):
        assert not re.search(pattern, stripped, re.I), pattern


# ------------------------------------------------- canonical order (§1, §2)
@needs_node
def test_no_filters_returns_canonical_order(tmp_path):
    findings = _vm_findings(large_assessment(groups=15, abstentions=0))
    result = run_filter(findings, {}, tmp_path)
    assert result["visible"] == [f["rank"] for f in findings]
    assert result["active"] == 0


@needs_node
def test_filtering_never_mutates_the_canonical_list(tmp_path):
    findings = _vm_findings(large_assessment(groups=10, abstentions=0))
    result = run_filter(findings, {"severity": ["CRITICAL", "HIGH"]}, tmp_path)
    assert result["input_unchanged"] is True
    assert result["returned_new_array"] is True


@needs_node
def test_clearing_filters_restores_exact_canonical_order(tmp_path):
    findings = _vm_findings(large_assessment(groups=20, abstentions=0))
    canonical = [f["rank"] for f in findings]
    filtered = run_filter(findings, {"severity": ["MEDIUM"]}, tmp_path)
    assert filtered["visible"] != canonical
    cleared = run_filter(findings, {}, tmp_path)
    assert cleared["visible"] == canonical


@needs_node
def test_filtered_subset_preserves_relative_order(tmp_path):
    findings = _vm_findings(large_assessment(groups=20, abstentions=0))
    result = run_filter(findings, {"severity": ["HIGH", "INFO"]}, tmp_path)
    assert result["visible"] == sorted(result["visible"])


# ------------------------------------------------------ individual facets
@needs_node
@pytest.mark.parametrize("facet,field", [
    ("severity", "severity"), ("status", "status"), ("certainty", "certainty"),
    ("observability", "observability"), ("fact_kind", "fact_kind"),
    ("dimension", "dimension"), ("issue_class", "issue_class"),
])
def test_each_facet_filters_independently(tmp_path, facet, field):
    findings = _vm_findings(_anomaly_assessment())
    values = {f[field] for f in findings if f[field] is not None}
    assert values, "fixture should exercise %s" % facet
    for value in values:
        result = run_filter(findings, {facet: [value]}, tmp_path)
        expected = [f["rank"] for f in findings if f[field] == value]
        assert result["visible"] == expected, (facet, value)
        assert result["active"] == 1


@needs_node
def test_multiple_values_within_a_facet_are_or(tmp_path):
    findings = _vm_findings(large_assessment(groups=10, abstentions=0))
    result = run_filter(findings, {"severity": ["CRITICAL", "HIGH"]}, tmp_path)
    expected = [f["rank"] for f in findings
                if f["severity"] in ("CRITICAL", "HIGH")]
    assert result["visible"] == expected


@needs_node
def test_multiple_facets_are_and(tmp_path):
    findings = _vm_findings(large_assessment(groups=12, abstentions=0))
    both = run_filter(findings, {"severity": ["CRITICAL"],
                                 "status": ["OBSERVED_ISSUE"]}, tmp_path)
    expected = [f["rank"] for f in findings
                if f["severity"] == "CRITICAL" and f["status"] == "OBSERVED_ISSUE"]
    assert both["visible"] == expected
    assert both["active"] == 2


@needs_node
def test_contradictory_filters_yield_an_empty_set(tmp_path):
    findings = _vm_findings(large_assessment(groups=10, abstentions=0))
    result = run_filter(findings, {"severity": ["CRITICAL"], "fact_kind": ["ABSENT"]},
                        tmp_path)
    assert result["visible"] == []
    assert result["input_unchanged"] is True


# --------------------------------------------- nullable protocol (§3, §8)
@needs_node
def test_unattributed_findings_remain_reachable(tmp_path):
    findings = _vm_findings(_anomaly_assessment())
    anomaly = [f for f in findings if f["fact_kind"] == "ANOMALY_SIGNAL"][0]
    assert anomaly["protocol"] is None
    assert anomaly["protocol_key"] == vocab.PROTOCOL_UNATTRIBUTED

    result = run_filter(findings, {"protocol": [vocab.PROTOCOL_UNATTRIBUTED]},
                        tmp_path)
    assert result["visible"] == [anomaly["rank"]]


@needs_node
def test_protocol_facet_partitions_every_finding(tmp_path):
    """No finding may be unreachable through the protocol facet."""
    findings = _vm_findings(_anomaly_assessment())
    keys = {f["protocol_key"] for f in findings}
    reached = []
    for key in keys:
        reached.extend(run_filter(findings, {"protocol": [key]}, tmp_path)["visible"])
    assert sorted(reached) == sorted(f["rank"] for f in findings)


@needs_node
def test_filtering_a_named_protocol_does_not_hide_anomalies_silently(tmp_path):
    """Selecting smtp legitimately excludes the anomaly — but it stays reachable."""
    findings = _vm_findings(_anomaly_assessment())
    smtp = run_filter(findings, {"protocol": ["smtp"]}, tmp_path)
    anomaly_rank = [f["rank"] for f in findings
                    if f["fact_kind"] == "ANOMALY_SIGNAL"][0]
    assert anomaly_rank not in smtp["visible"]
    unattributed = run_filter(
        findings, {"protocol": [vocab.PROTOCOL_UNATTRIBUTED]}, tmp_path)
    assert anomaly_rank in unattributed["visible"]


def test_anomaly_is_never_labelled_an_attack():
    vm = project(_anomaly_assessment()).to_dict()
    anomaly = [f for f in vm["findings"] if f["fact_kind"] == "ANOMALY_SIGNAL"][0]
    assert anomaly["fact_kind_label"] == "Anomaly signal"
    blob = json.dumps(anomaly).lower()
    for forbidden in ("attack", "intrusion", "malicious", "attacker", "compromise"):
        assert forbidden not in blob


# ------------------------------------------------- unknown values (§4)
@needs_node
def test_unknown_enum_values_are_filterable_not_hidden(tmp_path):
    a = base_assessment()
    a["prioritised"][0]["representative_finding"]["severity"] = "APOCALYPTIC"
    findings = _vm_findings(a)
    assert findings[0]["severity"] == "APOCALYPTIC"

    # visible with no filters
    assert findings[0]["rank"] in run_filter(findings, {}, tmp_path)["visible"]
    # and selectable by its own value
    result = run_filter(findings, {"severity": ["APOCALYPTIC"]}, tmp_path)
    assert result["visible"] == [findings[0]["rank"]]
    # a known severity does not sweep it up
    assert findings[0]["rank"] not in run_filter(
        findings, {"severity": ["MEDIUM"]}, tmp_path)["visible"]


def test_unknown_severity_is_flagged_in_the_summary_line():
    source = _source(FINDINGS_JS)
    assert "severity not recognised by this console" in source
    assert "row.severity_known" in source


# --------------------------------------------------------- facet counts (§6)
def test_facet_counts_come_from_the_projection():
    vm = project(_anomaly_assessment()).to_dict()
    for facet in ("severity", "status", "certainty", "observability", "fact_kind",
                  "dimension", "issue_class", "protocol"):
        for option in vm["filters"][facet]:
            field = "protocol_key" if facet == "protocol" else facet
            expected = sum(1 for f in vm["findings"]
                           if str(f[field]) == option["value"])
            assert option["count"] == expected, (facet, option["value"])


def test_findings_view_does_not_recount_facets():
    source = _source(FINDINGS_JS)
    assert "option.count" in source            # uses the projection's number
    assert "counts[" not in source             # does not build its own


# ---------------------------------------------- severity / data preservation
@needs_node
def test_filtering_changes_no_finding_data(tmp_path):
    findings = _vm_findings(critical_assessment())
    before = json.dumps(findings, sort_keys=True)
    run_filter(findings, {"severity": ["CRITICAL"]}, tmp_path)
    assert json.dumps(findings, sort_keys=True) == before


def test_severity_is_copied_not_derived():
    a = critical_assessment()
    vm = project(a).to_dict()
    assert vm["findings"][0]["severity"] == \
        a["prioritised"][0]["representative_finding"]["severity"]
    # severity survives low certainty untouched
    assert vm["findings"][0]["certainty"] == "UNCERTAIN"
    assert vm["findings"][0]["severity"] == "CRITICAL"


def test_evidence_states_stay_distinct_in_the_row():
    a = base_assessment()
    f = a["prioritised"][0]["representative_finding"]
    f["status"] = "AMBIGUOUS"
    f["observability"] = "NOT_OBSERVABLE"
    f["certainty"] = "UNDETERMINED"
    f["severity"] = "INFO"
    row = project(a).to_dict()["findings"][0]
    assert row["status_label"] == "AMBIGUOUS"
    assert row["observability_label"] == "NOT OBSERVABLE"
    assert row["certainty_label"] == "UNDETERMINED"
    assert len({row["status_label"], row["observability_label"],
                row["certainty_label"]}) == 3


# ------------------------------------------------------------- rendering
def test_required_fields_reach_the_detail_view():
    """Each field the milestone requires must be rendered where available."""
    source = _source(FINDINGS_JS)
    for field in ("row.rank", "row.issue_class_label", "row.severity_label",
                  "row.status_label", "row.certainty_label",
                  "row.observability_label", "row.fact_kind_label",
                  "row.dimension_label", "row.protocol_label",
                  "row.affected_sessions", "row.frames_text",
                  "row.source_rule_ids", "row.citations", "row.remediation",
                  "row.conclusion", "row.explanation"):
        assert field in source, field


def test_remediation_is_rendered_not_rewritten():
    source = _source(FINDINGS_JS)
    for field in ("r.observed", "r.why_it_matters", "r.recommended_action",
                  "r.affected_scope", "r.verification"):
        assert field in source, field
    assert "does not verify that remediation was" in source.replace("'\n      + '", "")


def test_empty_and_no_match_states_are_distinct():
    source = _source(FINDINGS_JS)
    assert "No findings match these filters" in source
    assert "No findings" in source
    assert "not a statement that the infrastructure is secure" in \
        source.replace("'\n            + '", "")
    assert "Clear all filters" in source


def test_result_count_is_announced():
    source = _source(FINDINGS_JS)
    assert "'aria-live': 'polite'" in source
    assert "role: 'status'" in source


# ----------------------------------------------------------- hostile content
@needs_node
def test_hostile_values_filter_without_breaking(tmp_path):
    a = hostile_assessment()
    a["prioritised"][0]["representative_finding"]["severity"] = '"><script>x</script>'
    a["prioritised"][0]["representative_finding"]["session"]["protocol"] = \
        "../../etc/passwd"
    findings = _vm_findings(a)
    result = run_filter(findings, {"severity": ['"><script>x</script>']}, tmp_path)
    assert result["visible"] == [findings[0]["rank"]]
    assert result["input_unchanged"] is True


def test_hostile_values_never_reach_a_class_or_id():
    a = hostile_assessment()
    a["prioritised"][0]["representative_finding"]["severity"] = '"><img src=x>'
    row = project(a).to_dict()["findings"][0]
    assert re.match(r"^[a-z_]+$", row["severity_tone"])
    # the checkbox id is sanitised in the view
    source = _source(FINDINGS_JS)
    assert "replace(/[^A-Za-z0-9_-]/g, '_')" in source


def test_hostile_strings_survive_as_data():
    vm = project(hostile_assessment()).to_dict()
    assert vm["issue_groups"][0]["title"].startswith("<script>")
    assert vm["findings"][0]["conclusion"].startswith("<script>")


# ---------------------------------------------------- edge cases / real data
def test_empty_assessment_has_no_findings_and_no_facets():
    vm = project(empty_assessment()).to_dict()
    assert vm["findings"] == []
    for facet in vm["filters"].values():
        assert facet == []


def test_long_text_is_carried_whole():
    a = base_assessment()
    long_text = "word " * 800
    a["prioritised"][0]["representative_finding"]["conclusion"] = long_text
    row = project(a).to_dict()["findings"][0]
    assert row["conclusion"] == long_text


def test_missing_optional_fields_do_not_break_the_row():
    a = base_assessment()
    f = a["prioritised"][0]["representative_finding"]
    for key in ("conclusion", "explanation", "remediation", "citations",
                "contradictions", "limitations"):
        f.pop(key, None)
    row = project(a).to_dict()["findings"][0]
    assert row["conclusion"] == "" and row["remediation"] is None
    assert row["citations"] == [] and row["contradictions"] == []


@needs_real
@needs_node
def test_real_assessment_filters_correctly(tmp_path):
    """Exercised against a real Postfix capture, not only fixtures."""
    svc = AnalysisService(str(tmp_path / "data"))
    run = svc.submit_path(STARTTLS, ai_enabled=True).run
    client = TestClient(create_app(service=svc), raise_server_exceptions=False)
    vm = client.get("/api/v1/analyses/%s/dashboard" % run.run_id).json()

    findings = vm["findings"]
    assert findings, "real capture should yield prioritised findings"

    canonical = [f["rank"] for f in findings]
    assert run_filter(findings, {}, tmp_path)["visible"] == canonical

    # every protocol option reaches its rows, including unattributed ones
    total = 0
    for option in vm["filters"]["protocol"]:
        got = run_filter(findings, {"protocol": [option["value"]]}, tmp_path)
        assert len(got["visible"]) == option["count"], option["value"]
        total += len(got["visible"])
    assert total == len(findings)

    # and clearing restores the canonical order
    assert run_filter(findings, {}, tmp_path)["visible"] == canonical
