"""
Phase-10 tests: History and analysis lifecycle (doc 23 §7 Screen 1, §9).

The lifecycle vocabulary is verified against the Phase-8 enum rather than assumed, so
a future state added to the backend without updating the console is caught here rather
than rendering as a blank cell.
"""
import os
import re

import pytest

fastapi = pytest.importorskip("fastapi", reason="backend extra not installed")
pytest.importorskip("httpx", reason="httpx required by TestClient")
from fastapi.testclient import TestClient                        # noqa: E402

from securemailscope.backend.api import create_app                # noqa: E402
from securemailscope.backend.lifecycle import (                   # noqa: E402
    INTERRUPTIBLE, TERMINAL, JobState,
)
from securemailscope.backend.repository import RunRecord          # noqa: E402
from securemailscope.backend.service import AnalysisService       # noqa: E402
from tests.reporting_fixtures import (                            # noqa: E402
    base_assessment, insufficient_evidence,
)

HISTORY_JS = "src/securemailscope/dashboard/static/views/history.js"
APP_JS = "src/securemailscope/dashboard/static/app.js"


def _source(path=HISTORY_JS):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _prose(path=HISTORY_JS):
    joined = re.sub(r"'\s*\+\s*'", "", _source(path))
    return joined.replace("\\'", "'")


def _code(path=HISTORY_JS):
    """Source with comments removed.

    Several of these assertions forbid a word appearing in the CODE. Comments
    legitimately name the very things they forbid — a docstring saying "no completion
    fraction is invented" must not fail a test looking for invented fractions — so
    comments are stripped before searching.
    """
    source = _source(path)
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"^\s*//.*$", "", source, flags=re.M)


def _client(svc):
    return TestClient(create_app(service=svc), raise_server_exceptions=False)


def _completed(svc, assessment=None, filename="capture.pcap"):
    assessment = assessment or base_assessment()
    run = svc.repo.create_run(RunRecord.new(source_filename=filename))
    svc.repo.store_assessment(assessment)
    for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING,
                   JobState.FINALIZING):
        svc.repo.transition(run, target, capture_id=assessment["capture_id"])
    svc.repo.transition(run, JobState.COMPLETED,
                        assessment_id=assessment["assessment_id"])
    return run


# ------------------------------------------------- lifecycle vocabulary
def test_console_knows_every_backend_state():
    """Verified against the actual enum, not against an assumed list."""
    source = _source()
    for state in JobState:
        assert re.search(r"\b%s:\s*\{" % state.value, source), state.value


def test_console_invents_no_state_the_backend_lacks():
    source = _source()
    declared = set(re.findall(r"^  ([A-Z_]+): \{", source, re.M))
    assert declared == {s.value for s in JobState}, declared ^ {s.value for s in JobState}


def test_every_backend_terminal_state_is_settled():
    """`settled` is a POLLING question and is deliberately wider than the backend's
    TERMINAL set: RECOVERY_REQUIRED is an audited intermediate the startup sweep moves
    straight to FAILED (ADR-0018), so re-asking about it gains nothing. Both
    directions are asserted so the two notions cannot quietly merge."""
    source = _source()

    def settled(state_name):
        block = re.search(r"\b%s: \{(.*?)\}," % state_name, source, re.S).group(1)
        return "settled: true" in block

    for state in TERMINAL:
        assert settled(state.value), "%s is backend-terminal but not settled" % state.value
    # RECOVERY_REQUIRED is the one documented exception
    assert settled("RECOVERY_REQUIRED")
    assert JobState.RECOVERY_REQUIRED not in TERMINAL
    unsettled = {s.value for s in JobState if not settled(s.value)}
    assert unsettled == {s.value for s in INTERRUPTIBLE}, unsettled


def test_unsettled_set_is_derived_not_duplicated():
    """The polling set must come from the table so the two cannot drift apart."""
    source = _source()
    assert "Object.keys(STATES).filter((k) => !STATES[k].settled)" in source


def test_unknown_future_state_renders_as_itself():
    prose = _prose()
    assert "shown as itself, never mapped onto a known one" in prose
    assert "a lifecycle state this console version does not recognise" in prose


def test_interruptible_states_are_unsettled_in_the_console():
    """A state the backend can sweep must not be shown as finished."""
    source = _source()
    for state in INTERRUPTIBLE:
        block = re.search(r"\b%s: \{(.*?)\}," % state.value, source, re.S).group(1)
        assert "settled: false" in block, state.value


# ------------------------------------------------------- no invented progress
def test_no_completion_fraction_is_invented():
    """The API exposes no progress fraction, so none may be displayed.

    The WORD "progress" is fine — the RUNNING state says "analysis in progress" and
    the status line counts runs in progress. What must not exist is a computed
    fraction, percentage or estimate, so that is what is asserted.
    """
    code = _code()
    for forbidden in ("percent", "Math.round(", "Math.floor(", "elapsed",
                      "estimate", "remaining", "toFixed("):
        assert forbidden.lower() not in code.lower(), forbidden
    # no arithmetic producing a ratio, and no percent sign in displayed copy
    assert not re.search(r"\w+\s*/\s*\w*(total|count|duration|expected)", code, re.I)
    assert "%" not in re.sub(r"%s", "", code)


def test_running_state_says_only_that_it_is_running():
    source = _source()
    block = re.search(r"\bRUNNING: \{(.*?)\},", source, re.S).group(1)
    assert "analysis in progress" in block
    assert "%" not in block


# --------------------------------------------------------- posture discipline
def test_run_without_assessment_shows_no_posture(tmp_path):
    svc = AnalysisService(str(tmp_path / "d"))
    run = svc.repo.create_run(RunRecord.new(source_filename="fail.pcap"))
    svc.repo.transition(run, JobState.VALIDATING)
    svc.repo.transition(run, JobState.FAILED, error_code="ANALYSIS_FAILED",
                        error_message="capture could not be analysed")
    item = _client(svc).get("/api/v1/analyses").json()["items"][0]
    assert item["state"] == "FAILED"
    assert item["overall_posture"] is None and item["score_value"] is None
    assert "no assessment" in _prose()


def test_completed_run_shows_stored_projection(tmp_path):
    svc = AnalysisService(str(tmp_path / "d"))
    run = _completed(svc)
    item = _client(svc).get("/api/v1/analyses").json()["items"][0]
    assert item["run_id"] == run.run_id
    assert item["overall_posture"] == "ADEQUATE"
    assert item["score_value"] == 88.0


def test_withheld_band_and_null_score_survive(tmp_path):
    svc = AnalysisService(str(tmp_path / "d"))
    _completed(svc, insufficient_evidence(), "thin.pcap")
    item = _client(svc).get("/api/v1/analyses").json()["items"][0]
    assert item["overall_posture"] == "INSUFFICIENT_EVIDENCE"
    assert item["score_value"] is None
    # and "not scored" is never rendered as a zero
    assert "not scored" in _prose()


def test_history_never_recomputes_a_security_value():
    source = _code()
    for pattern in (r"score\s*[<>]", r"severity", r"\.sort\(",
                    r"overall_posture\s*=\s*[^=]"):
        assert not re.search(pattern, source), pattern


# --------------------------------------------------------- safe failure display
def test_failure_shows_code_and_backend_message_only(tmp_path):
    svc = AnalysisService(str(tmp_path / "d"))
    run = svc.repo.create_run(RunRecord.new())
    svc.repo.transition(run, JobState.VALIDATING)
    svc.repo.transition(run, JobState.FAILED,
                        error_code="CAPTURE_VALIDATION_FAILED",
                        error_message="capture failed validation")
    item = _client(svc).get("/api/v1/analyses").json()["items"][0]
    assert item["error_code"] == "CAPTURE_VALIDATION_FAILED"
    assert "Traceback" not in (item["error_message"] or "")
    assert "/Users/" not in (item["error_message"] or "")

    code = _code()
    assert "item.error_code" in code and "item.error_message" in code
    # nothing else about the failure is synthesised
    for forbidden in ("stack", "traceback", "exception"):
        assert forbidden not in code.lower(), forbidden


def test_interrupted_run_is_shown_as_interrupted(tmp_path):
    """A crash-swept run must read as interrupted, not as a plain failure."""
    data = str(tmp_path / "d")
    svc = AnalysisService(data)
    run = svc.repo.create_run(RunRecord.new())
    for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING):
        svc.repo.transition(run, target)
    svc.close()

    reopened = AnalysisService(data)
    item = _client(reopened).get("/api/v1/analyses").json()["items"][0]
    assert item["state"] == "FAILED"
    assert item["error_code"] == "ANALYSIS_INTERRUPTED"
    # the console has a distinct vocabulary for the interrupted state itself
    assert "RECOVERY_REQUIRED" in _source()
    assert "the process stopped before the analysis finished" in _prose()


def test_no_recovery_controls_are_invented():
    """The API exposes no retry or resume action, so the console offers none."""
    code = _code()
    # Word-boundary matched: "POST" as a substring occurs inside "overall_posture".
    for forbidden in ("retry", "resume", "restart", "cancelRun", "POST", "DELETE",
                      "fetch"):
        assert not re.search(r"\b%s\b" % forbidden, code, re.I), forbidden


# ------------------------------------------------------------------- polling
def test_polling_is_bounded_and_stops_at_terminal_state():
    source = _source()
    assert "POLL_INTERVAL_MS = 4000" in source
    assert "POLL_MAX_TICKS" in source
    assert "pollTicks < POLL_MAX_TICKS" in source
    # polls only when something is actually in flight
    assert "if (active.length && pollTicks < POLL_MAX_TICKS)" in source
    assert "stopPolling()" in source


def test_polling_uses_a_single_chained_timer_not_an_interval():
    """setInterval could stack requests if one is slow; a chained timeout cannot."""
    source = _source()
    assert "setInterval" not in source
    assert "setTimeout" in source


def test_leaving_the_route_stops_polling():
    app = _source(APP_JS)
    assert "history.stopPolling()" in app
    assert "must not leave a timer behind" in app


def test_render_clears_any_previous_timer():
    source = _source()
    assert re.search(r"export async function render\([^)]*\)\s*\{\s*\n\s*stopPolling\(\);",
                     source)


# ----------------------------------------------------------------- navigation
def test_only_completed_runs_link_into_the_run(tmp_path):
    source = _source()
    assert "item.state === 'COMPLETED' && item.assessment_id" in source
    assert "href: `#/run/${item.run_id}`" in source


def test_history_uses_one_request_for_the_page(tmp_path):
    source = _source()
    assert source.count("listAnalyses(") == 1
    assert "getAssessment" not in source and "getDashboard" not in source


def test_empty_history_is_explained(tmp_path):
    svc = AnalysisService(str(tmp_path / "d"))
    body = _client(svc).get("/api/v1/analyses").json()
    assert body["total"] == 0
    prose = _prose()
    assert "No analyses yet" in prose
    assert "curl -F file=@capture.pcap" in prose


def test_multiple_runs_all_appear(tmp_path):
    svc = AnalysisService(str(tmp_path / "d"))
    for index in range(4):
        doc = base_assessment()
        doc["assessment_id"] = "aid%013d" % index
        doc["capture_id"] = ("%02d" % index) + "f" * 62
        _completed(svc, doc, "capture-%d.pcap" % index)
    body = _client(svc).get("/api/v1/analyses").json()
    assert body["total"] == 4
    assert len({i["run_id"] for i in body["items"]}) == 4


def test_history_does_not_build_a_global_analytics_view():
    """An analysis history, not a BI dashboard (doc 23 §7).

    Matched against code with comments stripped and on word boundaries: "mean"
    otherwise matches the word "means" in a docstring.
    """
    code = _code()
    for forbidden in ("average", "trend", "aggregate", "total_score", "mean",
                      "chart", "sparkline", "histogram"):
        assert not re.search(r"\b%s\b" % forbidden, code, re.I), forbidden


# ------------------------------------------------------------------- security
def test_history_view_obeys_the_dom_boundary():
    stripped = re.sub(r"/\*.*?\*/", "", _source(), flags=re.S)
    stripped = re.sub(r"^\s*//.*$", "", stripped, flags=re.M)
    for forbidden in (".innerHTML", ".outerHTML", ".insertAdjacentHTML",
                      "document.write", "eval(", "new Function("):
        assert forbidden not in stripped, forbidden


def test_history_builds_only_hash_routes_from_validated_ids():
    source = _source()
    hrefs = re.findall(r"href: ([^,}]+)", source)
    assert hrefs, "history should link somewhere"
    for href in hrefs:
        assert href.strip().startswith("`#/run/"), href


def test_hostile_filename_and_state_are_safe(tmp_path):
    payload = '<script>alert(1)</script>'
    svc = AnalysisService(str(tmp_path / "d"))
    run = svc.repo.create_run(RunRecord.new(source_filename=payload))
    svc.repo.transition(run, JobState.VALIDATING)
    svc.repo.transition(run, JobState.FAILED, error_code="ANALYSIS_FAILED",
                        error_message=payload)
    item = _client(svc).get("/api/v1/analyses").json()["items"][0]
    # carried as data
    assert item["source_filename"] == payload
    assert item["error_message"] == payload
    # and the view puts it only in text nodes
    source = _source()
    assert "text: label" in source
    assert "className: `" not in source


def test_state_tone_comes_from_a_fixed_vocabulary():
    source = _source()
    tones = set(re.findall(r"tone: '([a-z_]+)'", source))
    assert tones <= {"neutral", "completed", "failed", "cancelled", "unknown",
                     "strong", "adequate", "weak", "critical",
                     "insufficient_evidence"}
    # the unknown fallback is a literal, never derived from the API value
    assert "tone: 'unknown'" in source
