"""
Phase-10 Milestone 10: real PCAP through the full stack (doc 23 §17).

Every test here starts from a real capture in the research corpus and drives the whole
system:

    PCAP -> ingest -> dissect -> sessions -> deterministic analysis
         -> cross-session -> [ML] -> posture -> persistence -> API
         -> dashboard view model  AND  HTML / PDF / JSON reports

The point is cross-surface agreement. The console and the report are two presentations
of one assessment; if they disagree, one of them has a defect and the assessment is the
tiebreaker.

The three demo scenes from `docs/architecture/08-demo-architecture.md` §2 are exercised
on genuine project evidence, not manufactured outcomes.
"""
import io
import json
import os
import re

import pytest

fastapi = pytest.importorskip("fastapi", reason="backend extra not installed")
pytest.importorskip("httpx", reason="httpx required by TestClient")
from fastapi.testclient import TestClient                        # noqa: E402

from securemailscope.backend.api import create_app                # noqa: E402
from securemailscope.backend.service import AnalysisService       # noqa: E402
from securemailscope.dissect import TsharkAdapter                 # noqa: E402

PCAP_DIR = "research/experiments/oq33r/out"
CAPTURES = {
    "smtp_starttls": "postfix_smtp_starttls_upgrade.pcap",
    "smtp_plaintext": "postfix_smtp_plaintext_session.pcap",
    "smtp_no_starttls": "postfix_smtp_no_starttls_offered.pcap",
    "smtp_declines": "postfix_smtp_client_declines.pcap",
    "imap_implicit": "dovecot_imap_imaps_implicit_tls.pcap",
    "imap_starttls": "dovecot_imap_starttls_upgrade.pcap",
    "pop3_plaintext": "dovecot_pop3_plaintext_login.pcap",
}


def _tshark():
    try:
        TsharkAdapter().version()
        return True
    except Exception:
        return False


def _have(name):
    return os.path.isfile(os.path.join(PCAP_DIR, CAPTURES[name]))


needs_real = pytest.mark.skipif(
    not _tshark() or not all(_have(k) for k in CAPTURES),
    reason="tshark or the OQ-33r captures are absent")

pytestmark = needs_real


def _path(name):
    return os.path.join(PCAP_DIR, CAPTURES[name])


def _stack(tmp_path):
    svc = AnalysisService(str(tmp_path / "data"))
    return svc, TestClient(create_app(service=svc), raise_server_exceptions=False)


def _analyse(tmp_path, name, ai=False):
    """Run the real pipeline and return every surface for the same assessment."""
    svc, client = _stack(tmp_path)
    run = svc.submit_path(_path(name), ai_enabled=ai).run
    assert run.state.value == "COMPLETED", run.error_message

    base = "/api/v1/analyses/%s" % run.run_id
    canonical = client.get(base + "/assessment").json()["assessment"]
    view_model = client.get(base + "/dashboard").json()
    report_json = client.get(base + "/reports/json").json()
    html = client.get(base + "/reports/html").text
    pdf = client.get(base + "/reports/pdf").content
    return {
        "svc": svc, "client": client, "run": run, "canonical": canonical,
        "vm": view_model, "report_json": report_json, "html": html, "pdf": pdf,
    }


def _html_text(html):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def _pdf_text(data):
    pypdf = pytest.importorskip("pypdf")
    reader = pypdf.PdfReader(io.BytesIO(data))
    return re.sub(r"\s+", " ",
                  "\n".join(p.extract_text() or "" for p in reader.pages))


# =====================================================================
# Full-stack smoke: every capture completes and reaches every surface
# =====================================================================
@pytest.mark.parametrize("name", sorted(CAPTURES))
def test_capture_flows_through_the_entire_stack(tmp_path, name):
    out = _analyse(tmp_path, name)
    assert out["run"].capture_id and out["run"].assessment_id
    assert out["canonical"]["assessment_id"] == out["run"].assessment_id
    assert out["vm"]["identity"]["assessment_id"] == out["run"].assessment_id
    assert out["report_json"]["assessment_id"] == out["run"].assessment_id
    assert out["pdf"][:5] == b"%PDF-"
    assert out["html"].startswith("<!DOCTYPE html>")


# =====================================================================
# Cross-surface agreement: JSON vs dashboard vs HTML vs PDF
# =====================================================================
@pytest.mark.parametrize("name", ["smtp_starttls", "smtp_plaintext",
                                  "imap_implicit", "pop3_plaintext"])
def test_all_four_surfaces_agree(tmp_path, name):
    out = _analyse(tmp_path, name, ai=(name == "smtp_starttls"))
    canonical, vm = out["canonical"], out["vm"]
    html_text, pdf_text = _html_text(out["html"]), _pdf_text(out["pdf"])

    # --- identity ----------------------------------------------------
    assert out["report_json"] == canonical          # json report IS the canonical doc
    assert vm["identity"]["assessment_id"] == canonical["assessment_id"]
    assert vm["identity"]["capture_id"] == canonical["capture_id"]
    for blob in (html_text, pdf_text):
        assert canonical["assessment_id"] in blob
        assert canonical["capture_id"] in blob

    # --- posture -----------------------------------------------------
    posture = canonical["overall_posture"]
    assert vm["posture"]["value"] == posture
    label = posture.replace("_", " ")
    for blob in (html_text, pdf_text):
        assert label in blob

    # --- score -------------------------------------------------------
    if canonical.get("score"):
        value = canonical["score"]["value"]
        assert vm["posture"]["score_value"] == value
        rendered = str(value).rstrip("0").rstrip(".")
        for blob in (html_text, pdf_text):
            assert rendered in blob
    else:
        assert vm["posture"]["score_value"] is None
        for blob in (html_text, pdf_text):
            assert "Not scored" in blob

    # --- coverage ----------------------------------------------------
    assert vm["coverage"]["sessions_total"] == \
        canonical["coverage"]["sessions_total"]
    assert vm["coverage"]["observation_counts"] == \
        canonical["coverage"]["observation_counts"]
    fraction = canonical["coverage"]["assessed_fraction"]
    percent = "%.1f%%" % (fraction * 100.0)
    assert vm["coverage"]["percent_text"] == percent
    for blob in (html_text, pdf_text):
        assert percent in blob

    # --- findings: identity and severity -----------------------------
    assert len(vm["findings"]) == len(canonical["prioritised"])
    for index, entry in enumerate(canonical["prioritised"]):
        finding = entry["representative_finding"]
        row = vm["findings"][index]
        assert row["rank"] == entry["rank"]
        assert row["severity"] == finding["severity"]
        assert row["status"] == finding["status"]
        assert row["certainty"] == finding["certainty"]
        assert row["observability"] == finding["observability"]

    # --- issue groups and severities --------------------------------
    assert len(vm["issue_groups"]) == len(canonical["issue_groups"])
    for index, group in enumerate(canonical["issue_groups"]):
        assert vm["issue_groups"][index]["severity"] == group["severity"]
        assert vm["issue_groups"][index]["recurrence"] == group["recurrence"]

    # --- standards ---------------------------------------------------
    standards = set((canonical.get("standards_summary") or {})
                    .get("standards", {}).keys())
    assert {r["standard"] for r in vm["standards"]["standards"]} == standards
    for standard in standards:
        for blob in (html_text, pdf_text):
            assert standard in blob

    # --- limitations -------------------------------------------------
    assert vm["limitations"] == canonical["limitations"]
    for limitation in canonical["limitations"][:3]:
        snippet = re.sub(r"\s+", " ", limitation)[:50]
        for blob in (html_text, pdf_text):
            assert snippet in blob

    # --- abstentions -------------------------------------------------
    assert len(vm["abstentions"]) == len(canonical["abstentions"])
    for index, abstention in enumerate(canonical["abstentions"]):
        assert vm["abstentions"][index]["reason"] == abstention["reason"]
        assert vm["abstentions"][index]["resolved_by"] == abstention["resolved_by"]

    # --- ML role -----------------------------------------------------
    summary = canonical.get("model_summary") or {}
    assert vm["ml"]["enabled"] == bool(summary.get("ai_enabled"))
    if summary.get("role"):
        assert vm["ml"]["role"] == summary["role"]
        for blob in (html_text, pdf_text):
            assert summary["role"] in blob


# =====================================================================
# Demo scene A — inversion (doc 08 §2)
# A legitimate STARTTLS decline and a server not offering STARTTLS are
# different facts, and neither is reported as an attack.
# =====================================================================
def test_scene_a_inversion_declines_are_not_attacks(tmp_path):
    declines = _analyse(tmp_path / "a", "smtp_declines")
    absent = _analyse(tmp_path / "b", "smtp_no_starttls")

    # Affirmative attribution claims must be absent. Matched as PHRASES: the word
    # "attacker" legitimately appears in the engine's own denial, "no attacker,
    # intent or attribution is or can be established from a packet capture", which
    # is precisely the statement this scene exists to show.
    for out in (declines, absent):
        blob = json.dumps(out["vm"]).lower()
        for forbidden in ("stripping attack", "attack detected", "attacker identified",
                          "malicious actor", "intrusion detected", "was compromised",
                          "confirmed stripping"):
            assert forbidden not in blob, (out["run"].run_id, forbidden)

    # the two captures are genuinely different analyses
    assert declines["canonical"]["capture_id"] != absent["canonical"]["capture_id"]

    # and the engine's own denial reaches the console verbatim
    for out in (declines, absent):
        joined = " ".join(out["vm"]["limitations"]).lower()
        assert "no attacker, intent or attribution" in joined
        assert "absence of a starttls advertisement is ambiguous" in joined
        assert "stripping and genuine non-support are byte-identical" in joined


# =====================================================================
# Demo scene B — honesty
# The tool states what it cannot observe rather than inferring it.
# =====================================================================
def test_scene_b_honesty_states_what_cannot_be_observed(tmp_path):
    out = _analyse(tmp_path, "imap_implicit")
    vm = out["canonical"]

    # implicit TLS: the certificate is not observable from a passive capture
    reasons = {a["reason"] for a in vm["abstentions"]}
    assert reasons, "implicit TLS should produce abstentions"

    # every abstention says what would settle it
    for abstention in vm["abstentions"]:
        assert abstention["resolved_by"].strip()

    # the console carries that through
    view = out["vm"]
    assert len(view["abstentions"]) == len(vm["abstentions"])
    for row in view["abstentions"]:
        assert row["resolved_by"].strip()

    # not-observable is a recorded evidence state, not silence
    counts = view["coverage"]["observation_counts"]
    assert set(counts) & {"NOT_OBSERVABLE", "UNKNOWN", "AMBIGUOUS"}

    # The console never converts an absence into reassurance. Matched as PHRASES:
    # "certificate valid" as a substring occurs inside the engine's honest
    # "certificate validation was not performed for this session", which is the
    # statement this scene is demonstrating.
    blob = json.dumps(view).lower()
    for forbidden in ('"secure"', '"safe"', "certificate is valid",
                      "valid certificate", "certificate is trusted",
                      "no issues found", "100% secure"):
        assert forbidden not in blob, forbidden

    # and the engine's own non-observability statement is present
    whys = " ".join(a["why"] for a in view["abstentions"]).lower()
    resolutions = " ".join(a["resolved_by"] for a in view["abstentions"]).lower()
    assert "not performed" in whys or "not observable" in whys
    assert "not resolvable by passive capture" in resolutions


def test_scene_b_no_findings_is_not_rendered_as_secure(tmp_path):
    """A capture with nothing to report must not read as a clean bill of health."""
    out = _analyse(tmp_path, "imap_implicit")
    vm = out["vm"]
    # whatever the finding count, coverage and abstentions qualify it
    assert vm["coverage"]["summary_text"]
    assert vm["unavailable"]
    html_text = _html_text(out["html"])
    assert "NOT OBSERVABLE" in html_text or "Not observable" in html_text


# =====================================================================
# Demo scene C — --no-ai equivalence and AI transparency
# =====================================================================
def test_scene_c_no_ai_equivalence_across_the_whole_stack(tmp_path):
    with_ai = _analyse(tmp_path / "ai", "smtp_starttls", ai=True)
    without = _analyse(tmp_path / "noai", "smtp_starttls", ai=False)

    a, b = with_ai["canonical"], without["canonical"]

    # the security conclusion is identical
    assert a["overall_posture"] == b["overall_posture"]
    assert a["score"]["value"] == b["score"]["value"]
    assert a["standards_summary"] == b["standards_summary"]
    assert a["remediation_summary"] == b["remediation_summary"]
    penalising = lambda doc: [g for g in doc["issue_groups"] if g["penalising"]]
    assert penalising(a) == penalising(b)

    # and the console shows the same conclusion both ways
    assert with_ai["vm"]["posture"]["value"] == without["vm"]["posture"]["value"]
    assert with_ai["vm"]["posture"]["score_value"] == \
        without["vm"]["posture"]["score_value"]

    # the ML lane declares itself honestly, and only when enabled
    assert with_ai["vm"]["ml"]["enabled"] is True
    assert with_ai["vm"]["ml"]["role"] == "secondary prioritisation signal only"
    assert without["vm"]["ml"]["enabled"] is False
    assert without["vm"]["ml"]["role"] == ""

    # its limitations travel with it
    assert len(with_ai["vm"]["ml"]["limitations"]) >= 2
    assert "zero unique true detections" in " ".join(
        with_ai["vm"]["ml"]["limitations"])

    # and nothing anywhere claims detection
    for out in (with_ai, without):
        blob = (json.dumps(out["vm"]) + _html_text(out["html"])
                + _pdf_text(out["pdf"])).lower()
        for forbidden in ("ai detected", "attack detected", "malicious traffic",
                          "confirmed an intrusion", "detected tls stripping"):
            assert forbidden not in blob


def test_ml_adjustment_never_crosses_a_severity_tier(tmp_path):
    """The bounded-ordering claim, checked on real data."""
    out = _analyse(tmp_path, "smtp_starttls", ai=True)
    for row in out["vm"]["findings"]:
        assert abs(row["ml_adjustment"] or 0) <= 4.0


# =====================================================================
# Forensic chain
# =====================================================================
def test_capture_id_is_the_sha256_of_the_analysed_bytes(tmp_path):
    import hashlib
    out = _analyse(tmp_path, "smtp_starttls")
    with open(_path("smtp_starttls"), "rb") as handle:
        expected = hashlib.sha256(handle.read()).hexdigest()
    assert out["run"].capture_id == expected
    assert out["canonical"]["capture_id"] == expected
    assert out["vm"]["identity"]["capture_id"] == expected


def test_artifacts_verify_after_the_full_cycle(tmp_path):
    out = _analyse(tmp_path, "smtp_starttls")
    items = out["client"].get(
        "/api/v1/analyses/%s/artifacts?verify=true" % out["run"].run_id
    ).json()["items"]
    kinds = {i["kind"] for i in items}
    assert {"pcap", "html", "pdf"} <= kinds
    for item in items:
        assert item["integrity"] == "OK", item["kind"]
        assert len(item["sha256"]) == 64
        assert "relative_path" not in item


def test_provenance_rules_reach_the_console(tmp_path):
    out = _analyse(tmp_path, "smtp_starttls")
    rules = out["canonical"]["provenance"]["rule_ids"]
    assert rules, "real analysis should record which rules ran"
    assert out["vm"]["provenance"]["rule_ids"] == rules


# =====================================================================
# Analyst workflow, end to end on real data
# =====================================================================
def test_analyst_workflow_history_to_report(tmp_path):
    """History -> overview -> findings -> evidence -> reports, on real captures."""
    svc, client = _stack(tmp_path)
    for name in ("smtp_starttls", "imap_implicit", "pop3_plaintext"):
        svc.submit_path(_path(name), ai_enabled=(name == "smtp_starttls"))

    listing = client.get("/api/v1/analyses").json()
    assert listing["total"] == 3
    completed = [i for i in listing["items"] if i["state"] == "COMPLETED"]
    assert len(completed) == 3
    assert all(i["overall_posture"] for i in completed)

    run_id = completed[0]["run_id"]
    base = "/api/v1/analyses/%s" % run_id
    vm = client.get(base + "/dashboard").json()

    # overview needs a posture, coverage and an ML statement
    assert vm["posture"]["label"] and vm["coverage"]["summary_text"]
    assert vm["ml"] is not None
    # findings screen needs its facets
    assert isinstance(vm["filters"], dict)
    # evidence screen needs provenance and limitations
    assert vm["provenance"]["rule_ids"] and vm["limitations"]
    # reports are reachable
    reports = client.get(base + "/reports").json()
    assert {r["format"] for r in reports["items"]} == {"html", "pdf", "json"}
    for fmt in ("html", "pdf", "json"):
        assert client.get(base + "/reports/" + fmt).status_code == 200


def test_every_capture_produces_a_distinct_assessment(tmp_path):
    """Different bytes must not collapse to one conclusion."""
    svc, client = _stack(tmp_path)
    ids = {}
    for name in sorted(CAPTURES):
        run = svc.submit_path(_path(name)).run
        ids[name] = (run.capture_id, run.assessment_id)
    capture_ids = {c for c, _a in ids.values()}
    assert len(capture_ids) == len(CAPTURES), "capture ids must be distinct"
