"""
Phase-11 Milestone 12: the new evidence against real and generated captures.

Two things are proved here, and the first matters more than the second.

1. **Phase 11 changed no existing verdict.** All ten real OQ-33r captures score exactly
   what they scored at `v0.5.0-phase10`. Adding key-exchange, forward-secrecy and
   certificate evidence must enrich the assessment, not silently re-rate traffic that
   was already assessed. Measured against the tag before these numbers were written
   down, so the baseline is observed, not asserted.

2. **The new rules fire correctly where evidence exists.** The real corpus is 100 %
   TLS 1.3 and therefore cannot exercise the certificate family at all, so three TLS 1.2
   captures were generated for the purpose. That limitation is stated rather than hidden.
"""
import glob
import os
import tempfile

import pytest

from securemailscope.dissect import TsharkAdapter

REAL_DIR = "research/experiments/oq33r/out"
SYNTH_DIR = "research/experiments/p11cert/out"


def _tshark_available():
    try:
        TsharkAdapter().version()
        return True
    except Exception:                            # pragma: no cover - environment
        return False


needs_tshark = pytest.mark.skipif(not _tshark_available(), reason="tshark unavailable")
needs_backend = pytest.mark.skipif(
    not os.path.isdir(REAL_DIR), reason="research corpus not present")

#: Scores measured at v0.5.0-phase10, BEFORE the Phase-11 rules existed.
#: Any movement here means Phase 11 re-rated traffic it was only meant to enrich.
PHASE_10_BASELINE = {
    "dovecot_imap_imaps_implicit_tls.pcap": ("STRONG", 100.0),
    "dovecot_imap_plaintext_login.pcap": ("WEAK", 60.0),
    "dovecot_imap_starttls_upgrade.pcap": ("ADEQUATE", 88.0),
    "dovecot_pop3_plaintext_login.pcap": ("WEAK", 60.0),
    "dovecot_pop3_pop3s_implicit_tls.pcap": ("STRONG", 100.0),
    "dovecot_pop3_stls_upgrade.pcap": ("STRONG", 100.0),
    "postfix_smtp_client_declines.pcap": ("ADEQUATE", 88.0),
    "postfix_smtp_no_starttls_offered.pcap": ("ADEQUATE", 85.0),
    "postfix_smtp_plaintext_session.pcap": ("ADEQUATE", 88.0),
    "postfix_smtp_starttls_upgrade.pcap": ("ADEQUATE", 88.0),
}


@pytest.fixture(scope="module")
def service():
    pytest.importorskip("fastapi", reason="backend extra not installed")
    from securemailscope.backend.service import AnalysisService
    with tempfile.TemporaryDirectory() as tmp:
        svc = AnalysisService(os.path.join(tmp, "data"))
        yield svc
        svc.close()


def assess(service, path):
    return service.get_assessment(service.submit_path(path).run.run_id)


# ================================================= 1. no existing verdict moved
@needs_tshark
@needs_backend
@pytest.mark.parametrize("name", sorted(PHASE_10_BASELINE))
def test_real_capture_scores_are_unchanged_from_phase_10(service, name, request):
    """THE regression property for this phase.

    New evidence must not re-rate previously assessed traffic. If this fails, either a
    new rule is emitting OBSERVED_ISSUE where it should abstain, or an issue class is
    colliding with an existing one and inflating recurrence damping.
    """
    expected_band, expected_score = PHASE_10_BASELINE[name]
    a = assess(service, os.path.join(REAL_DIR, name))
    assert a["overall_posture"] == expected_band, name
    assert (a["score"] or {}).get("value") == expected_score, name


@needs_tshark
@needs_backend
def test_new_rules_add_no_penalising_findings_on_real_traffic(service):
    """The corollary: on this corpus every new finding is INFO or COMPLIANT.

    Not because the rules are toothless -- the generated captures below show them
    firing -- but because modern Postfix and Dovecot are correctly configured, which is
    itself a result worth stating.
    """
    new_prefixes = ("CERTIFICATE", "KEY_EXCHANGE", "FORWARD_SECRECY",
                    "INSECURE_CONFIGURATION")
    for name in sorted(PHASE_10_BASELINE):
        a = assess(service, os.path.join(REAL_DIR, name))
        for group in a["issue_groups"]:
            if group["issue_class"].startswith(new_prefixes):
                assert group["severity"] == "INFO", (name, group["issue_class"])


@needs_tshark
@needs_backend
def test_real_corpus_cannot_exercise_the_certificate_family(service):
    """A stated limitation, asserted so it cannot quietly stop being true.

    Every real capture negotiates TLS 1.3, where RFC 8446 SS2 encrypts the Certificate
    message. If a real capture ever does yield a certificate, this test fails and the
    traceability entry's limitation needs revisiting -- which is the point.
    """
    for name in sorted(PHASE_10_BASELINE):
        a = assess(service, os.path.join(REAL_DIR, name))
        classes = {g["issue_class"] for g in a["issue_groups"]}
        assert "CERTIFICATE_KEY_STRENGTH" not in classes, name
        assert "CERTIFICATE_VALIDITY" not in classes, name


# ====================================== 2. the new rules fire where evidence exists
SYNTHETIC = {
    "smtps_tls12_chain_rsa2048.pcap": ("STRONG", 100.0),
    "smtps_tls12_selfsigned_rsa2048.pcap": ("ADEQUATE", 88.0),
    "smtps_tls12_weak_sha1_rsa1024.pcap": ("CRITICAL", 44.0),
}


def _synthetic_present():
    return all(os.path.isfile(os.path.join(SYNTH_DIR, n)) for n in SYNTHETIC)


needs_synthetic = pytest.mark.skipif(
    not _synthetic_present(), reason="Phase-11 TLS 1.2 fixtures not present")


@needs_tshark
@needs_synthetic
@pytest.mark.parametrize("name", sorted(SYNTHETIC))
def test_generated_tls12_captures_score_as_measured(service, name):
    expected_band, expected_score = SYNTHETIC[name]
    a = assess(service, os.path.join(SYNTH_DIR, name))
    assert a["overall_posture"] == expected_band, name
    assert (a["score"] or {}).get("value") == expected_score, name


@needs_tshark
@needs_synthetic
def test_weak_certificate_produces_both_expected_issues(service):
    """RSA-1024 and SHA-1 are independent conditions and must both be reported."""
    a = assess(service, os.path.join(SYNTH_DIR, "smtps_tls12_weak_sha1_rsa1024.pcap"))
    failing = {g["issue_class"] for g in a["issue_groups"]
               if g["severity"] in ("HIGH", "CRITICAL")}
    assert failing == {"CERTIFICATE_KEY_STRENGTH", "CERTIFICATE_SIGNATURE_ALGORITHM"}


@needs_tshark
@needs_synthetic
def test_self_signed_certificate_is_the_only_issue_in_that_capture(service):
    a = assess(service, os.path.join(SYNTH_DIR, "smtps_tls12_selfsigned_rsa2048.pcap"))
    failing = {g["issue_class"] for g in a["issue_groups"]
               if g["severity"] not in ("INFO",)}
    assert failing == {"CERTIFICATE_CHAIN_STRUCTURE"}


@needs_tshark
@needs_synthetic
def test_healthy_chain_produces_no_issues(service):
    """The negative control: a well-configured TLS 1.2 server must score clean.

    Without this, the certificate rules could pass every other test by flagging
    everything.
    """
    a = assess(service, os.path.join(SYNTH_DIR, "smtps_tls12_chain_rsa2048.pcap"))
    for group in a["issue_groups"]:
        assert group["severity"] == "INFO", group["issue_class"]


@needs_tshark
@needs_synthetic
def test_certificate_evidence_is_marked_observed_provenance():
    """Phase 11 emits only `observed`. A retrieved or decrypted certificate would be a
    different forensic claim (docs/research/01A SS4.1), and no code path may produce one.

    Asserted at the FINDING layer, which is where the guarantee actually lives. The
    posture document summarises findings into issue groups and does not carry
    `evidence_refs`, so a search of the assessment would prove nothing either way --
    a limitation worth knowing rather than papering over with a weaker assertion.

    Checked on the provenance FIELD, not by searching text for the word: "retrieved"
    appears legitimately in the RFC 6960 citation ("OCSP status is retrieved in a
    separate network transaction"), which is the engine explaining why it does NOT do
    that. A blunt search flags the explanation as the offence.
    """
    from securemailscope.analysis import SecurityAnalysisEngine
    from securemailscope.config import Config
    from securemailscope.ingest import analyze_capture
    from securemailscope.session import reconstruct_sessions

    run, frames = analyze_capture(
        os.path.join(SYNTH_DIR, "smtps_tls12_chain_rsa2048.pcap"), Config())
    sessions = reconstruct_sessions(frames, run.capture.capture_id)
    report = SecurityAnalysisEngine().analyse(sessions)

    seen = {r.provenance for f in report.findings for r in f.evidence_refs}
    assert seen, "no provenance recorded on any evidence reference"
    assert seen <= {"observed", "none"}, seen

    # the certificate finding specifically must carry observed provenance
    cert_refs = [r for f in report.findings if f.rule_id == "SEC-CERT-001"
                 for r in f.evidence_refs if r.field_name == "tls_certificate_chain"]
    assert cert_refs
    assert any(r.provenance == "observed" for r in cert_refs)


# ======================================================= cross-surface agreement
@needs_tshark
@needs_synthetic
def test_reports_render_the_new_findings(service):
    """The report is a presentation of the assessment; it must not drop new content."""
    from securemailscope.reporting.service import render_bytes

    assessment = assess(
        service, os.path.join(SYNTH_DIR, "smtps_tls12_weak_sha1_rsa1024.pcap"))
    raw, _document = render_bytes(assessment, "html")
    body = raw.decode("utf-8").lower()
    for expected in ("key strength", "signature algorithm"):
        assert expected in body, expected
    # and the boundary travels with the findings rather than being dropped in
    # rendering. Asserted on the two concepts rather than one exact phrase, since
    # the renderer may wrap or truncate any individual limitation string.
    assert "trust" in body and "revocation" in body


@needs_tshark
@needs_synthetic
def test_dashboard_view_model_carries_the_new_findings(service):
    from securemailscope.dashboard import project

    a = assess(service, os.path.join(SYNTH_DIR, "smtps_tls12_weak_sha1_rsa1024.pcap"))
    blob = str(project(a)).lower()
    assert "key strength" in blob or "certificate_key_strength" in blob
    # no verdict-shaped label may claim a condition the session does not have
    assert "forward secrecy absent" not in blob


# ================================================================= performance
@needs_tshark
@needs_backend
def test_analysis_stays_within_the_phase_10_envelope(service):
    """Phase 11 adds a certificate parse; it must not change the cost profile.

    A generous bound: the point is to catch an accidental quadratic or a per-frame
    re-parse, not to benchmark the host.
    """
    import time
    path = os.path.join(REAL_DIR, "postfix_smtp_starttls_upgrade.pcap")
    assess(service, path)                        # warm caches
    start = time.time()
    assess(service, path)
    elapsed = time.time() - start
    assert elapsed < 5.0, elapsed
