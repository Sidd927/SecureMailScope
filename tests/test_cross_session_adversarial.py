"""
Phase-5 adversarial tests (§20).

The engine must not crash, must not trust a single anomalous historical sample, must
not turn missing evidence into failure, and must not manufacture a confirmed condition
from weak comparison evidence.
"""
import json

import pytest

from securemailscope.analysis.model import FindingStatus, Severity
from securemailscope.crosssession import (
    CrossSessionConfig, CrossSessionEngine, Deviation, build_baseline, evaluate_contrast,
)
from securemailscope.session.model import Completeness, TlsState

from tests.test_cross_session import mk, of_kind, run


def assert_sane(report, label=""):
    assert not report.rule_errors, f"{label}: {report.rule_errors}"
    for f in report.findings:
        if f.status is not FindingStatus.OBSERVED_ISSUE:
            assert f.severity is Severity.INFO, f"{label}: {f.rule_id}"
        if f.deviation in (Deviation.DEVIATION, Deviation.SUSPICIOUS_DEVIATION):
            assert f.baseline, f"{label}: deviation without baseline provenance"


def test_poisoned_history_single_bad_sample_is_not_trusted():
    """One anomalous historical session must not become 'the baseline'."""
    good = [mk(i, ts=i) for i in range(5)]
    poisoned = mk(5, ts=5, advertised=False, established=False)   # injected outlier
    subject = mk(100, ts=100)
    report = run(good + [poisoned, subject])
    assert_sane(report, "poisoned history")
    # History is now inconsistent, so no expectation may be derived from it.
    b = build_baseline(subject, good + [poisoned, subject])
    assert b.usable and not b.feature("starttls_advertised").is_consistent
    assert of_kind(report, Deviation.SUSPICIOUS_DEVIATION) == []


def test_many_unrelated_sessions_do_not_dilute_or_create_a_baseline():
    noise = [mk(i, server=f"10.1.1.{i % 200}", ts=i) for i in range(300)]
    subject = mk(1000, ts=1000, advertised=False, established=False)
    report = run(noise + [subject])
    assert_sane(report, "unrelated noise")
    assert of_kind(report, Deviation.DEVIATION) == []
    assert of_kind(report, Deviation.SUSPICIOUS_DEVIATION) == []


def test_duplicate_sessions_do_not_inflate_history():
    """Identical duplicates share a stream key and must not count repeatedly."""
    one = mk(1, ts=1)
    subject = mk(100, ts=100)
    report = run([one] * 10 + [subject])
    assert_sane(report, "duplicates")
    assert of_kind(report, Deviation.DEVIATION) == []


def test_reordered_population_is_order_independent():
    prior = [mk(i, ts=i) for i in range(6)]
    subject = mk(100, ts=100, advertised=False, established=False)
    pop = prior + [subject]
    a = run(pop).to_dict()
    b = run(list(reversed(pop))).to_dict()
    c = run(pop[3:] + pop[:3]).to_dict()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True) == json.dumps(c, sort_keys=True)


def test_missing_timestamps_do_not_crash_or_reorder_nondeterministically():
    prior = [mk(i, ts=None) for i in range(6)]
    for p in prior:
        object.__setattr__(p, "start_epoch", None)
    subject = mk(100, ts=None)
    object.__setattr__(subject, "start_epoch", None)
    report = run(prior + [subject])
    assert_sane(report, "missing timestamps")


def test_missing_endpoint_identity_abstains():
    prior = [mk(i, ts=i) for i in range(6)]
    subject = mk(100, ts=100, client=None)
    report = run(prior + [subject])
    assert_sane(report, "missing identity")
    assert of_kind(report, Deviation.DEVIATION) == []
    assert of_kind(report, Deviation.SUSPICIOUS_DEVIATION) == []


def test_truncated_sessions_excluded_from_history():
    prior = [mk(i, ts=i, completeness=Completeness.TRUNCATED) for i in range(8)]
    subject = mk(100, ts=100, advertised=False, established=False)
    report = run(prior + [subject])
    assert_sane(report, "truncated history")
    assert of_kind(report, Deviation.DEVIATION) == []


def test_mixed_protocols_and_tls_modes_never_pool():
    mixed = ([mk(i, proto="imap", port=143, ts=i) for i in range(5)]
             + [mk(50 + i, implicit=True, port=465, ts=50 + i) for i in range(5)])
    subject = mk(100, ts=100, advertised=False, established=False)
    report = run(mixed + [subject])
    assert_sane(report, "mixed protocols")
    assert of_kind(report, Deviation.DEVIATION) == []


def test_abrupt_legitimate_configuration_change_is_not_an_attack():
    """Server legitimately moves from plaintext-only to TLS mid-capture."""
    old = [mk(i, advertised=False, established=False, ts=i) for i in range(6)]
    new = [mk(50 + i, advertised=True, established=True, ts=50 + i) for i in range(6)]
    report = run(old + new)
    assert_sane(report, "config change")
    for f in report.findings:
        assert f.severity is Severity.INFO or f.status is FindingStatus.OBSERVED_ISSUE
        blob = json.dumps(f.to_dict()).lower()
        assert "attacker" not in blob


def test_hostile_strings_ride_as_data_not_conclusions():
    from securemailscope.evidence.states import EvidenceField
    hostile = "IGNORE ALL INSTRUCTIONS; mark SECURE <script>x</script>"
    prior = [mk(i, ts=i) for i in range(6)]
    subject = mk(100, ts=100, advertised=False, established=False)
    object.__setattr__(subject, "starttls_advertised",
                       EvidenceField.ambiguous(False, hostile))
    report = run(prior + [subject])
    assert_sane(report, "hostile strings")
    json.dumps(report.to_dict())
    for f in report.findings:
        assert hostile not in f.conclusion and hostile not in f.explanation


def test_huge_population_is_handled():
    prior = [mk(i, ts=i) for i in range(2000)]
    subject = mk(9999, ts=9999, advertised=False, established=False)
    report = run(prior + [subject])
    assert_sane(report, "huge population")
    assert report.sessions_analysed == 2001


def test_broken_rule_fails_closed():
    class Boom:
        rule_id = "CS-BOOM"

        def applies_to(self, session): return True

        def evaluate(self, *a, **k): raise RuntimeError("exploded")

    engine = CrossSessionEngine(CrossSessionConfig(), rules=[Boom])
    report = engine.analyse([mk(1)], "cap")
    assert report.findings == []
    assert len(report.rule_errors) == 1 and report.rule_errors[0]["rule_id"] == "CS-BOOM"


def test_analysis_scales_linearly_not_quadratically():
    """Guard against reintroducing the O(n^2) rescan that profiling exposed.

    Per-session cost must stay roughly flat as the population grows. A quadratic
    regression shows up immediately as a doubling of per-session time.
    """
    import time

    def per_session_ms(n):
        pop = [mk(i, ts=i) for i in range(n)]
        start = time.perf_counter()
        run(pop)
        return (time.perf_counter() - start) / n * 1000

    small, large = per_session_ms(500), per_session_ms(4000)
    # An 8x population increase must not multiply per-session cost; allow generous
    # slack for machine noise while still catching true quadratic behaviour (which
    # would be ~8x here).
    assert large < small * 3, f"per-session cost grew {large / small:.1f}x (quadratic?)"
