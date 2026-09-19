"""
Phase-6 tests: feature extraction, encoding and leakage governance (§35).

The leakage tests are the load-bearing ones. A feature layer that quietly encodes a
deterministic verdict, a capture identity or a generator artifact makes every downstream
metric meaningless, and that failure is invisible unless something asserts against it.
"""
import ast
import pathlib

import pytest

from securemailscope.crosssession.baseline import BaselineStatus, build_baseline
from securemailscope.crosssession.comparability import Comparability, assess
from securemailscope.crosssession.contrast import ContrastState, evaluate_contrast
from securemailscope.evidence.states import EvidenceField, EvidenceState
from securemailscope.ml.encoding import FeatureEncoder
from securemailscope.ml.features import (
    FEATURE_SCHEMA_VERSION, FEATURE_SPECS, FORBIDDEN_INPUTS, OTHER,
    CrossSessionContext, FeatureGroup, FeatureKind, LeakageRisk, MLFeatureExtractor,
)
from securemailscope.session.model import (
    AppState, Completeness, Direction, ProtocolEvent, SessionEvidence, TlsState,
    TransportRole,
)

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "securemailscope"


def mk(stream=1, *, client="10.1.1.5", server="10.1.1.80", port=587, proto="smtp",
       advertised=True, established=True, version="TLS1.3", implicit=False,
       completeness=Completeness.COMPLETE, packets=20, ts=1000.0) -> SessionEvidence:
    adv = (EvidenceField.observed(True, "250-STARTTLS seen", frames=[2])
           if advertised is True else
           EvidenceField.ambiguous(False, "no upgrade capability in the reply", frames=[2])
           if advertised is False else
           EvidenceField.unknown("no capability response observed"))
    tls = (EvidenceField.observed(version, "ServerHello", frames=[5])
           if established else EvidenceField.unknown("no ServerHello observed"))
    return SessionEvidence(
        capture_id="cap", tcp_stream_id=stream, protocol=proto,
        client_ip=client, client_port=40000 + stream, server_ip=server, server_port=port,
        first_frame=1, last_frame=packets, start_epoch=ts, end_epoch=ts + 0.5,
        packet_count=packets,
        transport_flags=(TransportRole.SETUP_OBSERVED, TransportRole.TEARDOWN_OBSERVED),
        completeness=completeness,
        app_state=AppState.TLS_ESTABLISHED if established else AppState.CLOSED,
        tls_state=TlsState.ESTABLISHED if established else TlsState.NONE,
        implicit_tls=implicit,
        starttls_advertised=adv,
        starttls_requested=(EvidenceField.observed(True, "STARTTLS", frames=[3])
                            if established else
                            EvidenceField.observed(False, "never issued", frames=[3])),
        tls_negotiated_version=tls,
        auth_activity=EvidenceField.observed(not established, "AUTH LOGIN", frames=[4]),
        events=[ProtocolEvent("greeting", Direction.SERVER_TO_CLIENT, 1, ts),
                ProtocolEvent("capability_response", Direction.SERVER_TO_CLIENT, 2, ts)],
    )


# --------------------------------------------------------------- schema governance
def test_every_spec_documents_its_governance():
    for spec in FEATURE_SPECS:
        assert spec.source and spec.meaning and spec.missing_policy, spec.feature_id
        assert isinstance(spec.leakage_risk, LeakageRisk)


def test_no_high_leakage_feature_is_shipped():
    """HIGH risk exists in the vocabulary to be testable, not to be used."""
    assert [s.feature_id for s in FEATURE_SPECS
            if s.leakage_risk is LeakageRisk.HIGH] == []


def test_feature_ids_are_unique():
    ids = [s.feature_id for s in FEATURE_SPECS]
    assert len(ids) == len(set(ids))


def test_ordinal_features_justify_their_ordering():
    """Numeric encoding of an ordered category needs a written reason (§8)."""
    ordinal = [s for s in FEATURE_SPECS if s.feature_id.endswith("_ordinal")]
    assert ordinal
    for spec in ordinal:
        assert len(spec.ordinal_justification) > 40, spec.feature_id


def test_ml_package_does_not_import_the_rule_engines():
    """Structural anti-circularity (§5, §20): the ML lane cannot see a finding.

    AST-based rather than a substring scan, so a mention in a docstring or a comment
    does not trip it and a real import cannot hide behind one.
    """
    banned = {"securemailscope.analysis", "securemailscope.analysis.model",
              "securemailscope.analysis.rules", "securemailscope.analysis.engine",
              "securemailscope.crosssession.rules", "securemailscope.crosssession.model",
              "securemailscope.crosssession.engine"}
    offenders = []
    for path in sorted((SRC / "ml").glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in banned:
                offenders.append(f"{path.name}: from {node.module}")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in banned:
                        offenders.append(f"{path.name}: import {alias.name}")
    assert offenders == [], offenders


def test_no_forbidden_identity_field_is_a_feature():
    ids = {s.feature_id for s in FEATURE_SPECS}
    assert ids.isdisjoint(set(FORBIDDEN_INPUTS))


def test_no_feature_names_a_rule_or_a_verdict():
    """Feature ids must not encode a rule id, a severity or a finding status."""
    banned = ("sec_", "sec-", "cs_", "cs-", "severity", "finding", "risk_score",
              "posture", "critical", "observed_issue", "compliant", "malicious",
              "attack", "strip")
    for spec in FEATURE_SPECS:
        low = spec.feature_id.lower()
        assert not any(b in low for b in banned), spec.feature_id


# --------------------------------------------------------------------- extraction
def test_extraction_is_deterministic():
    session = mk()
    ex = MLFeatureExtractor()
    assert ex.extract(session).values == ex.extract(session).values


def test_schema_version_travels_with_the_vector():
    assert MLFeatureExtractor().extract(mk()).schema_version == FEATURE_SCHEMA_VERSION


def test_evidence_states_survive_as_their_own_categories():
    """UNKNOWN, AMBIGUOUS and NOT_OBSERVABLE must never collapse into 'false' (§9)."""
    ex = MLFeatureExtractor()
    unknown = mk(advertised=None)
    ambiguous = mk(advertised=False)
    assert ex.extract(unknown).values["starttls_advertised"] == EvidenceState.UNKNOWN.value
    assert ex.extract(ambiguous).values["starttls_advertised"] == (
        EvidenceState.AMBIGUOUS.value)
    assert (ex.extract(unknown).values["starttls_advertised"]
            != ex.extract(ambiguous).values["starttls_advertised"])


def test_not_observable_is_distinct_from_absent():
    """The TLS 1.3 case: the certificate is unobservable, not missing."""
    ex = MLFeatureExtractor()
    session = mk()
    session.starttls_advertised = EvidenceField.not_observable("implicit TLS carries no "
                                                               "capability exchange")
    value = ex.extract(session).values["starttls_advertised"]
    assert value == EvidenceState.NOT_OBSERVABLE.value
    assert value != "false"


def test_missing_numeric_is_flagged_not_silently_zeroed():
    session = mk(established=False)          # no version -> no ordinal
    vector = MLFeatureExtractor().extract(session)
    assert "tls_version_ordinal" in vector.missing
    assert vector.values["tls_version_ordinal"] == 0.0


def test_missing_timestamps_do_not_fabricate_a_duration():
    session = mk()
    session.start_epoch = None
    session.end_epoch = None
    vector = MLFeatureExtractor().extract(session)
    assert "duration_s" in vector.missing


def test_group_restriction_removes_features_rather_than_zeroing_them():
    only_tls = MLFeatureExtractor((FeatureGroup.TLS,)).extract(mk())
    assert "tls_state" in only_tls.values
    assert "proto" not in only_tls.values
    assert "contrast_state" not in only_tls.values


def test_context_absent_is_marked_and_does_not_invent_a_baseline():
    vector = MLFeatureExtractor().extract(mk())
    assert vector.context_available is False
    assert vector.values["baseline_status"] == OTHER
    assert "baseline_size" in vector.missing


def test_context_features_use_phase5_primitives():
    population = [mk(i, ts=1000.0 + i) for i in range(8)]
    subject = population[-1]
    ctx = CrossSessionContext(
        comparability=assess(subject),
        baseline=build_baseline(subject, population),
        contrast=evaluate_contrast(subject, population))
    vector = MLFeatureExtractor().extract(subject, ctx)
    assert vector.context_available is True
    assert vector.values["comparability"] == Comparability.COMPARABLE.value
    assert vector.values["baseline_status"] == BaselineStatus.ESTABLISHED.value
    assert vector.values["baseline_size"] == 7.0


# ---------------------------------------------------------------------- encoding
def test_column_layout_depends_on_the_schema_not_on_the_data():
    a = FeatureEncoder()
    b = FeatureEncoder()
    assert a.columns == b.columns
    assert a.layout_signature() == b.layout_signature()


def test_categoricals_are_one_hot_never_ordinal_integers():
    enc = FeatureEncoder()
    for spec in FEATURE_SPECS:
        if spec.kind is not FeatureKind.CATEGORICAL:
            continue
        cols = [c for c in enc.columns if c.startswith(spec.feature_id + "=")]
        assert len(cols) == len(spec.vocabulary), spec.feature_id


def test_one_hot_sets_exactly_one_column_per_categorical():
    enc = FeatureEncoder()
    row = dict(zip(enc.columns, enc.encode_one(MLFeatureExtractor().extract(mk()))))
    for spec in FEATURE_SPECS:
        if spec.kind is not FeatureKind.CATEGORICAL:
            continue
        hot = [c for c in enc.columns
               if c.startswith(spec.feature_id + "=") and row[c] == 1.0]
        assert len(hot) == 1, (spec.feature_id, hot)


def test_unknown_category_routes_to_other_without_shifting_the_layout():
    """An unseen cipher suite in the field must degrade, not break (§22, §35)."""
    enc = FeatureEncoder()
    vector = MLFeatureExtractor().extract(mk())
    vector.values["tls_cipher"] = "0xdead"
    row = dict(zip(enc.columns, enc.encode_one(vector)))
    assert row[f"tls_cipher={OTHER}"] == 1.0
    assert len(enc.encode_one(vector)) == len(enc.columns)


def test_missing_indicator_columns_exist_and_are_set():
    enc = FeatureEncoder()
    vector = MLFeatureExtractor().extract(mk(established=False))
    row = dict(zip(enc.columns, enc.encode_one(vector)))
    assert row["tls_version_ordinal__missing"] == 1.0
    assert row["tls_version_ordinal"] == 0.0


def test_encoder_rejects_a_mismatched_schema_version():
    enc = FeatureEncoder()
    vector = MLFeatureExtractor().extract(mk())
    stale = type(vector)(schema_version="0.0", session_key=vector.session_key,
                         capture_id=vector.capture_id, values=vector.values)
    with pytest.raises(ValueError, match="schema mismatch"):
        enc.encode_one(stale)


def test_excluded_features_leave_the_matrix_entirely():
    enc = FeatureEncoder(exclude=("tls_cipher",))
    assert not any(c.startswith("tls_cipher=") for c in enc.columns)
    assert enc.layout_signature() != FeatureEncoder().layout_signature()
