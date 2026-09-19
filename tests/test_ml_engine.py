"""
Phase-6 tests: anomaly engine, contract, explanation and model governance (§35).

The behaviours asserted here are the ones that keep the ML lane a *lane* rather than a
second opinion on security facts: it abstains instead of guessing, it explains itself,
it is reproducible, and its output cannot be mistaken for a finding.
"""
import pytest

from securemailscope.ml.contract import (
    AnomalyBand, MLAnomalyResult, ModelArtifact, dataset_hash,
)
from securemailscope.ml.encoding import FeatureEncoder
from securemailscope.ml.engine import (
    ML_ENGINE_VERSION, AnomalyConfig, AnomalyEngine, AnomalyReport,
)
from securemailscope.ml.explain import explain, reference_row
from securemailscope.ml.features import FeatureGroup
from securemailscope.ml.models import MeanShiftBaselineModel, RobustZScoreModel
from securemailscope.session.model import Completeness, TlsState

from test_ml_features import mk


def population(n=12, **kw):
    return [mk(i, ts=1000.0 + i, **kw) for i in range(n)]


def fitted_engine(sessions=None, quantile=0.9, model=None):
    engine = AnomalyEngine(model or RobustZScoreModel(aggregate="sum"))
    sessions = sessions or population()
    rows = engine.matrix(sessions).rows
    engine.fit(rows)
    engine.set_threshold(rows, quantile)
    return engine


# ----------------------------------------------------------------- contract
def test_scored_band_requires_a_score():
    with pytest.raises(ValueError, match="requires an anomaly_score"):
        MLAnomalyResult(session_key="k", capture_id="c", model_id="m",
                        model_version="1", feature_schema_version="1.0",
                        anomaly_score=None, threshold=1.0,
                        band=AnomalyBand.ANOMALOUS, basis="x")


def test_not_scored_must_not_carry_a_score():
    with pytest.raises(ValueError, match="must not carry a score"):
        MLAnomalyResult(session_key="k", capture_id="c", model_id="m",
                        model_version="1", feature_schema_version="1.0",
                        anomaly_score=0.5, threshold=1.0,
                        band=AnomalyBand.NOT_SCORED, basis="x")


def test_every_result_records_a_basis():
    with pytest.raises(ValueError, match="why it says what it says"):
        MLAnomalyResult(session_key="k", capture_id="c", model_id="m",
                        model_version="1", feature_schema_version="1.0",
                        anomaly_score=None, threshold=None,
                        band=AnomalyBand.NOT_SCORED, basis="")


def test_result_carries_no_deterministic_verdict_vocabulary():
    """§28: an anomaly result must not look like, or be convertible into, a finding."""
    report = fitted_engine().analyse(population())
    payload = report.results[0].to_dict()
    for banned in ("severity", "status", "standards", "remediation", "finding_id",
                   "rule_id", "conclusion"):
        assert banned not in payload


def test_basis_never_asserts_an_attack():
    report = fitted_engine().analyse(population())
    for result in report.results:
        low = result.basis.lower()
        for banned in ("attack", "attacker", "malicious", "stripped", "stripping",
                       "compromise", "intrusion", "credential theft"):
            assert banned not in low, result.basis


# ---------------------------------------------------------------- abstention
def test_abstains_on_an_incomplete_session_rather_than_scoring_it():
    """The distinctive failure of the model rejected in 10B was re-flagging capture
    artifacts. Abstention makes that structurally impossible."""
    sessions = population()
    sessions[3].completeness = Completeness.INCOMPLETE
    report = fitted_engine(population()).analyse(sessions)
    partial = [r for r in report.results if r.band is AnomalyBand.NOT_SCORED]
    assert len(partial) == 1
    assert partial[0].anomaly_score is None
    assert "completeness" in partial[0].basis


def test_abstains_when_no_protocol_was_identified():
    sessions = population()
    sessions[2].protocol = None
    report = fitted_engine(population()).analyse(sessions)
    assert any(r.band is AnomalyBand.NOT_SCORED
               and "no mail protocol" in r.basis for r in report.results)


def test_abstention_is_counted_and_reported():
    sessions = population()
    for s in sessions[:4]:
        s.completeness = Completeness.INCOMPLETE
    report = fitted_engine(population()).analyse(sessions)
    assert report.abstentions == 4
    assert report.sessions_scored == len(sessions) - 4
    assert report.to_dict()["counts"]["abstention_rate"] == round(4 / len(sessions), 4)


def test_truncated_sessions_can_be_scored_only_by_explicit_opt_in():
    sessions = population()
    sessions[1].completeness = Completeness.INCOMPLETE
    engine = AnomalyEngine(RobustZScoreModel(),
                           AnomalyConfig(score_truncated=True))
    rows = engine.matrix(population()).rows
    engine.fit(rows)
    engine.set_threshold(rows, 0.9)
    assert engine.analyse(sessions).abstentions == 0


# ------------------------------------------------------------------ scoring
def test_unfitted_engine_refuses_to_score():
    with pytest.raises(RuntimeError, match="no fitted model"):
        AnomalyEngine().analyse(population())


def test_identical_input_produces_identical_output():
    engine = fitted_engine()
    a = engine.analyse(population()).to_dict()
    b = engine.analyse(population()).to_dict()
    assert a == b


def test_scoring_is_order_independent():
    engine = fitted_engine()
    forward = engine.analyse(population())
    reverse = engine.analyse(list(reversed(population())))
    by_key = {r.session_key: r.anomaly_score for r in forward.results}
    for result in reverse.results:
        assert by_key[result.session_key] == result.anomaly_score


def test_threshold_comes_from_validation_and_scoring_cannot_move_it():
    engine = fitted_engine()
    before = engine.threshold
    engine.analyse(population(20, established=False))
    assert engine.threshold == before


def test_threshold_quantile_is_validated():
    engine = AnomalyEngine(RobustZScoreModel())
    rows = engine.matrix(population()).rows
    engine.fit(rows)
    for bad in (0.0, 1.0, -0.5, 2.0):
        with pytest.raises(ValueError, match="quantile"):
            engine.set_threshold(rows, bad)


def test_bands_respect_the_threshold():
    engine = fitted_engine()
    for result in engine.analyse(population()).results:
        if result.band is AnomalyBand.ANOMALOUS:
            assert result.anomaly_score >= engine.threshold
        elif result.band is AnomalyBand.NORMAL:
            assert result.anomaly_score < engine.threshold


def test_a_clearly_different_session_scores_above_its_own_population():
    """Sanity: the model must at least separate something it has never seen.

    This test caught the top-k saturation defect: with `topk_mean`, an obviously
    different session and an ordinary one both scored exactly _CONSTANT_NOVELTY and the
    ranking was flat. It is written against the shipped `sum` aggregate for that reason.
    """
    normal = population(14)
    engine = fitted_engine(normal, quantile=0.95)
    odd = mk(99, ts=2000.0, established=False, advertised=False, proto="pop3",
             port=110, packets=300)
    scores = {r.session_key: r.anomaly_score
              for r in engine.analyse(normal + [odd]).results if r.scored}
    assert scores[odd.stream_key] > max(
        v for k, v in scores.items() if k != odd.stream_key)


# -------------------------------------------------------------- explanation
def test_robust_z_explains_itself_natively():
    engine = fitted_engine()
    scored = [r for r in engine.analyse(population()).results if r.scored]
    assert any(r.top_features for r in scored)
    for result in scored:
        for contribution in result.top_features:
            assert contribution.column in engine.encoder.columns
            assert contribution.direction in (
                "above_normal", "below_normal", "differs_from_normal")


def test_occlusion_explains_a_model_with_no_native_attribution():
    engine = AnomalyEngine(MeanShiftBaselineModel())
    rows = engine.matrix(population()).rows
    engine.fit(rows)
    engine.set_threshold(rows, 0.9)
    odd = mk(99, ts=2000.0, established=False, advertised=False, packets=400)
    result = [r for r in engine.analyse(population() + [odd]).results
              if r.session_key == odd.stream_key][0]
    assert result.top_features
    assert all(c.contribution > 0 for c in result.top_features)


def test_explanation_is_empty_rather_than_invented_without_a_reference():
    model = MeanShiftBaselineModel().fit([(0.0, 0.0), (1.0, 1.0)])
    assert explain(model, (5.0, 5.0), ("a", "b"), {"a": "a", "b": "b"},
                   reference=None) == ()


def test_reference_row_is_the_column_median():
    assert reference_row([(1.0, 10.0), (2.0, 20.0), (3.0, 30.0)]) == (2.0, 20.0)


# ------------------------------------------------------------- reproducibility
def test_artifact_records_everything_needed_to_reproduce():
    engine = fitted_engine()
    artifact = engine.artifact
    assert artifact.feature_schema_version == "1.0"
    assert artifact.layout_signature == engine.encoder.layout_signature()
    assert artifact.training_rows > 0
    assert artifact.threshold == engine.threshold
    assert artifact.threshold_method
    assert artifact.trained_at_utc.endswith("Z")


def test_artifact_hash_changes_when_training_data_changes():
    a = fitted_engine(population(12)).artifact.artifact_hash
    b = fitted_engine(population(12, established=False)).artifact.artifact_hash
    assert a != b


def test_dataset_hash_is_stable_and_content_addressed():
    rows = ((1.0, 2.0), (3.0, 4.0))
    assert dataset_hash(rows, ("a", "b")) == dataset_hash(rows, ("a", "b"))
    assert dataset_hash(rows, ("a", "b")) != dataset_hash(rows, ("a", "c"))
    assert dataset_hash(rows, ("a", "b")) != dataset_hash(((1.0, 2.0),), ("a", "b"))


def test_layout_signature_pins_the_matrix_a_model_was_trained_on():
    full = FeatureEncoder()
    reduced = FeatureEncoder((FeatureGroup.TLS,))
    assert full.layout_signature() != reduced.layout_signature()


def test_report_serialises_without_losing_the_model_identity():
    payload = fitted_engine().analyse(population()).to_dict()
    assert payload["model"]["id"] == "robust-z"
    assert payload["versions"]["engine"] == ML_ENGINE_VERSION
    assert payload["versions"]["feature_schema"] == "1.0"


def test_empty_population_yields_an_empty_report():
    report = AnomalyEngine().analyse([])
    assert isinstance(report, AnomalyReport)
    assert report.sessions_seen == 0 and report.results == []
