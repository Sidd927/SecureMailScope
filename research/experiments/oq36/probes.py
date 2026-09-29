"""
Phase-6 diagnostic probes (§20 anti-circularity, §21 benign variation,
§31 feature ablation, §32 generator artifact, §34 performance).

These are the experiments that decide whether a leaderboard number means anything. A
model can post a respectable PR-AUC while having learned the capture generator, or
while merely re-deriving the rules engine. Each probe here is designed to catch one of
those failure modes, and each is allowed to return a negative answer.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import time
import warnings
from collections import Counter, defaultdict
from typing import Dict, List, Sequence, Tuple

warnings.filterwarnings("ignore")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "src"))

from bakeoff import (  # noqa: E402
    OPERATING_Q, confusion, derived, deterministic_flags, ranking_metrics,
)
from dataset import Record, load_all, make_splits  # noqa: E402

from securemailscope.ml.encoding import FeatureEncoder  # noqa: E402
from securemailscope.ml.engine import AnomalyConfig, AnomalyEngine  # noqa: E402
from securemailscope.ml.features import FeatureGroup, MLFeatureExtractor  # noqa: E402
from securemailscope.ml.models import RobustZScoreModel  # noqa: E402

RESULTS = os.path.join(HERE, "results")

#: Scenarios that are entirely legitimate but deliberately *unusual* -- the population
#: a naive "anything different is anomalous" model destroys itself on (§21).
BENIGN_VARIATION = {
    "B08_config_change": "server legitimately stops advertising mid-capture",
    "B09_mixed_legit": "heterogeneous but legitimate client population",
    "B16_legacy_tls": "obsolete TLS versions, legitimately negotiated",
    "C07_reject_upgrade": "server refuses an upgrade the client did request",
    "C09_mixed_legit": "heterogeneous but legitimate client population",
    "C10_config_change": "server legitimately starts advertising mid-capture",
    "C17_legacy_tls": "obsolete TLS versions, legitimately negotiated",
    "C18_reset_teardown": "abrupt RST teardown of otherwise normal traffic",
    "C15_implicit_smtps": "implicit TLS, no upgrade behaviour at all",
    "C16_implicit_pop3s": "implicit TLS, no upgrade behaviour at all",
}


def _rows(records: Sequence[Record]) -> List[Tuple[float, ...]]:
    return [r.row for r in records]


def _fit_and_threshold(model, train, val, q=OPERATING_Q):
    model.fit(_rows(train))
    scores = sorted(model.score(_rows(val)))
    rank = max(0, min(len(scores) - 1, int(round(q * (len(scores) - 1)))))
    return model, float(scores[rank])


# ------------------------------------------------------ §32 generator artifact
def generator_artifact(corpus, scorable) -> dict:
    """Can a supervised classifier tell generator B from generator C by features alone?

    If yes, the feature space encodes the capture pipeline, and any 'cross-generator'
    result is partly a measurement of that. This classifier is a DIAGNOSTIC and is never
    shipped -- it is trained on generator identity, which §39 forbids as a model input.
    """
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_score
        import numpy as np
    except ImportError as exc:
        return {"error": str(exc)}

    recs = [r for r in corpus["B"] + corpus["C"] if scorable[r.session_key]]
    X = np.asarray(_rows(recs), dtype=float)
    y = np.asarray([0 if r.generator == "B" else 1 for r in recs])
    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=1)
    acc = cross_val_score(clf, X, y, cv=5, scoring="accuracy")
    clf.fit(X, y)
    encoder = FeatureEncoder()
    importances = sorted(zip(encoder.columns, clf.feature_importances_),
                         key=lambda t: -t[1])[:15]
    majority = max(Counter(y.tolist()).values()) / len(y)
    return {
        "question": "can generator identity be recovered from the feature vector?",
        "cv_accuracy_mean": round(float(acc.mean()), 4),
        "cv_accuracy_std": round(float(acc.std()), 4),
        "majority_class_rate": round(float(majority), 4),
        "verdict": ("SEPARABLE: features carry generator identity"
                    if acc.mean() > majority + 0.05 else
                    "NOT SEPARABLE beyond the majority class"),
        "top_columns": [{"column": c, "importance": round(float(i), 5)}
                        for c, i in importances],
    }


# ------------------------------------------------------------- §31 ablation
ABLATIONS: List[Tuple[str, Tuple[FeatureGroup, ...]]] = [
    ("A_protocol_only", (FeatureGroup.PROTOCOL,)),
    ("B_tls_only", (FeatureGroup.TLS,)),
    ("C_context_only", (FeatureGroup.CONTEXT,)),
    ("D_all", tuple(FeatureGroup)),
    ("E_all_minus_context", (FeatureGroup.PROTOCOL, FeatureGroup.TLS,
                             FeatureGroup.STRUCTURE, FeatureGroup.AUTH)),
    ("F_all_minus_structure", (FeatureGroup.PROTOCOL, FeatureGroup.TLS,
                               FeatureGroup.AUTH, FeatureGroup.CONTEXT)),
    ("G_no_cipher", tuple(FeatureGroup)),          # exclusion applied below
]


def ablation(corpus) -> dict:
    """Which feature groups actually carry the signal?

    Re-extracts from the same sessions for each group subset, so an ablation genuinely
    removes a feature rather than zeroing a column the model still sees.
    """
    out = {}
    for name, groups in ABLATIONS:
        exclude = ("tls_cipher",) if name == "G_no_cipher" else ()
        extractor = MLFeatureExtractor(groups)
        encoder = FeatureEncoder(groups, exclude)
        engine = AnomalyEngine(config=AnomalyConfig(groups=groups,
                                                    exclude_features=exclude))
        rebuilt: Dict[str, List[Record]] = {}
        for gen, recs in corpus.items():
            by_capture: Dict[str, List[Record]] = defaultdict(list)
            for r in recs:
                by_capture[r.capture_id].append(r)
            new: List[Record] = []
            for capture_id, group in by_capture.items():
                sessions = [r.session for r in group]
                ctx = engine.contexts(sessions)
                for r in group:
                    vector = extractor.extract(r.session, ctx.get(r.session_key))
                    new.append(Record(r.generator, r.scenario, r.capture, r.capture_id,
                                      r.session_key, r.label, r.session,
                                      encoder.encode_one(vector)))
            rebuilt[gen] = new
        splits = make_splits(rebuilt)
        scorable = {r.session_key: engine._abstain_reason(r.session) is None
                    for recs in rebuilt.values() for r in recs}
        train = [r for r in splits.train if scorable[r.session_key]]
        val = [r for r in splits.validation if scorable[r.session_key]]
        model, threshold = _fit_and_threshold(RobustZScoreModel(aggregate="sum"), train, val)
        block = {"columns": len(encoder.columns), "threshold": round(threshold, 4)}
        # SELECT is reported alongside the test splits on purpose: acting on an
        # ablation measured only on TEST_* would be selecting a configuration from the
        # held-out data. Any future re-selection must use the SELECT column.
        for split_name, recs in (("SELECT", splits.test_b), ("TEST_C", splits.test_c),
                                 ("TEST_A", splits.test_a)):
            scored = [r for r in recs if scorable[r.session_key]]
            scores = model.score(_rows(scored))
            labels = [r.is_attack for r in scored]
            sighted = [i for i, r in enumerate(scored) if not r.blind]
            conf = confusion([s >= threshold for s in scores], labels)
            block[split_name] = {
                **conf, **derived(conf),
                "pr_auc_excl_blind": ranking_metrics(
                    [scores[i] for i in sighted],
                    [labels[i] for i in sighted]).get("pr_auc"),
            }
        out[name] = block
    return out


# ------------------------------------------------------ §20 anti-circularity
def anti_circularity(corpus, splits, scorable) -> dict:
    """Is the ML signal just the rules engine wearing a hat?

    Two measurements. First, how much the ML flag set overlaps the deterministic flag
    set -- high overlap with no unique detections is redundancy, not intelligence.
    Second, whether removing the CONTEXT group (which carries the Phase-5-derived
    contrast state, the feature closest to a conclusion) changes the answer.
    """
    out = {}
    for label, groups, exclude in (("with_context", tuple(FeatureGroup), ()),
                                   ("without_context",
                                    (FeatureGroup.PROTOCOL, FeatureGroup.TLS,
                                     FeatureGroup.STRUCTURE, FeatureGroup.AUTH), ())):
        if label == "with_context":
            sp, sc = splits, scorable
        else:
            extractor = MLFeatureExtractor(groups)
            encoder = FeatureEncoder(groups, exclude)
            engine = AnomalyEngine(config=AnomalyConfig(groups=groups))
            rebuilt = {}
            for gen, recs in corpus.items():
                by_capture = defaultdict(list)
                for r in recs:
                    by_capture[r.capture_id].append(r)
                new = []
                for capture_id, group in by_capture.items():
                    ctx = engine.contexts([r.session for r in group])
                    for r in group:
                        v = extractor.extract(r.session, ctx.get(r.session_key))
                        new.append(Record(r.generator, r.scenario, r.capture,
                                          r.capture_id, r.session_key, r.label,
                                          r.session, encoder.encode_one(v)))
                rebuilt[gen] = new
            sp = make_splits(rebuilt)
            sc = {r.session_key: engine._abstain_reason(r.session) is None
                  for recs in rebuilt.values() for r in recs}

        train = [r for r in sp.train if sc[r.session_key]]
        val = [r for r in sp.validation if sc[r.session_key]]
        model, threshold = _fit_and_threshold(RobustZScoreModel(aggregate="sum"), train, val)
        per_split = {}
        for split_name, recs in (("TEST_C", sp.test_c), ("TEST_A", sp.test_a)):
            rules, cross = deterministic_flags(recs)
            scored = [r for r in recs if sc[r.session_key]]
            keys = [r.session_key for r in scored]
            scores = model.score(_rows(scored))
            ml = {k: s >= threshold for k, s in zip(keys, scores)}
            ml_set = {k for k in keys if ml[k]}
            rule_set = {k for k in keys if rules.get(k)}
            union = ml_set | rule_set
            jaccard = len(ml_set & rule_set) / len(union) if union else 0.0
            per_split[split_name] = {
                "ml_flagged": len(ml_set), "rules_flagged": len(rule_set),
                "jaccard_with_rules": round(jaccard, 4),
                "ml_only": len(ml_set - rule_set),
                "ml_only_attacks": sum(1 for k in (ml_set - rule_set)
                                       if any(r.session_key == k and r.is_attack
                                              for r in scored)),
            }
        out[label] = per_split
    out["interpretation"] = (
        "A high Jaccard with the rules engine and zero unique detections would mean "
        "the model re-derived the rules. A low Jaccard with zero unique TRUE detections "
        "means it is looking somewhere else and finding nothing useful there.")
    return out


# ---------------------------------------------------- §21 benign variation
def benign_variation(corpus, splits, scorable) -> dict:
    """False-positive rate on legitimate-but-unusual traffic, per scenario."""
    train = [r for r in splits.train if scorable[r.session_key]]
    val = [r for r in splits.validation if scorable[r.session_key]]
    model, threshold = _fit_and_threshold(RobustZScoreModel(aggregate="sum"), train, val)
    per_scenario = {}
    for gen, recs in corpus.items():
        for scenario, note in BENIGN_VARIATION.items():
            group = [r for r in recs
                     if r.scenario == scenario and scorable[r.session_key]
                     and not r.is_attack]
            if not group:
                continue
            scores = model.score(_rows(group))
            flagged = sum(1 for s in scores if s >= threshold)
            per_scenario[scenario] = {
                "description": note, "sessions": len(group), "flagged": flagged,
                "false_positive_rate": round(flagged / len(group), 4),
                "median_score": round(statistics.median(scores), 4),
                "threshold": round(threshold, 4),
            }
    total = sum(v["sessions"] for v in per_scenario.values())
    flagged = sum(v["flagged"] for v in per_scenario.values())
    return {"threshold": round(threshold, 4), "per_scenario": per_scenario,
            "overall": {"sessions": total, "flagged": flagged,
                        "false_positive_rate": round(flagged / total, 4) if total else 0.0}}


# --------------------------------------------------------------- §34 timing
def performance(corpus, splits, scorable) -> dict:
    engine = AnomalyEngine(config=AnomalyConfig())
    sessions = [r.session for r in corpus["C"][:400]]
    t0 = time.time()
    engine.matrix(sessions)
    extract_s = time.time() - t0

    train = [r for r in splits.train if scorable[r.session_key]]
    t0 = time.time()
    model = RobustZScoreModel(aggregate="sum").fit(_rows(train))
    fit_s = time.time() - t0

    scored = [r for r in splits.test_c if scorable[r.session_key]]
    t0 = time.time()
    model.score(_rows(scored))
    score_s = time.time() - t0

    engine.model = model
    engine.set_threshold_value(1.0, "fixed for timing")
    engine._reference = tuple(0.0 for _ in engine.encoder.columns)
    subset = [r.session for r in scored[:200]]
    t0 = time.time()
    engine.analyse(subset, "timing")
    end_to_end_s = time.time() - t0

    return {
        "feature_extraction_ms_per_session": round(1000 * extract_s / len(sessions), 4),
        "fit_seconds": round(fit_s, 4),
        "fit_rows": len(train),
        "scoring_ms_per_session": round(1000 * score_s / max(1, len(scored)), 4),
        "end_to_end_ms_per_session": round(1000 * end_to_end_s / max(1, len(subset)), 4),
        "note": "end-to-end includes Phase-5 context rebuild and per-session explanation",
    }


def generator_artifact_reduced(corpus, scorable) -> dict:
    """Repeat §32 after dropping the features that made generators separable.

    The first run named STRUCTURE (duration, frame span, packet count, events per
    packet) plus port_class and tls_cipher as the separating columns -- exactly the
    features the schema had already marked MEDIUM leakage risk. This run answers the
    follow-up question the team actually needs: is what remains generator-neutral?
    """
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_score
        import numpy as np
    except ImportError as exc:
        return {"error": str(exc)}

    groups = (FeatureGroup.PROTOCOL, FeatureGroup.TLS, FeatureGroup.AUTH,
              FeatureGroup.CONTEXT)
    exclude = ("port_class", "tls_cipher")
    extractor = MLFeatureExtractor(groups)
    encoder = FeatureEncoder(groups, exclude)
    engine = AnomalyEngine(config=AnomalyConfig(groups=groups,
                                                exclude_features=exclude))
    rows, labels = [], []
    for gen in ("B", "C"):
        by_capture = defaultdict(list)
        for r in corpus[gen]:
            by_capture[r.capture_id].append(r)
        for capture_id, group in by_capture.items():
            ctx = engine.contexts([r.session for r in group])
            for r in group:
                if not scorable[r.session_key]:
                    continue
                v = extractor.extract(r.session, ctx.get(r.session_key))
                rows.append(encoder.encode_one(v))
                labels.append(0 if gen == "B" else 1)

    X, y = np.asarray(rows, dtype=float), np.asarray(labels)
    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=1)
    acc = cross_val_score(clf, X, y, cv=5, scoring="accuracy")
    clf.fit(X, y)
    majority = max(Counter(y.tolist()).values()) / len(y)
    top = sorted(zip(encoder.columns, clf.feature_importances_),
                 key=lambda t: -t[1])[:10]
    return {
        "removed": ["STRUCTURE group"] + list(exclude),
        "columns": len(encoder.columns),
        "cv_accuracy_mean": round(float(acc.mean()), 4),
        "majority_class_rate": round(float(majority), 4),
        "verdict": ("STILL SEPARABLE" if acc.mean() > majority + 0.05
                    else "NOT SEPARABLE beyond the majority class"),
        "top_columns": [{"column": c, "importance": round(float(i), 5)} for c, i in top],
    }


def main() -> None:
    os.makedirs(RESULTS, exist_ok=True)
    engine = AnomalyEngine(config=AnomalyConfig())
    corpus = load_all(engine)
    splits = make_splits(corpus)
    scorable = {r.session_key: engine._abstain_reason(r.session) is None
                for recs in corpus.values() for r in recs}

    report = {
        "generator_artifact": generator_artifact(corpus, scorable),
        "generator_artifact_reduced": generator_artifact_reduced(corpus, scorable),
        "ablation": ablation(corpus),
        "anti_circularity": anti_circularity(corpus, splits, scorable),
        "benign_variation": benign_variation(corpus, splits, scorable),
        "performance": performance(corpus, splits, scorable),
    }
    with open(os.path.join(RESULTS, "probes.json"), "w") as fh:
        json.dump(report, fh, indent=1, sort_keys=True)

    ga = report["generator_artifact"]
    print(f"[§32] generator separability: cv_acc={ga.get('cv_accuracy_mean')} "
          f"majority={ga.get('majority_class_rate')} -> {ga.get('verdict')}")
    gr = report["generator_artifact_reduced"]
    print(f"[§32b] after removing {gr.get('removed')}: cv_acc={gr.get('cv_accuracy_mean')} "
          f"majority={gr.get('majority_class_rate')} -> {gr.get('verdict')}")
    print("[§31] ablation (shipped robust-z sum), PR-AUC excluding blind:")
    for name, block in report["ablation"].items():
        print(f"   {name:24s} cols={block['columns']:4d} "
              f"SELECT={block['SELECT']['pr_auc_excl_blind']} | "
              f"TEST_C={block['TEST_C']['pr_auc_excl_blind']} "
              f"fpr={block['TEST_C']['fpr']:.3f} | "
              f"TEST_A={block['TEST_A']['pr_auc_excl_blind']} "
              f"fpr={block['TEST_A']['fpr']:.3f}")
    print("[§20] anti-circularity:")
    for label in ("with_context", "without_context"):
        for split_name, b in report["anti_circularity"][label].items():
            print(f"   {label:16s} {split_name}: ml={b['ml_flagged']} "
                  f"rules={b['rules_flagged']} jaccard={b['jaccard_with_rules']} "
                  f"ml_only={b['ml_only']} ml_only_attacks={b['ml_only_attacks']}")
    bv = report["benign_variation"]
    print(f"[§21] benign variation FP rate overall: "
          f"{bv['overall']['flagged']}/{bv['overall']['sessions']} = "
          f"{bv['overall']['false_positive_rate']}")
    for name, b in sorted(bv["per_scenario"].items(),
                          key=lambda kv: -kv[1]["false_positive_rate"])[:5]:
        print(f"   {name:24s} {b['flagged']:3d}/{b['sessions']:3d} "
              f"= {b['false_positive_rate']:.3f}  ({b['description']})")
    print("[§34] performance:", json.dumps(report["performance"]))
    print(f"\nwrote {os.path.join(RESULTS, 'probes.json')}")


if __name__ == "__main__":
    main()
