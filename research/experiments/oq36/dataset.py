"""
Phase-6 dataset assembly (§10, §11, §12, §13, §30).

Builds the evaluation corpus by running the REAL pipeline over every capture:

    PCAP -> analyze_capture -> reconstruct_sessions -> Phase-5 context -> features

Nothing is re-parsed and nothing is simulated at the session level, so the matrix the
models see is exactly the evidence the product produces.

Split policy, which is the part that actually matters:

  * TRAIN   generator B, *normal-labelled sessions only*, from TRAIN scenarios
  * VAL     generator C, *normal-labelled sessions only*, from VAL scenarios -> threshold
  * TEST_B  generator B, held-out SCENARIOS (same generator, unseen scenarios)
  * TEST_C  generator C, held-out SCENARIOS (cross generator)
  * TEST_A  generator A in full (cross generator, independently authored, and the corpus
            the deterministic engine was originally validated against)

Labels are used for EVALUATION ONLY. `fit` never receives them, and the threshold is
selected from validation scores of normal sessions without reference to any attack.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from securemailscope.ingest import analyze_capture
from securemailscope.ml.encoding import FeatureEncoder
from securemailscope.ml.engine import AnomalyConfig, AnomalyEngine
from securemailscope.session import reconstruct_sessions
from securemailscope.session.model import SessionEvidence

HERE = os.path.dirname(os.path.abspath(__file__))
GEN_A_DIR = os.path.join(HERE, "..", "oq28", "pcaps")
GEN_B_DIR = os.path.join(HERE, "corpus", "genB")
GEN_C_DIR = os.path.join(HERE, "corpus", "genC")

#: Ground-truth labels that denote active manipulation. Everything else is benign --
#: including weak TLS and failed upgrades, which are real security problems but are NOT
#: stripping. Conflating "insecure" with "manipulated" would make the evaluation
#: meaningless (§13).
ATTACK_LABELS = {"ATTACK_STRIP_ADVERT", "ATTACK_STRIP_COMMAND"}

#: Scenarios where EVERY client is stripped, so no unaffected control exists anywhere.
#: Experimentally established as undetectable from the capture alone (02A §9 #1,
#: FN 30/30). Reported separately so a known-impossible case does not silently depress
#: every recall number.
BLIND_SCENARIOS = {"B05_strip_blind", "C05_strip_blind", "H_no_control"}

#: Generator B scenarios withheld from training entirely.
B_HELDOUT = {"B05_strip_blind", "B06_strip_command", "B09_mixed_legit", "B16_legacy_tls"}
#: Generator C scenarios used for threshold selection (normals only).
C_VAL = {"C01_upgrade_smtp", "C02_decline_smtp", "C03_no_support_smtp",
         "C12_imap_upgrade", "C14_pop3_no_support", "C15_implicit_smtps",
         "C16_implicit_pop3s"}


@dataclass
class Record:
    """One session plus everything needed to evaluate and to audit the split."""
    generator: str
    scenario: str
    capture: str
    capture_id: str
    session_key: Optional[str]
    label: str
    session: SessionEvidence = field(repr=False, default=None)
    row: Tuple[float, ...] = ()

    @property
    def is_attack(self) -> bool:
        return self.label in ATTACK_LABELS

    @property
    def blind(self) -> bool:
        return self.scenario in BLIND_SCENARIOS

    @property
    def row_hash(self) -> str:
        return hashlib.sha256(
            ",".join(f"{v:.6f}" for v in self.row).encode()).hexdigest()[:16]


# -------------------------------------------------------------- ground truth
def _truth_gen_bc(directory: str) -> Dict[Tuple[str, str, int], Tuple[str, str]]:
    """(capture, client_ip, client_port) -> (scenario, label) for generators B and C."""
    meta = json.load(open(os.path.join(directory, "ground_truth.json")))
    out = {}
    for cap in meta["captures"]:
        for s in cap["streams"]:
            out[(cap["pcap"], s["client"], s["client_port"])] = (
                cap["scenario"], s["ground_truth"])
    return out


def _truth_gen_a() -> Dict[Tuple[str, str, int], Tuple[str, str]]:
    """Generator A's sidecar keys streams as 'client:port->server'."""
    entries = json.load(open(os.path.join(GEN_A_DIR, "ground_truth.json")))
    out = {}
    for entry in entries:
        for s in entry.get("streams", []):
            left = s["stream"].split("->")[0]
            ip, _, port = left.rpartition(":")
            out[(entry["pcap"], ip, int(port))] = (entry["case"], s["ground_truth"])
    return out


# ------------------------------------------------------------------- loading
def load_generator(directory: str, generator: str,
                   truth: Dict[Tuple[str, str, int], Tuple[str, str]],
                   engine: AnomalyEngine) -> List[Record]:
    records: List[Record] = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".pcap"):
            continue
        run, frames = analyze_capture(os.path.join(directory, name))
        sessions = reconstruct_sessions(frames, run.capture.capture_id)
        if not sessions:
            continue
        # Context and encoding are computed per CAPTURE, exactly as the product does:
        # a baseline may only be built from sessions in the same analysis population.
        matrix = engine.matrix(sessions)
        ordered = sorted(sessions, key=lambda s: (
            s.start_epoch if s.start_epoch is not None else float("-inf"),
            s.first_frame if s.first_frame is not None else -1,
            s.tcp_stream_id if s.tcp_stream_id is not None else -1))
        for session, row in zip(ordered, matrix.rows):
            scenario, label = truth.get(
                (name, session.client_ip, session.client_port),
                (os.path.splitext(name)[0], "UNLABELLED"))
            records.append(Record(
                generator=generator, scenario=scenario, capture=name,
                capture_id=session.capture_id, session_key=session.stream_key,
                label=label, session=session, row=tuple(row)))
    return records


def load_all(engine: Optional[AnomalyEngine] = None) -> Dict[str, List[Record]]:
    engine = engine or AnomalyEngine(config=AnomalyConfig())
    return {
        "A": load_generator(GEN_A_DIR, "A", _truth_gen_a(), engine),
        "B": load_generator(GEN_B_DIR, "B", _truth_gen_bc(GEN_B_DIR), engine),
        "C": load_generator(GEN_C_DIR, "C", _truth_gen_bc(GEN_C_DIR), engine),
    }


# -------------------------------------------------------------------- splits
@dataclass
class Splits:
    train: List[Record]
    validation: List[Record]
    test_b: List[Record]
    test_c: List[Record]
    test_a: List[Record]

    def as_dict(self) -> Dict[str, List[Record]]:
        return {"TRAIN": self.train, "VAL": self.validation, "TEST_B": self.test_b,
                "TEST_C": self.test_c, "TEST_A": self.test_a}


def make_splits(corpus: Dict[str, List[Record]]) -> Splits:
    train = [r for r in corpus["B"] if r.scenario not in B_HELDOUT and not r.is_attack]
    validation = [r for r in corpus["C"] if r.scenario in C_VAL and not r.is_attack]
    test_b = [r for r in corpus["B"] if r.scenario in B_HELDOUT]
    test_c = [r for r in corpus["C"] if r.scenario not in C_VAL]
    test_a = list(corpus["A"])
    return Splits(train, validation, test_b, test_c, test_a)


# ------------------------------------------------------- integrity / leakage
def duplicate_report(splits: Splits) -> dict:
    """Identical feature rows are the leakage risk that matters (§12).

    Two sessions from the same scenario are *expected* to encode identically -- the
    corpus deliberately repeats behaviour. What must not happen is the same row
    appearing in TRAIN and in a TEST split, which would let a model recognise a row it
    has already been fitted on.
    """
    by_split = {name: Counter(r.row_hash for r in recs)
                for name, recs in splits.as_dict().items()}
    train_hashes = set(by_split["TRAIN"])
    cross: Dict[str, int] = {}
    for name, counts in by_split.items():
        if name == "TRAIN":
            continue
        cross[name] = sum(n for h, n in counts.items() if h in train_hashes)
    return {
        "distinct_rows": {k: len(v) for k, v in by_split.items()},
        "total_rows": {k: sum(v.values()) for k, v in by_split.items()},
        "rows_also_present_in_train": cross,
        "scenario_overlap": _scenario_overlap(splits),
        "capture_overlap": _capture_overlap(splits),
    }


def _scenario_overlap(splits: Splits) -> Dict[str, List[str]]:
    train_scenarios = {r.scenario for r in splits.train}
    out = {}
    for name, recs in splits.as_dict().items():
        if name == "TRAIN":
            continue
        shared = sorted({r.scenario for r in recs} & train_scenarios)
        if shared:
            out[name] = shared
    return out


def _capture_overlap(splits: Splits) -> Dict[str, List[str]]:
    train_caps = {(r.generator, r.capture) for r in splits.train}
    out = {}
    for name, recs in splits.as_dict().items():
        if name == "TRAIN":
            continue
        shared = sorted(c for g, c in ({(r.generator, r.capture) for r in recs}
                                       & train_caps))
        if shared:
            out[name] = shared
    return out


def inventory(corpus: Dict[str, List[Record]], splits: Splits,
              encoder: Optional[FeatureEncoder] = None) -> dict:
    encoder = encoder or FeatureEncoder()
    per_generator = {}
    for gen, recs in corpus.items():
        per_generator[gen] = {
            "sessions": len(recs),
            "captures": len({r.capture for r in recs}),
            "scenarios": len({r.scenario for r in recs}),
            "attacks": sum(1 for r in recs if r.is_attack),
            "benign": sum(1 for r in recs if not r.is_attack),
            "labels": dict(sorted(Counter(r.label for r in recs).items())),
            "protocols": dict(sorted(Counter(
                r.session.protocol or "none" for r in recs).items())),
            "tls_versions": dict(sorted(Counter(
                str(r.session.tls_negotiated_version.value
                    or r.session.tls_negotiated_version.state.value)
                for r in recs).items())),
            "implicit_tls": sum(1 for r in recs if r.session.implicit_tls),
            "clients": len({r.session.client_ip for r in recs}),
            "servers": len({r.session.server_ip for r in recs}),
        }
    split_summary = {
        name: {"sessions": len(recs),
               "attacks": sum(1 for r in recs if r.is_attack),
               "blind_attacks": sum(1 for r in recs if r.is_attack and r.blind),
               "generators": sorted({r.generator for r in recs}),
               "scenarios": sorted({r.scenario for r in recs})}
        for name, recs in splits.as_dict().items()
    }
    return {
        "feature_schema_version": encoder.specs[0].feature_id and "1.0",
        "logical_features": len(encoder.specs),
        "encoded_columns": len(encoder.columns),
        "layout_signature": encoder.layout_signature(),
        "per_generator": per_generator,
        "splits": split_summary,
        "integrity": duplicate_report(splits),
        "attack_labels": sorted(ATTACK_LABELS),
        "blind_scenarios": sorted(BLIND_SCENARIOS),
    }


if __name__ == "__main__":
    eng = AnomalyEngine()
    data = load_all(eng)
    sp = make_splits(data)
    report = inventory(data, sp, eng.encoder)
    out = os.path.join(HERE, "results")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "dataset-inventory.json"), "w") as fh:
        json.dump(report, fh, indent=1, sort_keys=True)
    print(json.dumps({k: report[k] for k in
                      ("logical_features", "encoded_columns", "layout_signature")},
                     indent=1))
    for gen, info in sorted(report["per_generator"].items()):
        print(f"gen {gen}: {info['sessions']:4d} sessions  {info['captures']:2d} captures  "
              f"attacks={info['attacks']:3d}  clients={info['clients']}  "
              f"servers={info['servers']}")
    for name, info in report["splits"].items():
        print(f"{name:7s}: {info['sessions']:4d} sessions  attacks={info['attacks']:3d} "
              f"(blind {info['blind_attacks']})  generators={info['generators']}")
    print("integrity:", json.dumps(report["integrity"]["rows_also_present_in_train"]))
    print("scenario overlap with train:", report["integrity"]["scenario_overlap"])
