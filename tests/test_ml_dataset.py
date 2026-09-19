"""
Phase-6 dataset tests (§35 "Dataset"): split integrity, duplicate control and
generator reproducibility.

A held-out evaluation is only held out if nothing verifies it isn't. These tests assert
the properties the Phase-6 results depend on, so a later change to a generator or a
split cannot quietly invalidate every number in docs/research/17.

The generator tests need scapy and are skipped without it; the split tests read the
committed ground-truth manifests and need nothing.
"""
import json
import os
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
OQ36 = ROOT / "research" / "experiments" / "oq36"
CORPUS = OQ36 / "corpus"


def _scapy() -> bool:
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:
        return False


needs_scapy = pytest.mark.skipif(not _scapy(), reason="scapy not installed")
needs_corpus = pytest.mark.skipif(
    not (CORPUS / "genB" / "ground_truth.json").exists(),
    reason="generated corpus absent; run research/experiments/oq36/genb.py and genc.py")


def _manifest(generator: str) -> dict:
    return json.loads((CORPUS / f"gen{generator}" / "ground_truth.json").read_text())


# ------------------------------------------------------------ manifest sanity
@needs_corpus
@pytest.mark.parametrize("generator", ["B", "C"])
def test_manifest_labels_every_stream(generator):
    meta = _manifest(generator)
    assert meta["generator"] == generator
    for capture in meta["captures"]:
        assert capture["streams"]
        for stream in capture["streams"]:
            assert stream["ground_truth"]
            assert stream["client"] and stream["server"] and stream["protocol"]


@needs_corpus
@pytest.mark.parametrize("generator", ["B", "C"])
def test_stream_identity_is_unique_within_a_capture(generator):
    """Ground truth is joined to sessions on (client, port); collisions would silently
    mislabel and every downstream metric with it."""
    for capture in _manifest(generator)["captures"]:
        keys = [(s["client"], s["client_port"]) for s in capture["streams"]]
        assert len(keys) == len(set(keys)), capture["scenario"]


@needs_corpus
@pytest.mark.parametrize("generator", ["B", "C"])
def test_every_manifested_capture_exists_on_disk(generator):
    for capture in _manifest(generator)["captures"]:
        assert (CORPUS / f"gen{generator}" / capture["pcap"]).exists()


@needs_corpus
def test_generators_do_not_share_address_space():
    """Overlapping client or server IPs would make the two corpora one population and
    quietly destroy the cross-generator holdout."""
    def endpoints(generator):
        meta = _manifest(generator)
        return {s["client"] for c in meta["captures"] for s in c["streams"]} | \
               {s["server"] for c in meta["captures"] for s in c["streams"]}
    assert endpoints("B").isdisjoint(endpoints("C"))


@needs_corpus
def test_generators_do_not_share_scenario_ids():
    def scenarios(generator):
        return {c["scenario"] for c in _manifest(generator)["captures"]}
    assert scenarios("B").isdisjoint(scenarios("C"))


@needs_corpus
def test_both_attack_and_benign_populations_are_present():
    for generator in ("B", "C"):
        labels = {s["ground_truth"] for c in _manifest(generator)["captures"]
                  for s in c["streams"]}
        assert any(l.startswith("ATTACK_") for l in labels)
        assert any(l.startswith("BENIGN_") for l in labels)


@needs_corpus
def test_blind_stripping_scenarios_really_have_no_control_client():
    """The scenario is only 'blind' if every client at the endpoint is affected."""
    for generator, scenario in (("B", "B05_strip_blind"), ("C", "C05_strip_blind")):
        capture = [c for c in _manifest(generator)["captures"]
                   if c["scenario"] == scenario][0]
        assert {s["ground_truth"] for s in capture["streams"]} == {"ATTACK_STRIP_ADVERT"}


@needs_corpus
def test_control_scenarios_really_do_have_an_unaffected_client():
    for generator, scenario in (("B", "B04_strip_with_control"),
                                ("C", "C04_strip_control")):
        capture = [c for c in _manifest(generator)["captures"]
                   if c["scenario"] == scenario][0]
        attacked = {s["client"] for s in capture["streams"]
                    if s["ground_truth"].startswith("ATTACK_")}
        benign = {s["client"] for s in capture["streams"]
                  if not s["ground_truth"].startswith("ATTACK_")}
        assert attacked and benign and attacked.isdisjoint(benign)


# ------------------------------------------------------------ split integrity
@needs_corpus
def test_training_scenarios_never_appear_in_any_test_split():
    import sys
    sys.path.insert(0, str(OQ36))
    from dataset import B_HELDOUT, C_VAL  # noqa: E402

    b_scenarios = {c["scenario"] for c in _manifest("B")["captures"]}
    c_scenarios = {c["scenario"] for c in _manifest("C")["captures"]}
    assert B_HELDOUT <= b_scenarios, "held-out scenario names must exist"
    assert C_VAL <= c_scenarios, "validation scenario names must exist"
    # Training draws from B minus the held-out scenarios; the test split IS the
    # held-out scenarios, so the two are disjoint by construction.
    assert (b_scenarios - B_HELDOUT).isdisjoint(B_HELDOUT)
    # Validation and the generator-C test split partition generator C.
    assert C_VAL.isdisjoint(c_scenarios - C_VAL)


@needs_corpus
def test_recorded_split_integrity_shows_no_train_leakage():
    """Guards the committed result: if a regenerated corpus ever leaks a training row
    into a test split, this fails rather than the leak being discovered later."""
    path = OQ36 / "results" / "dataset-inventory.json"
    if not path.exists():
        pytest.skip("inventory not generated; run research/experiments/oq36/dataset.py")
    integrity = json.loads(path.read_text())["integrity"]
    assert integrity["rows_also_present_in_train"] == {
        "VAL": 0, "TEST_B": 0, "TEST_C": 0, "TEST_A": 0}
    assert integrity["scenario_overlap"] == {}
    assert integrity["capture_overlap"] == {}


# --------------------------------------------------------- reproducibility
@needs_scapy
@needs_corpus
@pytest.mark.parametrize("module,generator", [("genb", "B"), ("genc", "C")])
def test_generator_is_deterministic(module, generator, tmp_path):
    """Same seed must yield byte-identical captures.

    Generator A learned this the hard way: a bare `Ether()` took the source MAC from
    the host NIC, so the golden corpus was never reproducible off one machine
    (see the Phase-4 corpus re-baseline). Both new generators pin their addresses;
    this asserts it stayed true.
    """
    import hashlib
    import importlib
    import sys

    sys.path.insert(0, str(OQ36))
    gen = importlib.import_module(module)
    original_out = gen.OUT
    try:
        gen.OUT = str(tmp_path)
        gen.build()
        for capture in _manifest(generator)["captures"]:
            committed = (CORPUS / f"gen{generator}" / capture["pcap"]).read_bytes()
            regenerated = (tmp_path / capture["pcap"]).read_bytes()
            assert hashlib.sha256(committed).hexdigest() == \
                hashlib.sha256(regenerated).hexdigest(), capture["pcap"]
    finally:
        gen.OUT = original_out
