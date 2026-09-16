"""Phase-1 capture metadata + hashing tests (docs/architecture/04 §4)."""
import os

from securemailscope.evidence import Capture, sha256_file

GOLDEN = "research/experiments/oq28/pcaps/C_normal_tls.pcap"


def test_same_file_same_hash():
    assert sha256_file(GOLDEN) == sha256_file(GOLDEN)


def test_changed_bytes_change_hash(tmp_path):
    a = tmp_path / "a.bin"; a.write_bytes(b"hello")
    b = tmp_path / "b.bin"; b.write_bytes(b"hellp")
    assert sha256_file(str(a)) != sha256_file(str(b))


def test_hash_matches_known_corpus_value():
    # From craft.py / capinfos: C_normal_tls sha256 begins 0095d7d66336e45d
    assert sha256_file(GOLDEN).startswith("0095d7d66336e45d")


def test_capture_from_file_is_content_addressed():
    cap = Capture.from_file(GOLDEN, tool_versions={"tshark": "4.6.8"})
    assert cap.capture_id == cap.sha256
    assert cap.filename == "C_normal_tls.pcap"
    assert cap.size_bytes == os.path.getsize(GOLDEN)
    assert cap.packet_count is None  # not yet dissected
    assert cap.tool_versions["tshark"] == "4.6.8"


def test_with_dissection_is_immutable_enrichment():
    cap = Capture.from_file(GOLDEN)
    enriched = cap.with_dissection(packet_count=84, truncated=False)
    assert cap.packet_count is None          # original unchanged
    assert enriched.packet_count == 84
    assert enriched.sha256 == cap.sha256


def test_missing_file_raises(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        Capture.from_file(str(tmp_path / "nope.pcap"))
