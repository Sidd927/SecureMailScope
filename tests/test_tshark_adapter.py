"""Phase-1 tshark adapter tests — untrusted-input safety & exit-code mapping (ADR-0001)."""
import os

import pytest

from securemailscope.config import Config
from securemailscope.dissect import (
    TsharkAdapter, DissectStatus, TsharkNotFound,
)

GOLDEN = "research/experiments/oq28/pcaps/C_normal_tls.pcap"

#: Deliberately malformed capture content for test_malformed_file. MUST be fixed, not
#: random: os.urandom(256) previously drove this test, and libwiretap recognises dozens
#: of legacy capture formats with short/loose magic numbers, so random bytes matched one
#: of them and produced a spurious OK roughly 1 in 200-600 runs (verified empirically).
#: That made the test flaky rather than malformed-input handling being wrong.
#:
#: This fixed string was checked against the pcap/pcapng magic numbers (no collision)
#: and driven through tshark 4.6.8 150 times, yielding exit code 3 (MALFORMED) on every
#: run -- and since the content is fixed rather than freshly randomised per run, that
#: result is not a probability to re-verify each time; tshark's format sniffing is a
#: deterministic function of these exact bytes.
MALFORMED_FIXTURE = (
    b"SECUREMAILSCOPE-TEST-FIXTURE: deliberately malformed capture file, "
    b"not a format TShark understands. This is fixed, non-random test data.\n"
)


@pytest.fixture(scope="module")
def adapter():
    return TsharkAdapter()


def _tshark_available() -> bool:
    try:
        TsharkAdapter().version()
        return True
    except Exception:
        return False


needs_tshark = pytest.mark.skipif(not _tshark_available(), reason="tshark not installed")


@needs_tshark
def test_version_parsed():
    v = TsharkAdapter().version()
    assert v.split(".")[0].isdigit()


@needs_tshark
def test_valid_pcap_ok(adapter):
    r = adapter.dissect(GOLDEN)
    assert r.status == DissectStatus.OK
    assert r.usable and r.packet_count == 84


@needs_tshark
def test_empty_file_is_empty_not_ok(adapter, tmp_path):
    p = tmp_path / "empty.pcap"; p.write_bytes(b"")
    r = adapter.dissect(str(p))
    # Critical: exit 0 + 0 packets must NOT read as success (pre-code-review finding).
    assert r.status == DissectStatus.EMPTY
    assert not r.usable


@needs_tshark
def test_malformed_file(adapter, tmp_path):
    p = tmp_path / "junk.pcap"; p.write_bytes(MALFORMED_FIXTURE)
    r = adapter.dissect(str(p))
    assert r.status == DissectStatus.MALFORMED
    assert not r.usable


@needs_tshark
def test_truncated_file_usable_but_flagged(adapter, tmp_path):
    p = tmp_path / "trunc.pcap"
    with open(GOLDEN, "rb") as f:
        p.write_bytes(f.read(60))  # valid header, cut mid-packet
    r = adapter.dissect(str(p))
    assert r.status == DissectStatus.TRUNCATED  # exit 14


def test_missing_file(adapter, tmp_path):
    r = adapter.dissect(str(tmp_path / "nope.pcap"))
    assert r.status == DissectStatus.MISSING
    assert not r.usable


def test_too_large_guard(tmp_path):
    p = tmp_path / "big.pcap"; p.write_bytes(b"\x00" * 1024)
    small_ceiling = Config(max_capture_bytes=512)
    r = TsharkAdapter(small_ceiling).dissect(str(p))
    assert r.status == DissectStatus.TOO_LARGE


def test_missing_tshark_raises():
    bad = Config(tshark_path="/nonexistent/tshark_binary_xyz")
    with pytest.raises(TsharkNotFound):
        TsharkAdapter(bad).version()


@needs_tshark
def test_no_shell_injection_via_filename(adapter, tmp_path):
    # A filename with shell metacharacters must be treated as a literal path (arg array),
    # never interpreted. It simply doesn't exist -> MISSING, no command executed.
    evil = tmp_path / "a; touch /tmp/pwned_$$ .pcap"
    r = adapter.dissect(str(evil))
    assert r.status == DissectStatus.MISSING
    assert not os.path.exists("/tmp/pwned_$$")
