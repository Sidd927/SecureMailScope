"""
Narrow, safe adapter around the tshark CLI (ADR-0001).

Responsibilities ONLY: locate tshark, check version, invoke it safely on an untrusted
PCAP, map its exit behaviour to a typed outcome, and stream structured packet records.
NO security/business logic lives here (docs/architecture, Phase-11 §12/13). Downstream
code depends on this adapter's typed output, never on raw tshark JSON.

Security (Phase-1 §14):
  - argument ARRAY only; never shell=True; never string-interpolated commands.
  - the PCAP path is validated (exists, is a regular file, within size ceiling).
  - subprocess timeout; bounded behaviour on malformed input.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterator, List, Optional

from securemailscope.config import Config


class DissectStatus(str, Enum):
    OK = "OK"                  # exit 0, >=1 packet
    EMPTY = "EMPTY"            # exit 0 but 0 packets (verified: empty file reads cleanly)
    TRUNCATED = "TRUNCATED"    # exit 14: cut short mid-packet; partial packets usable
    MALFORMED = "MALFORMED"    # exit 3 / not a capture format
    MISSING = "MISSING"        # file does not exist
    TIMEOUT = "TIMEOUT"        # subprocess exceeded timeout
    TOO_LARGE = "TOO_LARGE"    # exceeds configured size ceiling
    ERROR = "ERROR"            # any other non-zero exit


class TsharkNotFound(RuntimeError):
    pass


class TsharkVersionError(RuntimeError):
    pass


@dataclass
class DissectResult:
    status: DissectStatus
    packets: List[dict] = field(default_factory=list)
    packet_count: int = 0
    stderr: str = ""
    tshark_version: str = ""

    @property
    def usable(self) -> bool:
        """True when packets are worth analysing. TRUNCATED is usable (partial), but the
        caller must mark the capture truncated. EMPTY is NOT usable."""
        return self.status in (DissectStatus.OK, DissectStatus.TRUNCATED) and self.packet_count > 0


_VER_RE = re.compile(r"TShark .*?(\d+)\.(\d+)\.(\d+)")


class TsharkAdapter:
    def __init__(self, config: Optional[Config] = None):
        self.cfg = config or Config.load()
        self._version: Optional[str] = None

    # ---- discovery / version ------------------------------------------------
    def version(self) -> str:
        if self._version is not None:
            return self._version
        try:
            out = subprocess.run(
                [self.cfg.tshark_path, "--version"],
                capture_output=True, text=True, timeout=30,
            )
        except FileNotFoundError as e:
            raise TsharkNotFound(f"tshark not found at {self.cfg.tshark_path!r}") from e
        except subprocess.TimeoutExpired as e:
            raise TsharkNotFound("tshark --version timed out") from e
        m = _VER_RE.search(out.stdout or "")
        if not m:
            raise TsharkVersionError("could not parse tshark version")
        major, minor, patch = (int(g) for g in m.groups())
        if major < self.cfg.tshark_min_major:
            raise TsharkVersionError(
                f"tshark {major}.{minor}.{patch} < required {self.cfg.tshark_min_major}.x"
            )
        self._version = f"{major}.{minor}.{patch}"
        return self._version

    # ---- dissection ---------------------------------------------------------
    def dissect(self, pcap_path: str) -> DissectResult:
        """Run tshark over an untrusted PCAP and return a typed result."""
        if not os.path.exists(pcap_path):
            return DissectResult(DissectStatus.MISSING, stderr="file does not exist")
        if not os.path.isfile(pcap_path):
            return DissectResult(DissectStatus.MISSING, stderr="not a regular file")
        size = os.path.getsize(pcap_path)
        if self.cfg.max_capture_bytes and size > self.cfg.max_capture_bytes:
            return DissectResult(DissectStatus.TOO_LARGE,
                                 stderr=f"{size} bytes exceeds ceiling {self.cfg.max_capture_bytes}")

        ver = self.version()  # raises TsharkNotFound / TsharkVersionError if unusable

        # -T ek : newline-delimited JSON, one record per packet -> streamable, bounded memory.
        cmd = [self.cfg.tshark_path, "-r", pcap_path, "-T", "ek"]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.cfg.tshark_timeout_s,
            )
        except subprocess.TimeoutExpired:
            return DissectResult(DissectStatus.TIMEOUT, tshark_version=ver,
                                 stderr=f"tshark exceeded {self.cfg.tshark_timeout_s}s")

        packets = list(self._parse_ek(proc.stdout))
        count = len(packets)
        stderr = (proc.stderr or "").strip()

        if proc.returncode == 0:
            status = DissectStatus.OK if count > 0 else DissectStatus.EMPTY
        elif proc.returncode == 14:
            status = DissectStatus.TRUNCATED
        elif proc.returncode == 3:
            status = DissectStatus.MALFORMED
        else:
            status = DissectStatus.ERROR
        return DissectResult(status, packets, count, stderr, ver)

    @staticmethod
    def _parse_ek(stdout: str) -> Iterator[dict]:
        """Yield packet layer records from -T ek output. Each packet is an {'index':...}
        line followed by a {'timestamp':..., 'layers':...} line; we keep the latter."""
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip index/control lines that aren't packet records
            if isinstance(obj, dict) and "layers" in obj:
                yield obj
