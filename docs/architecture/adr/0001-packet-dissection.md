# ADR-0001 — Packet dissection via tshark (not Zeek, not custom)
**Status:** Accepted 2026-09-16
**Context** Extraction layer is commodity (01C §5); rebuilding TCP/TLS is a poor engineering choice.
**Problem** What parses packets and reassembles streams?
**Options** A tshark · B Zeek · C hybrid · D custom.
**Evidence** 02 decision matrix. tshark is the only single tool fully dissecting SMTP+IMAP+POP3+TLS
(Zeek: no imap.log/pop3.log — 01B §3.1). Proven in 02B: tshark 4.6.8 dissectors recovered every raw
fact we need. tshark gives frame-level granularity (I-03).
**Decision** tshark does dissection + reassembly + TLS/X.509 parsing, consumed as structured output
(`-T ek`/`-T fields`). Our engine builds everything above it.
**Rejected** Zeek (forces us to build IMAP/POP3 anyway); hybrid (double dependency, no added
capability); custom (HIGH-effort reinvention, our toy reassembler in 02B is not production-grade).
**Consequences** + reuse mature parsing, all-protocol coverage, offline, demo-proven. − external
dependency; field-name coupling across versions.
**Risks** version/field drift → mitigate with an adapter + version check + golden-corpus regression;
install friction → bundle/pin + startup check.
**Open questions** OQ-38 tshark output mode (`ek` vs `fields`) for perf — decide at Phase 2 with a benchmark.

---
## Deployment strategy (added on approval, 2026-09-16)
Verified against tshark 4.6.8 on this host:
- **License:** GNU GPL v2-or-later. We invoke tshark as a **subprocess** (no linking) → no license
  contamination of our code.
- **Invocation:** argument **array** via `subprocess` (never `shell=True`, never string interpolation)
  — prevents shell injection from filenames/paths (Phase-1 §14).
- **Exit-code map (verified):** `0` = success; **but `0` + 0 packets = empty capture** (empty file
  reads cleanly) → treat as INCOMPLETE, not success. `3` = not-a-capture / missing file. `14` =
  truncated ("cut short mid-packet") → partial packets usable, mark capture truncated/INCOMPLETE.
  Adapter maps unknown non-zero → hard error with captured stderr.
- **Output mode:** `-T ek` (newline-delimited JSON per packet) for streaming/bounded memory on large
  captures (resolves OQ-38). `-T fields` reserved for targeted extraction.
- **Timeout / resource:** subprocess `timeout=`; kill on expiry; bounded stdout read.
- **Hashing:** SHA-256 computed by **us in Python** (streamed), not delegated to `capinfos`, to keep
  forensic integrity under our control. `capinfos` corroborates in tests only.
- **Version pinning:** startup check asserts `tshark --version` ≥ a documented minimum (4.x); recorded
  in capture metadata as `tool_versions.tshark`. Golden-corpus regression catches field drift.
- **OS:** CLI identical across macOS/Linux/Windows (Wireshark ships tshark on all three); adapter
  resolves the binary via PATH or a configured path.
