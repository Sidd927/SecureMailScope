# ADR-0007 — SQLite per-run + filesystem artifacts
**Status:** Accepted 2026-09-16
**Context** Single-analyst offline forensic tool; moderate data; reproducibility and shareability matter.
**Options** SQLite · PostgreSQL · analytical formats (parquet/duckdb) · filesystem only.
**Decision** One SQLite DB per analysis run (keyed by capture hash) for structured
evidence/sessions/findings/baselines/anomaly scores; PCAP + rendered reports on filesystem.
**Rejected** PostgreSQL (server dependency, over-engineered for one workstation); pure filesystem (no
query); parquet/duckdb (analytical, not needed at prototype scale).
**Consequences** + zero-config, portable, one-file provenance, offline. − limited concurrency (fine for target).
**Risks** very large captures stress SQLite → background job + size guard; revisit duckdb only if a benchmark demands it.
**Open questions** OQ-39 revisit at enterprise scale post-benchmark (25).
