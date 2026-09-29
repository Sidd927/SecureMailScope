# ADR-0007 — SQLite per-run + filesystem artifacts
**Status:** Accepted 2026-09-16 · **SUPERSEDED 2026-09-21 by [ADR-0017](0017-backend-storage-supersession.md)**

> Superseded in part. Written three phases before `PostureAssessment` existed. The
> per-run database and the shredding of findings/anomaly scores into tables are
> **withdrawn** — the latter would create a second, independently-writable representation
> of a security conclusion, which ADR-0016 forbids. SQLite-over-PostgreSQL and
> filesystem artifacts are **retained**. Read ADR-0017 for the current decision.

**Context** Single-analyst offline forensic tool; moderate data; reproducibility and shareability matter.
**Options** SQLite · PostgreSQL · analytical formats (parquet/duckdb) · filesystem only.
**Decision** One SQLite DB per analysis run (keyed by capture hash) for structured
evidence/sessions/findings/baselines/anomaly scores; PCAP + rendered reports on filesystem.
**Rejected** PostgreSQL (server dependency, over-engineered for one workstation); pure filesystem (no
query); parquet/duckdb (analytical, not needed at prototype scale).
**Consequences** + zero-config, portable, one-file provenance, offline. − limited concurrency (fine for target).
**Risks** very large captures stress SQLite → background job + size guard; revisit duckdb only if a benchmark demands it.
**Open questions** OQ-39 revisit at enterprise scale post-benchmark (25).
