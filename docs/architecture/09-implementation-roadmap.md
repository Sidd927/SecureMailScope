# 09 — Implementation Roadmap

**Status:** Draft — **implementation does not begin until Phase-11 is approved.** **Date:** 2026-09-16

Phased so each stage is independently testable and builds on a validated predecessor. Ordering may
adjust after approval. Each phase lists its exit gate.

| Phase | Deliverable | Exit gate |
|---|---|---|
| **1 Foundation** | repo skeleton, evidence schema (03), SQLite layer, capture hashing, versions, CI running the golden-corpus regression harness (seeded) | schema round-trips; reproducibility test green |
| **2 Ingest & dissection** | tshark adapter (ADR-0001), evidence normalization, tshark version check | OQ-28 pcaps parse; field-drift regression green |
| **3 Session reconstruction** | TCP→email sessions, STARTTLS/STLS state machine (3 protocols, implicit+explicit) | A/B/C/J/P_* regression reproduce 02B facts |
| **4 Deterministic security engine** | versioned standards-bound rules (ADR-0004), evidence states, NOT_OBSERVABLE for 1.3/resumed | per-rule unit tests; weak-crypto + TLS1.3 golden |
| **5 Cross-session reasoning** | baselines, time-aware history, control-endpoint, abstention (ADR-0005) | reproduce 02A/02B FP reduction on golden corpus |
| **6 ML experiment** | diversity-controlled corpus (needs OQ-33r), model bake-off (05 §5), metrics report | a model selected OR documented "secondary-signal only" |
| **7 ML integration** | chosen model as separate lane; `feature_contributions`; `--no-ai` flag | `--no-ai` vs full: identical findings (diff test) |
| **8 Risk/posture/prioritization** | coverage-aware posture, deterministic prioritisation + ML-influence policy (ADR-0007-risk) | policy unit tests; posture reproducible |
| **9 Reports** | canonical report → JSON/HTML/PDF (ADR-0009), escaping | render round-trip; XSS adversarial test |
| **10 Dashboard** | analyst views (21); reads report/evidence API | e2e smoke on demo corpus |
| **11 Optional analyst AI** | grounded NL query/explain (ADR-0008) — only if approved & time permits | injection + citation-validator tests |
| **12 Security hardening** | threat-model mitigations (06); security-reviewer pass | security-reviewer findings resolved |
| **13 Performance** | benchmark methodology (25); optimise hot paths | documented numbers, no fabrication |
| **14 Demo hardening** | frozen demo corpus, precomputed fallback (08) | demo-reviewer pass; offline dry-run |

**Critical path to a defensible SIH submission:** 1→2→3→4→5→8→9→10 (deterministic core + reports +
dashboard). Phases 6–7 (ML) and 11 (LLM) are parallelisable and gated on OQ-33r / approval; the core
must stand without them (`--no-ai`). Phase 6 depends on the real-server corpus, so start OQ-33r early.
