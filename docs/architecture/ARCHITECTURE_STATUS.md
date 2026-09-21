# ARCHITECTURE_STATUS

**Phase:** 11 (Architecture) — **complete, awaiting approval before implementation.**
**Date:** 2026-09-16 · Navigation/state doc — read this first, then the one relevant architecture doc.

---

## 1. Document map

| Doc | Status |
|---|---|
| [00-requirements-baseline](00-requirements-baseline.md) | 🟢 Locked |
| [01-system-architecture](01-system-architecture.md) | 🟢 Draft for approval |
| [02-architecture-options](02-architecture-options.md) | 🟢 Decided (tshark) |
| [03-data-model](03-data-model.md) | 🟢 Draft for approval |
| [04-evidence-provenance](04-evidence-provenance.md) | 🟢 Locked (contract) |
| [05-ai-anomaly-design](05-ai-anomaly-design.md) | 🟡 Design + experiment plan (model unselected) |
| [06-threat-model](06-threat-model.md) | 🟢 Draft for security-reviewer |
| [07-test-architecture](07-test-architecture.md) | 🟢 Draft |
| [08-demo-architecture](08-demo-architecture.md) | 🟢 Draft for demo-reviewer |
| [requirements-traceability](requirements-traceability.md) | 🟢 Live — all confirmed reqs mapped |
| [11-session-reconstruction](11-session-reconstruction.md) | 🟢 Implemented (Phase 3) |
| [12-security-analysis](12-security-analysis.md) | 🟢 Implemented (Phase 4) |
| [13-rule-catalog](13-rule-catalog.md) | 🟢 Live (rules v1.0) |
| [14-cross-session-reasoning](14-cross-session-reasoning.md) | 🟢 Implemented (Phase 5) |
| [15-cross-session-rule-catalog](15-cross-session-rule-catalog.md) | 🟢 Live (cross rules v1.0) |
| [16-ml-anomaly-architecture](16-ml-anomaly-architecture.md) | 🟢 Implemented (Phase 6) |
| [17-ml-model-evaluation](17-ml-model-evaluation.md) | 🟢 Live (outcome D, ADR-0015) |
| [18-ml-model-catalog](18-ml-model-catalog.md) | 🟢 Live (robust-z-sum retained) |
| [19-evidence-fusion-and-posture](19-evidence-fusion-and-posture.md) | 🟢 Implemented (Phase 7) |
| [21-backend-persistence-api](21-backend-persistence-api.md) | 🟢 Implemented (Phase 8) |
| [22-forensic-reporting](22-forensic-reporting.md) | 🟢 Implemented (Phase 9) |
| ADR 0001–0021 | 0001–0005,0007–0009,0011–0021 Accepted · 0006,0010 Proposed · **0007 superseded by 0017** · **0009 renderer amended by 0020** |

## 2. Locked decisions

Dissection = tshark (ADR-0001) · EvidenceField wrapper + 6 states (ADR-0002/04) · session+STARTTLS
state machine in our engine (ADR-0003) · versioned standards-bound rules (ADR-0004) · cross-session as
first-class layer (ADR-0005) · ~~SQLite per-run + FS artifacts (ADR-0007)~~ → **one SQLite catalog +
canonical assessment stored as a document + FS artifacts (ADR-0017, supersedes 0007)** · backend job
lifecycle distinct from `RunStatus`, pass-through API (ADR-0018) · report is a projection, not an
engine (ADR-0019) · PDF composed from the report model with ReportLab (ADR-0020, closes OQ-40) ·
report is a pure function of its assessment, `report_sha256` identity (ADR-0021) · one canonical report → 3
renderers (ADR-0009) · modular monolith Python/FastAPI (ADR-0011) · AI optional/read-only/grounded,
`--no-ai` identical findings (ADR-0008).

## 3. Two-lane invariant

Security lane (deterministic: rules + cross-session + risk) produces all facts/verdicts. Anomaly lane
(ML) produces only scores. They meet only at prioritisation via an explicit policy (ADR-0007-risk).
ML/AI never writes a finding or changes a fact.

## 4. Open (non-blocking) questions

OQ-26 local-LLM packaging · OQ-29 NAT identity · OQ-30 contrast-rule default · OQ-31/32 evidence
inferences · OQ-33r real-server corpus · OQ-38 tshark output mode · ~~OQ-40 offline PDF renderer~~ **(closed, ADR-0020)** ·
OQ-41 SPA framework. All deferred to their implementation phase.

**Closed by Phase 6 (ADR-0015, docs 16–18):** OQ-36 (model selection) — no candidate wins on
detection; `robust-z-sum` ships as a prioritisation signal. OQ-37 (complementary value) — **closed
negative**: zero unique true detections on all three held-out splits.

**Closed by Phase 7 (ADR-0016, doc 19):** A-01, A-03, A-04, A-05, R-01, R-02 implemented and
demonstrated end to end; the posture score was selected over two alternatives on 60 captures.

**Phase 7 hardening (2026-09-20):** OQ-46 **FIXED** (truncated sessions are classified and
excluded from baselines; the Phase-5 guard is live). OQ-47 **FIXED** (segmented capability lines
recovered from the reassembled EHLO response; three root causes, one of them in our own
normalizer). OQ-33r **PASS WITH LIMITATIONS** (10/10 real Postfix and Dovecot captures across
3 protocols and 4 TLS modes agree with an independent tshark read; two vendors, loopback only,
populations too small to exercise cross-session reasoning). Phase 7 is COMPLETE WITH EXPLICIT
LIMITATIONS and ready for Phase 8. Details: docs/research/22 and 23.

**Phase 8 (2026-09-21, in implementation):** backend, persistence and API on branch
`phase/08-backend-persistence-api`, branched from `v0.2.0-phase7`. Adds no security capability:
it orchestrates the existing engines and serves the canonical `PostureAssessment` unaltered.
ADR-0007 superseded by ADR-0017; lifecycle and API fixed by ADR-0018. Design: doc 21.
Audit finding — **no production callable went PCAP → `PostureAssessment`** before Phase 8; the only
end-to-end composition was a helper inside `tests/test_posture_corpora.py`.

**Phase 9 (2026-09-21):** forensic reporting on branch `phase/09-reporting`,
branched from `v0.3.0-phase8`. Renders the canonical assessment as HTML and PDF; adds no security
capability. **OQ-40 closed** by ADR-0020: WeasyPrint, wkhtmltopdf, Chromium, Playwright and every
other candidate were measured absent; ReportLab 5.0.1 + pypdf 6.19.0 verified working on Python
3.9.6 with byte-deterministic output under `invariant=1`. Design: doc 22.
**R-03 and R-05 move to COMPLETE** — the first requirement completions since Phase 7 —
on demonstrated behaviour: three formats served, semantic equivalence asserted across
them, artefacts content-addressed and integrity-verified. Visual QA found and fixed two
real layout defects. No A- or D- requirement changed; Phase 9 adds no detection.

**Opened by Phase 9:** OQ-54 — should the projection expose a stable section-id vocabulary for
Phase-10 deep-linking? OQ-55 — revisit HTML→PDF for visual fidelity if a browser engine ever
becomes a supported dependency, accepting the loss of byte determinism? OQ-56 — detached-signing
reports once a key-management story exists.

**Opened by Phase 8:** OQ-51 — do cross-capture trend queries justify a derived read-model
(rebuilt from documents, never written independently)? OQ-52 — is synchronous in-request analysis
acceptable for large captures, or must the ADR-0011 background-job path be exercised before the
demo? OQ-53 — should `force=true` retain both assessments when engine versions differ?

**Opened by Phase 7:** OQ-48 **closed** (scoring formula selected). OQ-49 — recalibrate severity
weights against real traffic (blocked on OQ-33r). OQ-50 — should recurrence count distinct
endpoints rather than sessions, once NAT identity (OQ-29) is resolved?

**Opened by Phase 6:** OQ-45 — does real multi-vendor traffic change the ML answer? Unanswerable on
synthetic corpora: the feature space is 98.6 % separable by generator (17 §10). Blocked on OQ-33r.
OQ-46 — `Completeness.TRUNCATED` is never assigned by the pipeline, making the Phase-5 comparability
guard dead code (16 §9.1). OQ-47 — TCP-segmented multi-line SMTP replies can lose `STARTTLS` (16 §9.2).

## 5. Stop conditions status (Phase-11 §36)

None triggered: every confirmed PS requirement maps (traceability); AI/ML has a defensible, empirical
plan (05); no decision recorded without comparison (ADRs); no security claim unevidenced. The one item
that *would* trigger — "implementation about to begin before approval" — is why this phase **stops here**.

## 6. Decisions requiring human approval

1. **tshark as the hard dependency** (ADR-0001) — acceptable for offline SIH deployment? (bundling plan exists.)
2. ~~**ML fallback stance** (ADR-0006 / 05 §5)~~ — **resolved by evidence, Phase 6.** The bake-off
   showed exactly the fallback case: ML qualifies only as a secondary prioritisation signal. Shipped
   on that basis with the limitation stated (ADR-0015). Remaining question for the owner: is that
   acceptable to present as the A-02 answer at SIH? (Recommended: yes — the honest negative result
   is stronger than an unsupported detection claim, and the evaluation rigour is itself the story.)
3. **Contrast-rule default OFF** (ADR-0005 / OQ-30) — precision/recall policy: default off, on when a
   control endpoint exists. Confirm.
4. **Optional LLM included at all** (ADR-0008) — build the analyst NL layer, or ship deterministic-only
   for the SIH prototype and keep LLM as documented future work? (Recommended: deterministic core first,
   LLM only if time permits.)
5. **SPOC internal deadline** (non-architecture, but gating) — confirm it is not before 30 Sep.
