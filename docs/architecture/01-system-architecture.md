# 01 — System Architecture

**Status:** Draft for approval. **Date:** 2026-09-16
**Depends on:** 00 (requirements), 02 (dissection = tshark), 03 (data model), 05 (ML), ADRs 0001–0011.

---

## 1. Principle

Deterministic security reasoning is the ground truth. ML adds an independent anomaly signal. The AI
analyst layer is optional and read-only. Evidence provenance is preserved end-to-end. Everything runs
offline and reproducibly.

## 2. Pipeline (validated hypothesis from Phase-11 §4, adjusted)

```
 PCAP/PCAPNG
     │  (capture hashed on ingest — SHA-256, immutable source ref)
     ▼
[1] Dissection            tshark → structured per-frame output          (ADR-0001)
     ▼
[2] Evidence Normalization    tshark fields → canonical evidence schema  (03, ADR-0002)
     ▼
[3] Session Reconstruction    frames → TCP streams → email sessions      (ADR-0003)
     │                        STARTTLS/STLS state machine per session
     ▼
[4] Deterministic Security Engine   rules bound to RFC 8996/NIST/RFC 3207 (ADR-0004)
     │      → findings (severity, evidence refs, provenance, NOT_OBSERVABLE)
     ▼
[5] Cross-Session / Temporal Reasoning   baselines, control-endpoint,    (ADR-0005)
     │      abstention (INSUFFICIENT_HISTORY)   ← validated 02A/02B
     ▼
[6] ML Anomaly Detection    unsupervised, cross-session deviation features (05, ADR-0006)
     │      → anomaly_score / band / feature_contributions  (SEPARATE lane)
     ▼
[7] Risk / Posture / Prioritization   deterministic policy; ML influences  (ADR-0007)
     │      priority only via an explicit, testable rule
     ▼
[8] Canonical Report Object  → JSON / HTML / PDF  (one model, 3 renderers) (ADR-0009)
     ▼
[9] Dashboard   (analyst workflow views)                                   (ADR-0010)
     ▼
[10] Optional Analyst AI   NL query/explain over structured evidence       (10B, ADR-0008)
```

**Two-lane invariant (the core of the design):** stages [4]/[5]/[7] are the *security lane* and
produce all facts and verdicts. Stage [6] is the *anomaly lane* and produces only scores. They meet
only at [7], through a documented policy, and [6] can never write a finding or change a fact.

## 3. Components

| # | Component | Responsibility | Determinism |
|---|---|---|---|
| 1 | `ingest` | hash capture, invoke tshark, validate format | deterministic |
| 2 | `evidence` | map tshark output → canonical schema with states | deterministic |
| 3 | `sessions` | TCP + email session reconstruction; STARTTLS state machine | deterministic |
| 4 | `rules` | versioned deterministic security rules → findings | deterministic |
| 5 | `crosssession` | baselines, control-endpoint contrast, abstention | deterministic |
| 6 | `mlanomaly` | unsupervised anomaly scoring over deviation features | seeded/reproducible |
| 7 | `risk` | posture score, prioritisation policy | deterministic |
| 8 | `report` | canonical report → JSON/HTML/PDF | deterministic |
| 9 | `dashboard` | analyst UI (reads report/evidence API) | — |
| 10 | `analyst_ai` | optional grounded NL query/explanation | non-deterministic, read-only |

## 4. Data flow & storage

Artifacts (PCAP, reports) on the filesystem, keyed by capture hash. Structured evidence, sessions,
findings, baselines, anomaly scores in **SQLite** (ADR-0007-storage) — one DB per analysis run for
reproducibility and easy sharing. Every row carries `analysis_version`, `rule_version`,
`model_version` for forensic reproducibility (§19 research / 04).

## 5. Deployment shape

**Modular monolith**, Python + FastAPI (ADR-0011). Analysis runs synchronously for small captures;
large captures run as a background job with progress polling (no external queue/broker). Frontend is a
static SPA served by the same app. Entire system runs on one workstation, offline. `--no-ai` disables
stages [6]-optional-influence and [10] with **identical security findings** (testable diff).

## 6. What this architecture deliberately is NOT

No microservices, message broker, Kubernetes, Redis, or cloud dependency (none justified — 22/23).
No custom TCP/TLS/X.509 parsing (ADR-0001). No LLM in the security path (10B). No DNS/SPF/DKIM path.

## 7. Traceability

Every PS requirement → component → test → demo evidence in
[requirements-traceability.md](requirements-traceability.md). Open architecture decisions needing human
approval are listed in [ARCHITECTURE_STATUS.md](ARCHITECTURE_STATUS.md) §Approval.
