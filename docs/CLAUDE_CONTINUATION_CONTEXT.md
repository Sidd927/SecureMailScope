# SecureMailScope — Claude Continuation Context

**Purpose:** orient a fresh Claude Code session with no prior conversation history.
Every fact below was read from this repository. Where detail is needed, this file points
at the authoritative document rather than repeating it.

**Written:** 2026-09-20 at `v0.2.0-phase7`. **Updated 2026-09-22** through Phase 10. The phase map
below stops at Phase 7 — **for Phases 8–12, read `docs/phase11/06-final-audit.md` and
`docs/phase12/01-final-requirements-audit.md` first.** Current release: **`v0.6.0-phase11`**
(`c5352de3`). Phase 12 (`docs/phase12/`) was a documentation-only SIH readiness audit — no
production source changed. Phase 12/finalization work lives on `phase/finalization`.

---

## Project

| | |
|---|---|
| SIH problem statement | **SIH26159** |
| Title | SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications |
| Organization | National Technical Research Organisation (NTRO) |
| Category / Theme | Software / Blockchain & Cybersecurity |
| Deadline | **30 September 2026** |

Verified against the live official portal — `docs/research/19-authoritative-ps-verification.md`
is the source of truth and outranks any other statement of scope in this repo.

**Scope is a passive-PCAP transport-security problem.** A mechanical term search of the
official PS text finds **zero** occurrences of `spf`, `dkim`, `dmarc`, `dns`, `dane`,
`mta-sts`, `bimi`, `s/mime`, `pgp`, `phishing` or `blockchain`. Do not add domain-
authentication features; two audited competitor repos made exactly that mistake.

## Git baseline

| Ref | Commit |
|---|---|
| `main` | `2fd5f0939c6773ba110cbe39e10a86bff2deaca3` (= Phase 3) |
| Phase-7 tag | `v0.2.0-phase7` → `9b3e6e4` |
| Phase-8 tag | `v0.3.0-phase8` → `a46781a` |
| Phase-9 tag | `v0.4.0-phase9` → `0019c6f` |
| Phase-10 branch | `phase/10-dashboard` (untagged pending review) |

Remote: `git@github.com:Sidd927/SecureMailScope.git`

**Phases 4, 5, 6 and 7 are NOT merged into `main`.** Each phase lives on its own branch;
`main` deliberately still points at Phase 3. Do not merge without being asked.

## Phase map

| Phase | Branch | Commit / tag | Contribution | In `main`? |
|---|---|---|---|---|
| Research + architecture | — | `f6cd544`, `470b430` | 15 research docs, 17 ADRs, architecture 00–19 | ✅ |
| 1 — foundation | — | tag `v0.1.0-phase1` = `8e8a288` | `EvidenceField`, `Capture`, `TsharkAdapter` | ✅ |
| 2 — ingest + dissection | `phase/02-ingest-dissection` | `36eb16b` | `analyze_capture()`, `FrameEvidence`, tshark boundary | ✅ |
| 3 — session reconstruction | `phase/03-session-reconstruction` | `2fd5f09` | `SessionEvidence`, SMTP/IMAP/POP3 state machines | ✅ (= `main`) |
| 4 — deterministic analysis | `phase/04-deterministic-security-engine` | `28ed634` | `SecurityFinding`, 8 standards-bound rules | ❌ |
| 5 — cross-session reasoning | `phase/05-cross-session-reasoning` | `16b130b` | `CrossSessionFinding`, baselines, contrast, 3 rules | ❌ |
| 6 — ML anomaly lane | `phase/06-ml-anomaly-detection` | `2db283c` | `MLAnomalyResult`, feature layer, model bake-off | ❌ |
| 7 — fusion + posture | `phase/07-evidence-fusion-posture` | `9b3e6e4` / `v0.2.0-phase7` | `PostureAssessment`, fusion, scoring, prioritisation, remediation, hardening | ❌ |

## Current architecture

```
PCAP → tshark → normalization → session reconstruction
     → deterministic security analysis
     → cross-session reasoning
     → (optional) ML prioritisation signal
     → evidence fusion → risk classification → posture scoring
     → prioritisation → remediation
     → PostureAssessment          ← canonical output
```

Packages under `src/securemailscope/`: `evidence`, `dissect`, `ingest`, `session`,
`analysis`, `crosssession`, `ml`, `posture`.

## Canonical contracts

| Object | Module | Role |
|---|---|---|
| `EvidenceField` | `evidence/states.py` | value + state + basis + provenance + frames. The correctness backbone |
| `SessionEvidence` | `session/model.py` | reconstructed session; Phase-4/5 input contract |
| `SecurityFinding` | `analysis/model.py` | deterministic conclusion; severity/status/standards/evidence refs |
| `CrossSessionFinding` | `crosssession/model.py` | comparison conclusion + baseline/contrast provenance |
| `MLAnomalyResult` | `ml/contract.py` | score, band, attribution. **No severity, no status** |
| **`PostureAssessment`** | `posture/model.py` | **the canonical output** |

Six evidence states, all semantically distinct and never collapsed:
`OBSERVED · INFERRED · UNKNOWN · AMBIGUOUS · INCOMPLETE · NOT_OBSERVABLE`.

## Phase-7 final state

Implemented and tested: canonical posture contracts · evidence fusion · fact-kind
separation · finding deduplication · contradiction handling · risk classification ·
posture scoring · prioritisation · remediation · standards traceability · evidence
coverage · abstention handling · ML secondary-signal integration · `--no-ai`
equivalence · provenance preservation.

**Scoring** (`posture/scoring.py`, formula `F2-group-damped`, selected over two
alternatives on 60 captures — ADR-0016):

```
score = 100 − Σ over penalising issue groups of
               weight(severity) × min(2.0, 1 + log2(recurrence)/4)
```

`INFO 0 · LOW 3 · MEDIUM 12 · HIGH 28 · CRITICAL 55`
Bands: `STRONG ≥90 · ADEQUATE ≥75 · WEAK ≥50 · CRITICAL <50 · INSUFFICIENT_EVIDENCE`.

> These weights and thresholds are **transparent engineering policy, not a calibrated
> measurement**. They were chosen so one CRITICAL leaves ADEQUATE and one MEDIUM does
> not, and validated for behaviour, not derived from incident data.

Only `OBSERVED_ISSUE` penalises. `COMPLIANT` gives no credit. Below
`MIN_ASSESSED_FRACTION = 0.5` the numeric score stands but the **band is withheld**
as `INSUFFICIENT_EVIDENCE`.

**Validation:** 443 tests, 0 failed, 0 skipped, 0 xfail.

## ML boundary — read before touching anything in `ml/`

Phase 6 ran a leakage-controlled bake-off over three generators with generator- and
scenario-held-out splits (`docs/architecture/17-ml-model-evaluation.md`, ADR-0015).

> **Outcome D: no candidate produced a single unique true detection on any held-out
> split.** The feature space is 98.6 % separable by generator, so the synthetic corpus
> cannot settle the question at all.

The retained model `robust-z-sum` is a **SECONDARY PRIORITISATION SIGNAL ONLY**.

ML **may** contribute a bounded ordering nudge (`MAX_ML_ADJUSTMENT = 4.0`, smaller than
the narrowest severity tier gap of 30, so it can never cross a tier) and populate
`model_summary`.

ML **may not**: determine a security fact · set or change severity · create a finding ·
penalise the score · identify an attacker · prove STARTTLS stripping · override
deterministic evidence · turn UNKNOWN into OBSERVED.

`--no-ai` produces byte-identical score, band, penalising groups, standards and
remediation. AST tests enforce that `posture/` cannot import the ML engine or feature
layer, and that `ml/` cannot import `posture/`.

## Requirements

| Req | Status |
|---|---|
| A-01 risk classification | **COMPLETE** |
| A-02 anomaly detection | **PARTIAL** — capability exists, **detection value not demonstrated** |
| A-03 posture scoring | **COMPLETE** |
| A-04 prioritisation | **COMPLETE** |
| A-05 remediation | **COMPLETE** for implemented issue classes |
| R-01 prioritised findings | **COMPLETE** |
| R-02 posture assessment | **COMPLETE** |
| R-03 JSON/PDF/HTML | **PARTIAL** — JSON only; PDF/HTML are Phase 9 |
| R-05 forensic reports | **PARTIAL** — data complete, no rendered artefact |

Authoritative detail (including incomplete D-requirements such as X.509 D-10…D-14):
`docs/architecture/requirements-traceability.md`. **Do not inflate these statuses.**

## Real-world validation (OQ-33r)

**10 / 10 scenarios passed**, each cross-checked against an independent tshark raw-byte
read. Vendors: **Postfix, Dovecot**. Protocols: **SMTP, IMAP, POP3**. TLS modes:
**cleartext, STARTTLS, implicit, none**.

Demonstrated on real vendor traffic: TLS 1.3 extraction via `supported_versions` ·
STARTTLS/STLS handling · a server genuinely not advertising correctly reported
`AMBIGUOUS` (not a confident negative) · plaintext-authentication detection · implicit
TLS reported `NOT_OBSERVABLE`.

**Does not establish:** universal vendor or MTA coverage · WAN behaviour ·
cross-session reasoning on real traffic · attack detection. Verdict recorded as
**PASS WITH LIMITATIONS** — `docs/research/23-oq33r-real-world-validation.md`.

## Known limitations

1. Severity weights and bands are policy, not empirical calibration.
2. Recurrence counts **sessions**, so NAT-collapsed populations under-count affected
   systems (OQ-29).
3. Certificate posture is **observability only** — no chain, expiry or key-strength
   conclusion; impossible passively for TLS 1.3 and resumed sessions.
4. **Cross-session reasoning has never run on real traffic** (real captures carry 1–2
   sessions; baselines need ≥5).
5. **`SEC-TLS-001` has never fired on a real server** — no weak vendor config exercised.
6. Exim image is built but never driven; client diversity limited to Python stdlib.
7. ML generalisation to real traffic is unestablished.
8. Corpora remain predominantly synthetic.

## Architectural rules — non-negotiable

- **Evidence over assumptions.** Every conclusion traces to frames, a rule and a standard.
- **UNKNOWN ≠ SECURE. AMBIGUOUS ≠ SECURE. NOT_OBSERVABLE ≠ SECURE.** Missing evidence
  never becomes a compliant state and never improves a score.
- **Absence of a STARTTLS advertisement is AMBIGUOUS, never stripping.** Proven
  byte-identical at the application layer (`docs/research/02B`).
- **ML cannot create security facts.** See the ML boundary above.
- **A cross-session deviation is not an attack** and never attributes an actor.
- **Duplicate evidence must not double-penalise**; contradictory evidence **fails closed**.
- **`PostureAssessment` is canonical.** Downstream layers consume it and must **not**
  recompute risk, score, severity, aggregation, remediation or ML conclusions. An AST
  test asserts only one scoring path exists in the source tree.
- Never claim attacker identity or intent, certificate validity when unobservable,
  SPF/DKIM/DMARC posture, successful remediation, or ML-discovered attacks.

## Phases 8-10 (added 2026-09-22)

| Phase | Tag | Delivered |
|---|---|---|
| 8 — backend | `v0.3.0-phase8` | SQLite catalog, job lifecycle, artifact store, FastAPI `/api/v1` |
| 9 — reporting | `v0.4.0-phase9` | `ReportDocument`, HTML + PDF renderers, report artifacts. **R-03, R-05 COMPLETE** |
| 10 — dashboard | untagged | analyst console: History / Overview / Findings / Evidence. **R-04 COMPLETE** |

Docs: `architecture/21`, `22`, `23`; ADR-0017…0022. Tests: **1120 passed**, with the
Phase 1-9 baseline of 697 verified intact.

**Still incomplete:** D-09, D-10-14 (X.509), D-16, D-17. **A-02 unchanged** —
capability yes, detection value no.

## Superseded: the Phase-8 plan below (kept for its starting rules)

**PHASE 8 — Backend + Persistence + API. COMPLETE (see above).**

```
PCAP → existing pipeline → PostureAssessment
                                 ↓
                   ┌─────────────┴─────────────┐
               Persistence                    API
                   └─────────────┬─────────────┘
                                 ↓
                 future dashboard / future reports
```

Likely responsibilities (from ADR-0007 storage, ADR-0011 backend): orchestration,
analysis lifecycle, SQLite persistence, artifact management, FastAPI, API schemas,
status/progress, error handling, resource limits, restart/recovery, JSON export,
backend tests.

### Phase-8 starting rule

Start from **`v0.2.0-phase7`**. Do not alter Phase-7 security logic. Consume
`PostureAssessment.to_dict()` and recompute nothing. `assessment_id` is content-addressed
and run-independent, so it is the natural persistence key. Always surface `coverage`
alongside `overall_posture` — the band is already withheld below 50 % assessment, and a
UI showing the band alone would reproduce the misleading claim the design guards against.
Carry `limitations` and `model_summary.role` through to any output.

## Highest-value documents

| Document | Why |
|---|---|
| `docs/SECUREMAILSCOPE_COMPLETE_TEAM_HANDOVER.md` | full 26-section onboarding (written at Phase 5; phase status superseded by this file) |
| `docs/research/19-authoritative-ps-verification.md` | **source of truth for scope and deadline** |
| `docs/architecture/ARCHITECTURE_STATUS.md` | current status, open questions |
| `docs/architecture/requirements-traceability.md` | requirement statuses with evidence |
| `docs/architecture/19-evidence-fusion-and-posture.md` | Phase-7 architecture, 20 sections |
| `docs/architecture/adr/0016-posture-scoring-and-fusion.md` | fusion + scoring decisions, rejected alternatives |
| `docs/architecture/16/17/18-ml-*.md` + `adr/0015` | ML architecture, evaluation, catalog, boundary |
| `docs/research/22-oq46-oq47-validation.md` | Phase-7 hardening fixes and their measured impact |
| `docs/research/23-oq33r-real-world-validation.md` | real-vendor validation and its limits |
| `docs/architecture/adr/0001-0016` | 17 ADRs; every significant decision with alternatives |
| `research/experiments/README.md` | how to reproduce every experiment |

## Commands

```bash
PYTHONPATH=src python3 -m pytest -q          # 443 tests
```

Requires Python ≥3.9 and **tshark** (developed on 4.6.8). The core package has zero
runtime dependencies; `scapy` (corpus generation) and `scikit-learn` (optional ML
candidates) are needed only by experiments. `pip install -e .` is unreliable on the
system pip — use `PYTHONPATH=src`.
