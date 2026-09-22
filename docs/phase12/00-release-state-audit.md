# Phase 12 — 00. Release-state audit

**Date:** 2026-09-22 · **Branch:** `phase/12-sih-final-audit` (from `v0.6.0-phase11`)
**Purpose:** reconstruct exactly what the released system is, with nothing assumed from memory.

> **File-organisation note.** The Phase-12 brief names 15 documents (`00`–`14`) explicitly. Several
> of its numbered sections (§7 capability map, §9 judge-visibility test, §11 scene selection, §16
> security-claim audit, §18 remaining-work analysis, §19 candidate ledger, §20/§21 D-11/A-02
> deep-dives, §23 performance, §25 slide evidence plan, §30 demo bundle, §31 freeze strategy) do not
> carry their own `Create:` filename. Each is folded into the numbered doc it most naturally
> extends, noted inline where it lands, so nothing in the brief is dropped and nothing is
> fragmented into trivial single-purpose files.

---

## 1. Release identity — independently re-verified

| | |
|---|---|
| Tag | `v0.6.0-phase11` (annotated, tag object `166d7b65…`) |
| Release commit | `c5352de3b59690bbe3f3192468c9651d10b7dc54` |
| Previous release | `v0.5.0-phase10` = `2d5594a8…` |
| `main` | frozen at `2fd5f093…` = **Phase 3** (session reconstruction) — confirmed by `git merge-base --is-ancestor v0.1.0-phase1 main`; `main` has never advanced past the first three phases |
| Phase-12 branch | `phase/12-sih-final-audit`, created `git switch --create … v0.6.0-phase11`, confirmed ancestor |
| Working tree | clean |
| Total commits on the release lineage | 57 |
| **Today** | **2026-09-22** (system clock; cross-checked against the last commit timestamp `2026-09-22 06:53:27 +0530`) |
| **Deadline** | **2026-09-30**, per `docs/research/19-authoritative-ps-verification.md`, retrieved from the official SIH portal | 
| **Days remaining** | **8** |

**FACT worth surfacing prominently, not burying:** `main` is not the released system. Anyone
evaluating this project by cloning the repository and staying on the default branch sees **only
Phase 3** — no analysis rules, no posture engine, no backend, no reports, no dashboard. This is a
deliberate invariant carried since Phase 8 ("do not touch `main`"), correct for engineering
discipline, but it is also a **submission-presentation risk** if the SIH submission or a judge's
clone points at the default branch rather than `v0.6.0-phase11`. Flagged in full in
`04-demo-reliability.md` and `13-final-engineering-decision.md`; not fixed here, because thawing
`main` is a policy decision, not an audit finding — see that document for the recommendation.

## 2. Environment, reconstructed by direct measurement

| | Measured value |
|---|---|
| Python | 3.9.6 |
| tshark | 4.6.8 (Wireshark) |
| Collected tests | 1219 |
| Test run (3× full suite) | 1219 passed / 0 failed / 0 skipped / 0 xfail, each run |
| Core runtime dependencies | **zero** — importing `ingest`, `session`, `analysis`, `crosssession`, `posture`, `ml`, `crypto.*` pulls in only Python stdlib modules (verified by module-set diff before/after import) |
| Optional extras | `backend` (fastapi, pydantic, uvicorn, python-multipart), `reporting-pdf` (reportlab), `test-backend` (httpx), `test-reporting` (pypdf), `dev` (pytest) |
| Dashboard runtime dependencies | **zero npm packages**, no build step — static ES modules served by the FastAPI app |
| Source size | 84 Python files, 16,107 lines in `src/securemailscope/`, 41 test files |
| Cold-start timings (measured this phase) | `AnalysisService()` construction 3.8 ms · full PCAP→assessment (`submit_path`) 123–277 ms per capture · `fastapi`+`uvicorn`+`pydantic` import 175 ms · `create_app()` 67 ms · `reportlab` import 4.6 ms |
| Docker | referenced only by `research/experiments/` probe scripts (certificate-fixture generation); **not** a runtime dependency of the shipped system |

No performance concern exists for a live demo: the entire pipeline, from a cold Python process to a
rendered assessment, completes in well under half a second per capture. This closes §23 of the
brief without further investigation — see `04-demo-reliability.md` for the full write-up.

## 3. Architecture, as released

```
dissect/    tshark adapter + raw field normalisation, no interpretation
  |
crypto/     (Phase 11) cipher-suite/OID reference tables, key-exchange and
            certificate derivation -- facts, never verdicts
  |
session/    SMTP/IMAP/POP3 state machines -> SessionEvidence (Phase 3)
  |
analysis/   16 deterministic, standards-bound rules -> SecurityFinding (Phase 4, +8 in Phase 11)
  |
crosssession/  3 rules over per-server baselines (>=5 comparable sessions) -> CrossSessionFinding (Phase 5)
  |
ml/         unsupervised anomaly model (robust-z-sum), secondary signal only (Phase 6)
  |
posture/    evidence fusion, F2-group-damped scoring, prioritisation, remediation
            -> the canonical PostureAssessment (Phase 7)
  |
backend/    SQLite catalogue, job lifecycle, content-addressed artifacts, FastAPI /api/v1 (Phase 8)
  |
reporting/  one ReportDocument -> JSON (native) / HTML (zero-dep) / PDF (reportlab) (Phase 9)
  |
dashboard/  Python projection -> 4-screen static ES-module console (Phase 10)
```

Nineteen standards-bound rules total: 16 single-session (`SEC-TLS-00{1,2,3}`, `SEC-STLS-00{1,2,3}`,
`SEC-PLAIN-00{1,2}`, `SEC-KEX-001`, `SEC-FS-001`, `SEC-CERT-00{1..5}`, `SEC-CFG-001`) + 3
cross-session (`CS-STARTTLS-00{1,2}`, `CS-TLS-001`).

Six evidence states, never collapsed: `OBSERVED · INFERRED · UNKNOWN · AMBIGUOUS · INCOMPLETE ·
NOT_OBSERVABLE`. Five provenance values, only `observed` and `none` ever emitted:
`observed · inherited · historical · retrieved · decrypted · none`.

## 4. Capability map (brief §7)

What the released system can actually do, verified against source and tests rather than asserted.

| Capability | What it does | Evidence it rests on | What it cannot establish | Where a judge sees it |
|---|---|---|---|---|
| PCAP ingest + validation | SHA-256 identity, malformed/empty/truncated/too-large classification via tshark exit codes | `dissect/tshark.py`, `test_tshark_adapter.py` (10 tests, now deterministic) | nothing about the traffic itself — a structural gate only | dashboard History screen; report identity block |
| Protocol reconstruction | SMTP/IMAP/POP3 state machines, explicit + implicit TLS, on standard **and** non-standard ports | `session/`, `P_*` regression suite | intent of the client/server, only observed protocol behaviour | Findings screen, per-session evidence |
| STARTTLS / STLS reasoning | advertisement / request / acceptance tracked separately; an absent advertisement is `AMBIGUOUS`, never `False` | `SEC-STLS-001/002/003`; 01B prior-art research | whether an absent advertisement is stripping or genuine non-support **within one session** — resolved only by cross-session evidence | Scene A (inversion) |
| TLS handshake / version / cipher | `TlsEvidence`, `SEC-TLS-001/002` against RFC 8996 + NIST SP 800-52r2 | golden TLS1.0/1.1/1.2 fixtures | completion when only a partial handshake was captured — reported as such, not assumed | Findings screen |
| Key exchange (D-09) | suite name (≤1.2) or ServerHello `key_share` group (1.3); closed-world table | `crypto/keyexchange`, `SEC-KEX-001`, 43 crypto tests | anything for a suite not in the reference table — `AMBIGUOUS`, never guessed | Findings screen |
| X.509 extraction (D-10) | full chain from a cleartext handshake; attribution enforced only where field cardinality proves it | `crypto/certificates`, `SEC-CERT-001` | anything when TLS 1.3 encrypts the Certificate message or a session resumes | Findings/Evidence screens |
| Certificate chain structure (D-11) | ordering, AKI↔SKI linkage, self-signed detection | `SEC-CERT-005` | **trust or revocation** — RFC 5280 §6 needs a trust anchor a PCAP has none of; OCSP/CRL are network transactions | Evidence screen, honesty scene |
| Certificate expiry/key/signature (D-12/13/14) | evaluated against **capture timestamp**, never wall-clock; RSA length from modulus; SHA-1/MD5 flagged by RFC 9155 | `SEC-CERT-002/003/004` | anything on a certificate not visible in the capture | Findings screen |
| Forward secrecy (D-17) | TLS 1.3 ⇒ `INFERRED True` (RFC 8446); ≤1.2 ⇒ `OBSERVED` from suite; static ECDH correctly distinguished from ephemeral ECDHE | `SEC-FS-001` | nothing — never `False` without an observed handshake | Findings screen |
| Insecure configuration (D-16) | declared, versioned 7-item checklist; unevaluated items are `NOT_OBSERVABLE`, never a false pass | `SEC-CFG-001` | any condition outside the 7 declared items | Findings screen |
| Cross-session reasoning | per-server baselines (≥5 comparable sessions), 3 rules distinguishing configuration from stripping | `crosssession/`, doc 14/15 | anything on captures with too few sessions to baseline — states so | Scene A |
| ML anomaly lane | unsupervised `robust-z-sum`, bounded to ±4.0 against a 30-point severity-tier gap, never emits a finding | `ml/`, ADR-0015/0024 | detection — zero unique true detections on every held-out split measured | Overview ML panel, `--no-ai` scene |
| Evidence fusion / posture scoring | `F2-group-damped`; only `OBSERVED_ISSUE` penalises; band withheld below 50% assessed coverage | `posture/scoring`, `posture/fusion` | a verdict when coverage is too thin — reports `INSUFFICIENT_EVIDENCE` instead | Overview screen |
| Provenance | every evidence reference carries frame numbers, stream key, timestamp, evidence state, provenance | `analysis/model.EvidenceRef` (Phase 11 addition) | nothing not present in the reference itself | Evidence screen, JSON/HTML/PDF reports |
| Persistence / artifact integrity | SQLite catalogue, content-addressed artifacts, re-hashed on access, tamper detected | `backend/`, doc 21 | nothing about capture authenticity before ingest | History screen, `?verify=true` |
| Reporting (JSON/HTML/PDF) | one `ReportDocument`, byte-deterministic, `report_sha256` identity, semantic equivalence asserted across all three | `reporting/`, doc 22 | nothing the assessment itself does not carry | report download links |
| Dashboard (4 screens) | History / Overview / Findings / Evidence; computes no security conclusion itself | `dashboard/`, doc 23 | packet-level drill-down — deliberately absent, the assessment carries none | live in the demo |
| `--no-ai` equivalence | identical findings with AI on/off, asserted end to end through the real API | `test_scene_c_no_ai_equivalence_across_the_whole_stack` | — this is proof, not a claim | Scene C |

## 5. Real-PCAP and synthetic corpus, inventoried

| Corpus | Location | Content | Role |
|---|---|---|---|
| Golden synthetic corpus | `research/experiments/oq28/pcaps/` | 25 PCAPs + `ground_truth.json`, covering STARTTLS advertise/strip/decline, implicit TLS, TLS 1.0/1.1/1.2, prompt-injection payload, control-endpoint pairing | unit/regression tests; source for the pre-existing demo-scene design (doc 08) |
| Real multi-vendor corpus (OQ-33r) | `research/experiments/oq33r/out/` | 10 real Postfix + Dovecot captures, SMTP/IMAP/POP3, cleartext/STARTTLS/implicit/plaintext | primary real-world validation; Phase-11 regression baseline (byte-identical scores to Phase 10) |
| Phase-11 certificate fixtures | `research/experiments/p11cert/out/` | 3 generated TLS 1.2 captures on port 465: healthy chain, self-signed leaf, RSA-1024/SHA-1 leaf | the **only** corpus that exercises D-10–D-14, because all 10 real captures are TLS 1.3 |
| ML bake-off corpora | `research/experiments/oq36/corpus/` | genB (17), genC (18) synthetic, independently authored generators | ADR-0015 evaluation; measured 98.6% generator-separability |

No pre-rendered report artifacts (HTML/PDF) exist anywhere in the repository yet — reports are
generated on demand in well under 100 ms, so this is not a latency problem, but it is a genuine gap
for a packaged, offline demo bundle. See `10-demo-environment.md`.

## 6. Known open questions carried into Phase 12

From `docs/phase11/06-final-audit.md` §7, unchanged by this audit (an audit does not resolve them —
only new evidence or engineering can):

| ID | Status |
|---|---|
| OQ-04 | trust store / enterprise internal CAs — open, the reason D-11 is PARTIAL |
| OQ-45 | does real multi-vendor traffic change the ML answer — open, corpus cannot discriminate (100% TLS 1.3, 100% forward secret) |
| OQ-58 | inherited certificate provenance for TLS 1.2 resumption — deferred, no corpus |
| OQ-59 | is OCSP stapling visible/usable in a cleartext handshake — not measured, not claimed |
| OQ-60 | can real TLS ≤1.2 mail traffic be obtained — open, stated limitation, asserted by a test |
| OQ-61 | would a varied-quality TLS 1.2 corpus give the ML lane real variance — deferred, would re-create the authorship leak |

## 7. Limitations, carried forward without softening

- `main` frozen at Phase 3 (§1, above) — a presentation risk, not a technical one.
- D-11: chain structure only; trust and revocation not observable from passive PCAP alone.
- A-02: real unsupervised capability shipped and evaluated; zero demonstrated detection value on
  any corpus this project holds, including the Phase-11 certificate/key-exchange features.
- The real corpus (10 captures) is 100% TLS 1.3 and cannot exercise the certificate family at all —
  D-10–D-14 validation rests on 3 generated fixtures, not real-world traffic.
- No pre-rendered demo artifacts exist; a fully offline, zero-setup demo bundle does not yet exist.
- README is stale in two places: it says "Phases 1–10 implemented" (should read through Phase 11)
  and does not mention the Phase-11 certificate/key-exchange capabilities at all.
