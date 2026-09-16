# 01D — SIH26159 Competitor Source Audit

**Method:** Direct source inspection. No capability credited from a README.
**Status:** Complete (v1) · **Date:** 2026-09-16
**Headline:** Of four "surviving differentiators" from 01C, **three are implemented by competitors**.
One survives, verified absent from all five codebases: **cross-session reasoning**. Separately,
**every competitor's AI is either a report rewriter or a rules engine laundered through ML** — which
reframes OQ-21 entirely.

---

## 1. Repositories audited

| Repo | Code files | Largest modules | Assessment |
|---|---|---|---|
| **soumyajit-cys/CipherPost** | 65 py | `rules.py` 19 KB, `reassembly.py` 13 KB, `handshake.py` 13 KB, `generate_corpus.py` 31 KB, `ml_engine.py` 245 ln | **Most complete + most intellectually honest** |
| **saravana-rr0411/SecureMailScope** | 78 | `crypto_risk_scorer.py` 36 KB (+46 KB tests), `certificate_analyzer.py` 30 KB, `posture_engine.py` 18 KB, `capture_agent/` | **Broadest scope** — includes live capture agent + Windows service |
| **ArpitSingh-01/Prahari-** | 67 | `reports/builder.py` 65 KB, `tls_parser.py` 18 KB, `sessions.py` 15 KB, `rules.py` 15 KB, `gen_traffic.py` 34 KB | **Best rules engine** — proper standards citations |
| **gouravsehlangia/SecureMailScope** | 39 | `pipeline.py` 32 KB, `handshake_parser.py` 20 KB, `starttls_detector.py` 14 KB, `cipher_suites.py` 18 KB | **Best STARTTLS/STLS state machine** |
| **shashwat4130/MailRakhwala** | 23 | `schemas/domain.py` 7 KB; most files 0–2 KB, many empty | 🔴 **Skeleton.** No PCAP parsing. `domain.py` suggests the doc 01 §8 DNS-scope error |
| **kris-5710, 13-saksham, fredfe08** | — | — | Thin or README-only (01C §6.2); `fredfe08` has SPF/DKIM/DMARC checkers = scope error |

---

## 2. Capability matrix

`VERIFIED` = source evidence cited · `PARTIAL` = present but limited · `CLAIMED ONLY` = README, not code ·
`NOT FOUND` = grep/inspection found nothing

| Capability | CipherPost | Prahari | saravana | gourav | MailRakhwala |
|---|---|---|---|---|---|
| PCAP ingest + reassembly | ✅ `reassembly.py` | ✅ `sessions.py` | ✅ | ✅ `reassembler.py` | ❌ NOT FOUND |
| SMTP state | ✅ | ✅ | ✅ | ✅ | ❌ |
| IMAP state | ✅ (strip fixture) | ✅ | ✅ | ✅ | ❌ |
| **POP3 / STLS** | 🟡 1 mention, **in a comment** | 🟡 `sessions.py` ×3 | 🟡 ×1 rules, ×3 posture | ✅ **VERIFIED** — `POP3_STLS_ADV/CMD/OK/ERR` regexes | ❌ |
| **STARTTLS stripping** | ✅ `rule_starttls_strip` | ✅ ×1 rules, ×2 sessions | ❌ NOT FOUND in rules | ✅ `StarttlsStatus.STRIPPED_DOWNGRADE` | ❌ |
| Implicit TLS (465/993/995) | 🟡 `is_starttls` flag | 🟡 | 🟡 | ✅ **VERIFIED** — explicit Case 1 branch | ❌ |
| Cleartext credentials | ✅ `rule_ssl_in_plaintext` | 🟡 | ✅ `is_confirmed_plaintext_payload` | ✅ `POP3_USER_PASS` regex | ❌ |
| Command/response injection | 🟡 1 mention | ❌ NOT FOUND | ❌ | ❌ | ❌ |
| TLS version/cipher/KEX | ✅ | ✅ | ✅ | ✅ `cipher_suites.py` 18 KB | ❌ |
| Certificate analysis | ✅ `certificates.py` | ✅ + `gen_certs.py` | ✅ 30 KB | ✅ `cert_analysis/` | ❌ |
| **TLS 1.3 awareness** | ✅ ×6 | ✅ ×4–5 | 🟡 ×2 | ❌ **ZERO mentions** | ❌ |
| **Session resumption** | ❌ **ZERO** | ✅ **VERIFIED** — `sess.resumed and not sess.ems` → CFG-006 | ❌ ZERO | ❌ ZERO | ❌ |
| **Observability / NOT_OBSERVABLE** | ❌ **ZERO** | ❌ ZERO | ✅ **VERIFIED** — `security_posture="NOT_OBSERVABLE"`, `score_confidence`, `session_completion` | ❌ ZERO | ❌ |
| **Cross-SESSION reasoning** | ❌ | ❌ | ❌ (`correlate_session_evidence` is cross-**layer**, single session) | ❌ | ❌ |
| Cross-layer correlation (1 session) | 🟡 | 🟡 | ✅ **VERIFIED** | 🟡 | ❌ |
| Posture scoring | ✅ | ✅ weighted rules | ✅ `posture_engine.py` | ✅ | ❌ |
| Report generation | ✅ `generator.py` | ✅ **65 KB** `builder.py` | ✅ 100 KB `reportGenerator.js` | ✅ | ❌ |
| ML | ✅ HistGB + IsolationForest + SHAP | 🟡 claimed | ✅ RandomForest | 🟡 anomaly flag | ❌ |
| **LLM** | ❌ none found | ❌ | ❌ | ✅ **Cerebras `llama3.1-8b`** | ❌ |
| Test corpus generator | ✅ 31 KB | ✅ 34 KB `gen_traffic.py` | 🟡 | ✅ `generate_test_pcaps.py` | ❌ |

---

## 3. The three differentiators we lost

01C §7 listed four surviving differentiators. Source inspection kills three.

### 3.1 ❌ Evidence-observability discipline — **saravana has it**

`backend/app/posture/posture_engine.py`:

```python
score_confidence = "HIGH"
if protocol == "UNKNOWN" and not tls_detected:
    base_score = 0
    score_confidence = "LOW"
    security_posture = "NOT_OBSERVABLE"
...
elif not tls_detected and not has_confirmed_plaintext:
    # Incomplete capture / insufficient evidence
    score_confidence = "LOW"
    security_posture = "INCOMPLETE"
...
session_completion = "COMPLETE" if (...) else ("INCOMPLETE" if tls_detected else "NOT_OBSERVED")
```

An explicit **`NOT_OBSERVABLE`** posture, a **`score_confidence`** dimension, a **`NOT_OBSERVED`**
completion state, and `is_confirmed_plaintext_payload()` separating *confirmed* from *inferred*
plaintext. **This is the core of our #1 differentiator, implemented.**

⚠️ It is *coarser* than Delgado's framework — no per-property provenance, no `not_applicable` vs
`ambiguous` vs `contradictory`, no TLS 1.3 certificate-unobservability handling (only 2 TLS 1.3
mentions in the whole engine). So a rigour gap remains. **But "we tier evidence and they don't" is
now false**, and must never be said.

### 3.2 ❌ POP3 / STLS coverage — **gouravsehlangia has it**

`starttls_detector.py` (297 lines) — the most complete STARTTLS implementation found anywhere,
including in the production tools of 01B/01C:

```python
POP3_STLS_ADV = re.compile(rb"\bSTLS\b", re.IGNORECASE)
POP3_STLS_CMD = re.compile(rb"^\s*STLS\r?\n", re.IGNORECASE | re.MULTILINE)
POP3_STLS_OK  = re.compile(rb"^\+OK.*\r?\n", ...)
POP3_STLS_ERR = re.compile(rb"^-ERR.*\r?\n", ...)
POP3_USER_PASS = re.compile(rb"USER\s+(\S+)\s*\r?\n.*?PASS\s+(\S+)", ...)
```

Plus an explicit implicit-TLS branch (*"Case 1: Direct / Implicit TLS (SMTPS, IMAPS, POP3S)"*),
a multi-fact model (`advertised_by_server`, `accepted_by_server`, `downgrade_detected`),
`StarttlsStatus.STRIPPED_DOWNGRADE`, and cleartext credential detection across all three protocols.

**All three protocols, both STARTTLS and implicit TLS. Our #2 differentiator is gone.**

⚠️ Its weakness is elsewhere: **zero TLS 1.3 references** in the module, and it is regex-over-payload
rather than true state-machine reconstruction — fragile against TCP segmentation, pipelining and
multiple STARTTLS attempts.

### 3.3 ❌ Resumption-aware reasoning — **Prahari has it**

`backend/app/pipeline/rules.py` — a properly structured rule registry with severity, weight,
category, **standards citation** and remediation:

```python
rule("CFG-006", "Session resumption without extended master secret", "medium", 10,
     "config", "RFC 7627 (EMS); Triple-Handshake attack literature",
     "Require the extended_master_secret extension for resumption.")
rule("CFG-007", "Insecure renegotiation observed", "high", 20, "config", "RFC 5746", ...)
...
if sess.resumed and not sess.ems:      _add(sess, out, "CFG-006", {})
if sess.reneg_seen and not sess.secure_renegotiation: _add(sess, out, "CFG-007", {})
```

RFC 7627 (EMS) and RFC 5746 (secure renegotiation) with Triple-Handshake attribution is **more
sophisticated citation discipline than Zeek's shipped `weak-keys.zeek`** (01B §3.1). Their
certificate rules cite CA/Browser Forum Baseline Requirements including the 2026 ≤47-day validity
change — current knowledge, not stale.

**Our #3 differentiator is gone.** ⚠️ Narrow though: resumption is handled as an EMS *rule*, not as
an *evidence-availability* problem (resumed session ⇒ no certificate ⇒ certificate properties
unobservable). That specific link is still absent everywhere.

---

## 4. The one that survives

### ✅ Cross-session reasoning — VERIFIED ABSENT from all five

Grepped every engine for `for sess in`, `all_sessions`, `group_by`, `across.*session`, `per_server`,
`by_server`, `correlat`:

| Repo | Result |
|---|---|
| CipherPost | No cross-session logic |
| Prahari | None (the `baseline` hits are *"CA/Browser Forum Baseline Requirements"* — a **false positive in my own earlier grep**, corrected here) |
| saravana | `correlate_session_evidence(session)` — docstring: *"cross-layer correlation across protocol, STARTTLS, TLS, and X.509 certificate evidence"* — **one session, multiple layers.** Not cross-session. |
| gourav | Per-session only |
| MailRakhwala | N/A |

**Every competitor reasons one session at a time.** This is the last capability-level gap, and it is
the one that unlocks the 01B §7.2 epistemics problem: *pure omission of a STARTTLS advertisement is
indistinguishable from genuine non-support **within a single session**, but becomes resolvable when
the same server is observed offering STARTTLS on another connection in the same capture.*

**Classification: TECHNICAL DIFFERENTIATION + PRODUCT DIFFERENTIATION. Not research novelty** —
cross-session correlation is standard practice in NSM (Zeek's `known-certs`, Arkime's session
search). It is novel *for this problem*, which is a much weaker claim and must be stated that way.

---

## 5. Part 4 — CipherPost deep dive

**Architecture.** FastAPI backend: `parsing/` (reassembly → tls_records → handshake → certificates →
rules) → `ml/` (features → ml_engine) → `reporting/generator.py`. Also a `live/` package (capture,
streams, alerts, ticketing) — so they target live capture too, beyond the PS's PCAP scope.

**`SessionAnalysis`** carries `session_id`, `protocol`, `five_tuple`, `is_starttls`, `tls_version`,
`negotiated_version_name`, `cipher`, `cipher_meta`, `cipher_iana`, `cipher_strength`,
`client_hello`, `server_hello`, plus `saw_starttls_offer`, `started_tls`, `tls_bytes`.

**Robustness of the `saw_starttls_offer` / `started_tls` / `tls_bytes` model — findings:**

| Case | Handled? |
|---|---|
| Capability stripping | ✅ `rule_starttls_strip` fires |
| Implicit TLS | ✅ `is_starttls` flag distinguishes |
| TLS 1.2 / TLS 1.3 | ✅ version constants present |
| **POP3 STLS** | ❌ no STLS regex/state |
| **Session resumption** | ❌ zero handling |
| **Temporary-error stripping** (`454`) | ❌ no distinct rule |
| **Command / response injection** | ❌ |
| **Multiple STARTTLS attempts** | ❌ booleans cannot represent a sequence |
| **Failed upgrade vs. never attempted** | ⚠️ conflated — see below |

⚠️ **Two defects worth learning from, not repeating:**

1. **Double-firing.** `rule_ssl_in_plaintext` triggers on `not started_tls and not tls_bytes`;
   `rule_starttls_strip` triggers on `saw_starttls_offer and not started_tls and not tls_bytes`.
   A stripped session satisfies **both**, producing a CRITICAL and a HIGH finding for one event.
2. **Benign/attack conflation at CRITICAL severity.** The rule cannot distinguish *"attacker
   stripped the advertisement"* from *"client saw the offer and chose not to upgrade"* (a
   misconfigured client, or opportunistic TLS behaving as designed). Both are reported CRITICAL
   *"Possible STARTTLS stripping"*. The word "Possible" is honest; **CRITICAL** is not. This is
   precisely the benign/attack discrimination problem from 01B §5 row 6 — **and it is exactly what
   cross-session baselining (§4) would resolve.**

**Intellectual honesty — credit where due.** `ml_engine.py` opens with:

> *"IMPORTANT DESIGN NOTE: initial labels come from the deterministic rules engine on the labeled
> corpus. This means the ML model is partially learning..."*

They document their own circularity. That is better practice than most of the field, and we should
match or exceed it.

---

## 6. Parts 5 & 8 — source-level AI audit

**No competitor's AI performs a function deterministic rules cannot.** Traced execution paths:

### gouravsehlangia — LLM as report rewriter, cloud-dependent

`ai_recommendations.py` (169 lines): `POST` to Cerebras, model **`llama3.1-8b`**, 5 s timeout,
`CEREBRAS_API_KEY` from env, response cached.

🔴 **The prompt hardcodes the conclusion before the model sees it:**

```python
if <anonymous kex>:   severity_hint = "The single most severe issue is the ANONYMOUS KEY EXCHANGE — ..."
elif <expired cert>:  severity_hint = "The single most severe issue is the EXPIRED CERTIFICATE — ..."
elif <deprecated tls>:severity_hint = "The single most severe issue is the DEPRECATED TLS VERSION — ..."
```

Severity ranking is a deterministic if/elif chain; the LLM only phrases it. And if no API key is
present, a template fallback (`parts: List[str]`, string concatenation) produces the same content.
**By their own code, the AI is removable with no loss of security function.**

⚠️ It also **requires network egress**, breaking the offline/air-gapped requirement (I-01/A-02) that
the PS's forensic framing implies.

### saravana — RandomForest trained on self-generated synthetic archetypes

`crypto_risk_scorer.py` (882 lines): `RandomForestClassifier`, `MODEL_NAME =
"CryptoRisk-RandomForestClassifier"`, persisted via joblib.

```python
def generate_controlled_training_data(n_samples: int = 2500, seed: int = 42):
    """Generates a reproducible, controlled synthetic training dataset ..."""
...
"training_dataset": "controlled-whole-session-cryptographic-archetypes-v2"
```

🔴 **This is doc 01 §6.3 Trap 2, shipped.** Training labels come from synthetic archetypes the team
constructed from their own rules. The forest learns to reproduce that generator; its reported
`confidence` (ensemble class probability) measures agreement with their own synthetic data, **not
real-world risk**. It is a rules engine laundered through ML, with added opacity. Unlike CipherPost,
**the circularity is not disclosed.**

### CipherPost — honest, but still circular

`HistGradientBoostingClassifier` + `IsolationForest` + `CalibratedClassifierCV`, SHAP contributions,
`classification_report`/`roc_auc_score`. Labels from their own rules engine — **documented in the
source**. No LLM found in the ML or rules modules.

### Summary

| Repo | AI type | Grounded? | Offline? | Necessary? |
|---|---|---|---|---|
| gourav | Cloud LLM (llama3.1-8b) | Prompt-fed, conclusion pre-decided | ❌ **No** | ❌ Has a template fallback |
| saravana | RandomForest on synthetic | Circular, **undisclosed** | ✅ | ❌ Reproduces its own rules |
| CipherPost | HistGB + IForest + SHAP | Circular, **disclosed** | ✅ | ❌ Approximates its own rules |
| Prahari | Claimed | — | — | Not located in source |

> 🎯 **The OQ-21 finding.** AI is *not* a differentiator — everyone has it. But **everyone's AI is
> epistemically empty**, and two of three are plainly so. The differentiation available is not
> "we have AI" or "we have no AI", but **"our AI does something that provably cannot be done
> deterministically, and we state exactly what and why."** Developed in
> [10A-ai-opportunity-validation.md](10A-ai-opportunity-validation.md).

---

## 7. Part 9 — hypothesis re-ranking

| | Hypothesis | Verdict | Type |
|---|---|---|---|
| **H0** | STARTTLS detection novelty | ❌ **REJECTED** | — (4 competitors + 2002–2025 literature) |
| **H1** | Cross-protocol STARTTLS state reconstruction | ❌ **REJECTED** | gourav covers SMTP+IMAP+POP3 + implicit TLS |
| **H2** | Integrated email crypto posture | ❌ **REJECTED** | All four are exactly this |
| **H3** | Evidence-linked analyst reporting | ❌ **REJECTED** | Prahari 65 KB builder, saravana 100 KB generator |
| **H4** | Offline/air-gapped | ⚠️ **PARTIALLY SURVIVES** | **Product.** gourav breaks it with a cloud LLM; others are offline by default. Weak, but a real discriminator against at least one competitor |
| **H5** | AI-assisted analyst reasoning | ⚠️ **PARTIALLY SURVIVES — reframed** | **Product.** Not "have AI" but "have *honest, grounded* AI". See §6 and doc 10A |
| **H6** | Forensic timeline reconstruction | 🟡 **UNRESOLVED** | Not found in competitor source; standard DFIR practice generally. Check Prahari's 65 KB report builder before claiming |
| **H7** | **Cross-session posture aggregation** | ✅ **SURVIVES** | **Technical + Product.** Verified absent from all five (§4). *Not research novelty* |
| **H8** | Deterministic engine + AI analyst layer | ⚠️ **PARTIALLY SURVIVES** | **Product.** Architecturally what CipherPost approximates; nobody enforces the boundary rigorously |
| **H9** | Protocol-security evidence graph | 🟡 **UNRESOLVED** | Not found in competitors. ⚠️ Risk of being decorative — must earn its place by enabling H7, not by looking impressive |

**Nothing here is RESEARCH NOVELTY.** H7 is the only clean technical survivor.

---

## 8. Part 10 — why a strong competitor could still beat this

| # | Objection | Evidence | Severity | Mitigation | Unresolved? |
|---|---|---|---|---|---|
| 1 | Wrapper perception | Extraction layer is commodity (01C §5) | High | Be explicit that value is in judgement/evidence layer | 🟠 Yes |
| 2 | Commodity detection | 4 competitors have STARTTLS strip detection | **High** | Compete on correctness, not existence | 🟠 Yes |
| 3 | AI shoehorning | §6 — everyone's AI is empty | High | Doc 10A: justify or omit, and say which | 🟠 Yes |
| 4 | Shallow PCAP analysis | gourav uses regex-over-payload, not state machines | Medium | Do real state reconstruction | 🟢 Mitigable |
| 5 | Insufficient novelty | H0–H3 all rejected | **High** | Stop claiming novelty; claim correctness | 🟠 Yes |
| 6 | False positives | CipherPost double-fires and conflates benign/attack at CRITICAL (§5) | Medium | Cross-session baselining (H7) | 🟢 Mitigable — **and this is our strongest concrete argument** |
| 7 | TLS 1.3 limitations | 01A §2 | Medium | Observability discipline | 🟢 Mitigable |
| 8 | Session resumption | Prahari ahead of us today | Medium | Link resumption → cert unobservability (nobody does this) | 🟢 Mitigable |
| 9 | Incomplete protocol coverage | gourav already covers all 3 | **High** | Must match as table stakes | 🟠 Yes |
| 10 | Competitor speed | CipherPost started 2026-09-01, pushed daily | **High** | We have **zero code** and ~4–14 days | 🔴 **Yes — severe** |
| 11 | Deployment complexity | saravana ships a Windows capture agent + service | Medium | Stay scoped to PCAP per the PS | 🟢 Mitigable |
| 12 | Demo complexity | Competitors have working dashboards | High | Demo must show *correctness*, not features | 🟠 Yes |
| 13 | No real-world validation | All corpora are synthetic, ours included | Medium | Ground-truth framework + honest disclosure | 🟠 Yes |
| 14 | Zeek dependency | OQ-20 undecided | Medium | Hybrid lean | 🟠 Yes |
| 15 | LLM dependency | gourav's failure mode | Low | Offline-only; no cloud calls | 🟢 Mitigated |
| 16 | **Competitors are further along in every dimension** | §1–2 | 🔴 **Severe** | Narrow scope; do fewer things correctly | 🔴 **Yes** |
| 17 | Derivative appearance | All submissions will look alike | **High** | H7 is the only structural difference available | 🟠 Yes |

**Objections 10 and 16 are the real threat, and they are not technical.** Four teams have working
code; we have research documents. That is a deliberate trade — the research has already prevented
two scope errors that competitors made (`fredfe08` and `MailRakhwala` both drifted toward DNS/domain
scope) — but the trade only pays if we now convert.

---

## 9. Part 12 — competition analysis

**What the average competitor is building:** PCAP → TCP reassembly → protocol ID → STARTTLS
detection → TLS handshake parse → X.509 validation → rule-based weak-crypto findings → ML risk score
→ 0–100 posture → JSON/HTML/PDF + React dashboard. **This shape is now the default answer to
SIH26159.** Expect most submissions to look like this.

**What the strongest are building:** the same, plus — CipherPost: live capture, calibrated ML with
SHAP, corpus generator, honest methodology notes. Prahari: a properly cited rules catalogue (RFC
7627/5746/8996, CA/B Forum), 65 KB report builder. saravana: observability states, cross-layer
correlation, a Windows capture agent. gourav: the most complete STARTTLS/STLS coverage.

**Where they all overlap:** everything above.
**Where they differ:** which *one* dimension each took further.
**Would ours look derivative?** **Yes — unless it does something structurally different.** On current
evidence the only structurally different thing available is **cross-session/longitudinal reasoning
(H7)**, because it changes what questions the tool can answer, not merely how well it answers the
same ones.

⚠️ **No competitor has everything.** Each is strong in one dimension and absent in others — nobody
combines gourav's protocol coverage, Prahari's citation rigour, saravana's observability states and
CipherPost's ML honesty. Assembling all four *plus* H7 is a coherent, defensible position. It is
**integration and correctness**, not novelty, and must be described that way.

---

## 10. Part 13 — comparison experiment specification

Not executable here (no lab, and running competitor code requires their dependency stacks).
**Specification:**

**Corpus:** the 14 captures from 01B §10.1 (T1–T14), generated via `striptls` (CC0-1.0).

**Systems under test:** `tshark` · `zeek` · `suricata` + ET · Arkime · CipherPost · gouravsehlangia ·
Prahari · saravana.

**Per capture × system, record:** findings produced · severity assigned · evidence offered
(packet/frame traceability?) · protocol coverage · **false positives against known ground truth** ·
explanation quality · posture output.

**Predicted results, stated in advance so they are falsifiable:**

| Capture | Prediction |
|---|---|
| T4 SMTP stripping | Zeek `tls=F` only; Suricata silent; CipherPost + gourav both detect |
| T3/T6 **POP3 STLS** | Zeek/Suricata/CipherPost produce nothing; **gourav detects** |
| T12 **resumed session** | Only Prahari reasons about it; others report certificate findings as *absent* rather than *unobservable* |
| T11 **TLS 1.3** | gourav degrades silently (zero TLS 1.3 handling); others partially |
| **Benign: client declines a genuine STARTTLS offer** | 🎯 **CipherPost reports CRITICAL "Possible STARTTLS stripping" — a false positive.** No per-session tool can avoid it |

**That last row is the experiment that matters.** It is a single, reproducible test case that
demonstrates the per-session limitation of every competitor and the value of cross-session
baselining — the strongest available evidence for H7, and the strongest possible demo.

---

## 11. Verdicts (Part 14)

1. **Strongest competitor** — **CipherPost** overall (completeness + disclosed methodology). But
   *per dimension*: gourav (STARTTLS/protocol coverage), Prahari (rules rigour + reporting),
   saravana (observability + breadth).
2. **Strongest verified capability** — gourav's `starttls_detector.py`: SMTP+IMAP+POP3 STARTTLS/STLS
   plus implicit TLS, more complete than anything in Zeek, Suricata, Snort, Arkime or NetworkMiner.
3. **Biggest remaining gap** — **cross-session / multi-session reasoning.** Verified absent from all
   five. Directly resolves the benign-vs-attack discrimination failure that every competitor has.
4. **H0–H9** — §7. Only **H7 SURVIVES**; H4/H5/H8 partially; H6/H9 unresolved; H0–H3 rejected.
5. **Do NOT build** — a from-scratch TCP reassembler or TLS dissector; another 0–100 score with
   invented weights; ML trained on our own synthetic labels; any cloud LLM dependency; any novelty
   claim about STARTTLS detection.
6. **Reuse** — `striptls` (CC0-1.0) for corpus; tshark/Zeek for TLS+certs; published rule sources
   (RFC 8996, NIST SP 800-52r2, RFC 7627, RFC 5746) rather than invented severities.
7. **Our value layer** — **cross-session evidence reasoning and correctness**, not extraction and not
   feature count.
8. **Does AI have a legitimate role?** — Not yet established. See doc 10A.
9. **Core or analyst-facing?** — **Analyst-facing only**, on the evidence of §6.
10. **Provisional thesis** — §12 below.
11. **Top 5 unresolved** — OQ-21 (AI role) · OQ-25 (does cross-session reasoning actually reduce
    false positives measurably?) · OQ-20 (Zeek or standalone) · OQ-01 (deadline) · A-01 (PS text).
12. **Next phase** — Phase 10 via doc 10A, then Phase 3.

---

## 12. Part 11 — strongest strategic position

Four candidate theses, tested against the audit:

| Thesis | Verdict |
|---|---|
| *"A passive forensic engine for reconstructing email transport-security state from PCAP."* | ❌ Describes all four competitors |
| *"Converts fragmented network evidence into an auditable email cryptographic posture."* | ❌ Describes CipherPost and Prahari |
| *"A deterministic evidence engine with an AI analyst interface."* | ⚠️ Architecturally what CipherPost approximates; survives only if the boundary is enforced and demonstrated |
| *"Reconstructs the security state of SMTP/IMAP/POP3 conversations and explains why a session is secure or insecure."* | ❌ Per-session framing — exactly what everyone does |

**None survives.** Each describes work already shipped. Provisional thesis built on what actually
survived:

> **SecureMailScope assesses an email *infrastructure* rather than individual sessions. By reasoning
> across every session in a capture, it distinguishes an attack from a configuration choice —
> a distinction no per-session analyzer can make — and reports each finding with its evidence,
> its provenance, and what could not be observed.**

**Why this survives the audit:** cross-session reasoning is verified absent from all five
competitors (§4); it resolves a false-positive class demonstrably present in the strongest
competitor (§5); it is testable with one reproducible capture (§10); and it shifts the unit of
analysis from *session* to *infrastructure*, which is what "enterprise email infrastructures" in the
PS Description actually asks for.

⚠️ **Provisional. Two things could kill it:** if cross-session baselining does not measurably reduce
false positives (**OQ-25** — must be tested, not assumed), or if a competitor adds it in the days
remaining. It is also **integration-grade differentiation, not novelty**, and claiming otherwise
would fail the same scrutiny that just destroyed H0–H3.
