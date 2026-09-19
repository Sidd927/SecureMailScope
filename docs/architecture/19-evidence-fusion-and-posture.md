# 19 — Evidence Fusion and Security Posture (Phase 7)

**Status:** Implemented · **Date:** 2026-09-20 · **Decision:** ADR-0016
**Plan:** `docs/research/20-phase-7-plan.md` · **Score review:** `research/experiments/oq48/`
**Satisfies:** A-01 (risk classification), A-03 (posture), A-04 (prioritisation),
A-05 (remediation)

---

## 1. Purpose

Phases 4–6 produce three independent streams of output. Phase 7 turns them into one
defensible answer to the question an analyst actually asks:

> *What is the cryptographic security posture of this email infrastructure, and how do
> you know?*

`PostureAssessment` is the canonical answer. The backend, dashboard and report
generators of later phases **consume it and recompute nothing** — if a conclusion is not
in that object, the system has not made it.

## 2. Scope

**In:** evidence fusion, deduplication, risk classification, posture scoring,
prioritisation, remediation guidance, evidence coverage, abstention handling, standards
structuring.

**Out (deliberately):** LLM, frontend, PDF/HTML rendering, SPF/DKIM/DMARC/DNS,
certificate validation beyond observability, any change to Phase 2–6 semantics.

## 3. Architecture

```
SessionEvidence[]   SecurityFinding[]   CrossSessionFinding[]   MLAnomalyResult[]
        │                   │                     │                     │
        │                   └──────────┬──────────┘                     │
        │                              ▼                                │
        │                      FusionEngine  ◄───────────────────────────┘
        │                              │              (dropped entirely when --no-ai)
        │                              ▼
        │                    FusedFinding[] + Abstention[]
        │                              │
        │                              ▼
        │                    risk.group_findings  →  IssueGroup[]
        │                              │
        ├──────────────────────────────┼──────────────┐
        ▼                              ▼              ▼
 EvidenceCoverage            scoring.compute_score   PriorityRanker
        │                              │              │
        └──────────────┬───────────────┴──────────────┘
                       ▼
               PostureAssessment
```

| Module | Responsibility |
|---|---|
| `posture/model.py` | canonical contracts; the three-dimension and three-fact-kind separations |
| `posture/standards.py` | structures the five standards the rules already cite; adds none |
| `posture/fusion.py` | deduplication, relations, contradiction handling, abstentions |
| `posture/risk.py` | issue grouping, risk/abstention summaries, coverage, protocol posture |
| `posture/scoring.py` | three candidate formulas; the selected one |
| `posture/prioritise.py` | A-04 ranking; the arithmetic ML boundary |
| `posture/remediation.py` | rule-bound A-05 templates |
| `posture/engine.py` | orchestration; the `--no-ai` boundary |

## 4. Data flow

1. **Fuse.** Findings from both deterministic lanes are keyed by content and merged;
   non-conclusive statuses are diverted to abstentions; ML results attach as
   prioritisation metadata and, where a session is `ANOMALOUS`, as their own fact.
2. **Group.** Fused findings are grouped by `(issue_class, fact_kind)` into
   `IssueGroup`, which is the unit scoring and ranking operate on.
3. **Cover.** Evidence coverage is computed over the *sessions*, independently of the
   findings, so it describes the capture rather than the conclusions.
4. **Score.** Penalties are summed over penalising groups only.
5. **Rank.** Groups are ordered by a deterministic multi-factor priority.
6. **Assemble.** Everything, plus provenance, standards, remediation and limitations.

## 5. Evidence model

Phase 7 introduces **no new evidence vocabulary**. It consumes `EvidenceState`,
`Severity`, `FindingStatus` and `EvidenceRef` unchanged and adds two derived, explicitly
separate dimensions:

| Dimension | Values | Derived from |
|---|---|---|
| **Severity** | INFO…CRITICAL | the rule, never recomputed |
| **Evidence certainty** | CONFIRMED / PROBABLE / UNCERTAIN / UNDETERMINED | the evidence states of the consulted refs |
| **Observability** | OBSERVABLE / PARTIALLY_OBSERVABLE / NOT_OBSERVABLE | the finding status and refs |

Certainty **fails toward less certainty**: one `AMBIGUOUS` or `INCOMPLETE` ref pulls the
whole finding to `UNCERTAIN`, because a conclusion is only as supported as its weakest
load-bearing observation.

> **Severity is never reduced because certainty is low.** A HIGH finding on ambiguous
> evidence stays HIGH and is reported as uncertain. Asserted by
> `test_severity_is_not_reduced_because_certainty_is_low`.

## 6. Finding fusion

### Deduplication identity

```
IssueKey = (issue_class, fact_kind, scope_key)
```

`issue_class` comes from an explicit `RULE_ISSUE_CLASS` map, not from parsing the rule
id, so renaming a rule cannot silently change fusion identity. `scope_key` is the
session `stream_key`.

**`finding_id` is deliberately not part of the key.** Ids are unique per instance, so a
key containing one can never detect a duplicate — deduplication would be a no-op that
looks like it works.

### Three fact kinds that never merge

| Kind | Source | May penalise? |
|---|---|---|
| `BASE_SECURITY_ISSUE` | deterministic `OBSERVED_ISSUE` | ✅ |
| `BEHAVIOURAL_DEVIATION` | cross-session `OBSERVED_ISSUE` | ✅ (as a deviation, not a weakness) |
| `ANOMALY_SIGNAL` | ML `ANOMALOUS` band | ❌ — blocked by a class invariant |
| `POSITIVE_EVIDENCE` | `COMPLIANT` / `INFORMATIONAL` | ❌ |
| `ABSTENTION` | non-conclusive statuses | ❌ |

`FactKind` is part of the key, so a deviation can *enrich* an issue without becoming
one. Merging them would silently promote "this differs from last time" into "this is a
vulnerability".

### Relations

`SUPPORTS` · `ENRICHES` · `DUPLICATES` · `CONTEXTUALIZES` · `PRIORITIZES` ·
`CONTRADICTS` · `ABSTAINS`. There is no `CAUSES`, no `PROVES` and no `ATTRIBUTES` —
passive capture establishes none of them.

### Provenance is never flattened

Even a source marked `DUPLICATES` keeps its own finding id, frames, evidence refs and
standards. Deduplication compresses the *count*, never the evidence.

### Contradiction handling

When sources sharing one key disagree on the outcome, fusion:
1. records the disagreement in `contradictions`;
2. retains `OBSERVED_ISSUE` if any source asserts one (fail-closed), otherwise falls to
   `AMBIGUOUS` — it never selects the reassuring reading;
3. downgrades certainty from `CONFIRMED` to `UNCERTAIN`, because contradicted evidence
   is not confirmed evidence whatever the individual refs say.

## 7. Risk classification (A-01)

Classification is **rule- and evidence-driven**. Phase 7 never assigns, raises or lowers
a severity. What it adds is scope: recurrence, protocols, certainty and the analytical
dimension.

Six dimensions, each supported by the evidence layer:
`PROTOCOL_VERSION` · `PLAINTEXT_EXPOSURE` · `UPGRADE_INTEGRITY` ·
`CRYPTO_CONFIGURATION` · `CERTIFICATE_TRUST` · `BEHAVIOURAL_CONSISTENCY`.

There is no domain-authentication dimension: SPF/DKIM/DMARC are absent from the
authoritative problem statement and unobservable in a transport capture.

`CERTIFICATE_TRUST` is present but permanently `NOT_OBSERVABLE` for TLS 1.3 and resumed
sessions, and says so with its reason rather than leaving a silent gap that reads as
"fine".

## 8. Posture scoring (A-03)

```
score = 100 − Σ over penalising issue groups of
                 severity_weight × recurrence_multiplier
```

with `recurrence_multiplier = min(2.0, 1 + log₂(recurrence)/4)`.

| Severity | Weight |
|---|---|
| INFO | 0 |
| LOW | 3 |
| MEDIUM | 12 |
| HIGH | 28 |
| CRITICAL | 55 |

Bands: **STRONG** ≥ 90 · **ADEQUATE** ≥ 75 · **WEAK** ≥ 50 · **CRITICAL** < 50 ·
**INSUFFICIENT_EVIDENCE** (a refusal to grade, not a grade).

Selected by measurement, not assertion — see ADR-0016 and §17.

**Not inputs to the score:** evidence certainty, observability, abstention count, ML
signal. Lowering the score for incomplete evidence would punish the capture rather than
the configuration; raising it would reward blindness. Coverage is reported alongside
instead. An AST test asserts `scoring.py` never reads `certainty`, `observability`,
`ml_signal` or `anomaly_score`.

### The missing-evidence guard

A capture in which nothing was established must not score 100/STRONG. Two mechanisms,
both leaving the arithmetic untouched:

1. `sessions_assessed == 0` → `INSUFFICIENT_EVIDENCE`, value 0.
2. `assessed_fraction < 0.5` → the numeric score stands, but the **band is withheld**.
   Reporting STRONG over a capture in which most sessions yielded no conclusion is the
   misleading part, not the number.

## 9. Prioritisation (A-04)

Priority is not severity. Ranking is **per issue group**, so one condition across 200
sessions is one row of analyst work rather than 200 identical rows.

| Factor | Contribution |
|---|---|
| Severity | INFO 0 · LOW 10 · MEDIUM 40 · HIGH 70 · CRITICAL 100 |
| Evidence certainty | CONFIRMED 6 · PROBABLE 3 · UNCERTAIN 1 · UNDETERMINED 0 |
| Fact kind | base issue 5 · deviation 2 · anomaly 0 |
| Recurrence | `min(8, 2·log₂(n))` |
| Standards-backed | 3 |
| Actionable (has remediation) | 2 |
| **ML adjustment** | **≤ 4.0** |

Severity gaps are ≥ 30; the ML ceiling is 4.0. An anomaly score can therefore reorder
findings *within* a tier and can never cross one — the boundary is arithmetic, not a
convention. `test_ml_adjustment_cannot_cross_a_severity_tier` asserts the inequality
directly against the tier gaps.

## 10. Remediation (A-05)

Six templates, each bound to one issue class, each carrying: what was observed, why it
matters, the recommended action, the affected scope, **how to verify**, the citations
that justify it, and its limitations.

There is no generic fallback. An issue class with no authored template gets no advice,
and `NON_ACTIONABLE` records which classes are observations rather than problems, so
"no remediation" is a decision rather than an oversight.

Every template carries two universal limitations: the capture may not have exercised all
configuration, and **SecureMailScope cannot confirm that a change was applied or
effective**. The rule's own remediation string is appended rather than replaced.

## 11. Standards traceability

Five standards, all Phase-4 verified: RFC 8996 · NIST SP 800-52r2 · RFC 3207 · RFC 2595 ·
RFC 8314. The registry maps each rule-emitted string to `(standard, section, reason)` and
carries the original text verbatim.

Three properties, all tested:
* **No standard is introduced** that a rule did not cite.
* **No string is rewritten** — `StandardCitation.text` is the rule's own wording.
* **Nothing is dropped.** An unrecognised string becomes `UNMAPPED` with its text intact
  and is listed in `standards_summary.unmapped_citations`. A forged reference injected
  through packet content therefore surfaces as unmapped rather than being trusted.

Matching is by marker substring because `NIST SP 800-52r2` is defined twice with
different wording (`tls_rules.py:28`, `plaintext_rules.py:21`) — a pre-existing
inconsistency the registry resolves rather than papers over.

## 12. ML boundary

`robust-z-sum` is a **secondary prioritisation signal only**. ADR-0015 measured zero
unique true detections on every held-out split; Phase 7 does not soften that.

| ML may | ML may not |
|---|---|
| contribute a bounded ordering nudge (≤ 4.0) | create, remove or modify a finding |
| appear as an `ANOMALY_SIGNAL` fact | penalise the score (class invariant forbids it) |
| carry score, band, threshold, attribution | change severity, status or certainty |
| populate `model_summary` | turn UNKNOWN into OBSERVED |

`--no-ai` is enforced at the top of `PostureEngine.assess`: ML results are dropped before
fusion, so they cannot reach scoring or ranking by any path. Asserted on fixtures *and*
end to end on a real capture: score, band, penalising groups, standards and remediation
are byte-identical; only `ml_adjustment`, the ordering it induces, `model_summary` and a
non-penalising `ANOMALY_SIGNAL` group may differ.

**No circularity.** AST tests assert `posture/` never imports the ML engine, feature
layer, encoder or models (only the result *contract*), and that `ml/` never imports
`posture/`. The dependency runs evidence → findings → context → optional ML → fusion →
posture, once, in one direction.

## 13. Abstention model

Seven reasons: `INSUFFICIENT_HISTORY` · `AMBIGUOUS_EVIDENCE` · `NOT_OBSERVABLE` ·
`INSUFFICIENT_CAPTURE` · `CONTRADICTORY_EVIDENCE` · `UNSUPPORTED_PROTOCOL_VARIANT` ·
`NOT_COMPARABLE`.

Every abstention records what could not be concluded, why, and **what additional evidence
would resolve it** — an abstention an analyst cannot act on is just a gap. A
cross-session finding with no baseline is reported as `INSUFFICIENT_HISTORY`, not as
`INSUFFICIENT_CAPTURE`: "we lack comparable sessions" and "we lack packets" are different
problems with different fixes.

Nothing is discarded. The full list is on the assessment; `risk_summary.abstentions` is
the readable grouped form.

## 14. Provenance

Every penalising fused finding traces to: source rule ids, source finding ids, the
session, the frames, the evidence refs with their states, the standards, and — for
cross-session sources — the baseline and contrast that permitted the comparison.
`test_every_penalising_finding_traces_back_to_frames_and_a_rule` asserts this on a real
capture.

`assessment_id` is content-addressed over capture id and issue groups, deliberately
**excluding** `run_id`: a run id is a fresh uuid per invocation, and folding it in would
make two analyses of identical evidence produce different ids.

## 15. Security considerations

All PCAP-derived text is untrusted. Ten hostile payloads are tested — prompt injection,
forged standards references, XSS, SQL, path traversal, bidirectional-override Unicode,
lone surrogates and a 100 000-character string. Asserted:

* the verdict, score and band are **unchanged** by hostile content;
* hostile text never appears in remediation or in a citation;
* a forged standards reference is flagged `UNMAPPED`, never trusted;
* no analyst-facing text names an attacker, adversary or threat actor;
* serialisation survives malformed Unicode.

Packet content may appear inside an `EvidenceRef` — that is its job, it is the observed
value — but it can never become an instruction, a severity or a recommendation.

## 16. Limitations

1. **Severity weights and band thresholds are a calibrated policy, not a measurement.**
   They were chosen so that one CRITICAL leaves ADEQUATE and one MEDIUM does not, and
   validated for behaviour, not derived from incident data.
2. **`MIN_ASSESSED_FRACTION = 0.5` is a policy choice**, documented in ADR-0016.
3. **Recurrence counts sessions, not endpoints.** A NAT-collapsed client population
   (OQ-29) will under-count distinct affected systems.
4. **Certificate posture is observability only.** No chain, expiry or key-strength
   conclusion is drawn, and none is possible passively for TLS 1.3 or resumed sessions.
5. **The corpora are synthetic.** Every number in §17 is corpus-relative. OQ-33r (real
   multi-vendor traffic) remains the blocking gap for generalisation claims.
6. **Two Phase-3 defects remain open** (§18) and are deferred by decision, not oversight.

## 17. Test evidence

**133 Phase-7 tests; 381 total, all passing.** No Phase 2–6 source file changed
(`git diff 2db283c` over those packages is empty).

| Property | Evidence |
|---|---|
| Score decomposable | value equals starting minus the sum of components |
| Monotonic on a new HIGH issue | asserted |
| Monotonic on recurrence | asserted |
| Duplicate-resistant | three reports of one condition → identical score (delta 0.0) |
| Capture length does not dominate | 10 → 100 sessions costs less than one MEDIUM |
| One CRITICAL among 59 benign | scores 45.0, well inside CRITICAL |
| Missing evidence not rewarded | no assessable session → `INSUFFICIENT_EVIDENCE` |
| Priority tier integrity | ML ceiling 4.0 < smallest tier gap 30 |
| `--no-ai` equivalence | fixtures and a real capture |
| Determinism / order independence | full `to_dict()` equality |
| Byte-identical attack/benign pair | identical posture on `B_strip_advert` vs `I_no_support` |
| Hostile text | 10 payloads × 2 assertions each |
| No circularity | AST guards both directions |

**Scoring review** (`research/experiments/oq48/`, 60 captures):

| Formula | Mean | Captures at 0 | Distinct values | 8 MEDIUM issues | Verdict |
|---|---:|---:|---:|---:|---|
| F1-instance | 36.7 | 37 | **5** | 4.0 | ❌ saturated |
| **F2-group-damped** | 53.2 | 1 | 16 | 4.0 | ✅ **selected** |
| F3-worst-dominant | 61.3 | 0 | 16 | **76.1** | ❌ under-penalises |

**Performance** — linear, measured on the posture layer alone:

| Sessions | Time | Per session |
|---:|---:|---:|
| 1 000 | 0.021 s | 0.021 ms |
| 5 000 | 0.098 s | 0.020 ms |
| 10 000 | 0.205 s | 0.021 ms |
| 25 000 | 0.533 s | 0.021 ms |

Flat from 1k to 25k. A scaling ceiling is asserted by test at 1k and 5k.

## 18. Pre-existing defects — deferred by decision

Both were found in Phase 6 (`docs/architecture/16` §9) and are **not** fixed here.
Neither can cause the posture engine to report a weakness as secure, and fixing either
means changing Phase-3 deterministic semantics — which belongs in its own change with
its own regression run, not buried inside a posture engine.

| # | Defect | Effect on posture | Decision |
|---|---|---|---|
| 1 | `Completeness.TRUNCATED` is never assigned by `session/base.py:_finalise`, making the Phase-5 comparability guard dead code | Truncated sessions report `INCOMPLETE` and still enter baselines. Visible: completeness counts appear in `EvidenceCoverage` | **Deferred, OQ-46** |
| 2 | TCP-segmented multi-line SMTP `250-` replies can lose `STARTTLS` | Fail-safe direction: yields `AMBIGUOUS`, which becomes an abstention, never a compliant or secure state | **Deferred, OQ-47** |

## 19. SIH traceability

| Req | Status | Where | Limitation |
|---|---|---|---|
| **A-01** risk classification | ✅ **COMPLETE** | `posture/risk.py`, `posture/model.py` | classification reflects the 11 implemented rules; unimplemented rules (D-10…D-14, D-17) are absent from it |
| **A-02** anomaly detection | 🟡 **PARTIAL, unchanged** | `ml/` + `crosssession/` | capability exists; **detection value not demonstrated** (ADR-0015). Phase 7 does not alter this |
| **A-03** posture assessment | ✅ **COMPLETE** | `posture/scoring.py`, `posture/risk.py` | weights and thresholds are calibrated policy, not derived from incident data |
| **A-04** prioritisation | ✅ **COMPLETE** | `posture/prioritise.py` | exploitability is not a factor — no evidence source supports it |
| **A-05** remediation | ✅ **COMPLETE** for implemented issue classes | `posture/remediation.py` | six templates; classes without one are explicitly `NON_ACTIONABLE` |
| **R-01** prioritised findings | ✅ **COMPLETE** | `PostureAssessment.prioritised` | — |
| **R-02** posture assessment object | ✅ **COMPLETE** | `PostureAssessment` | — |
| **R-03** JSON/PDF/HTML | 🟡 JSON only | `to_dict()` | PDF and HTML are Phase 9 |
| **R-05** forensic reports | 🟡 data complete, no artefact | provenance, frames, versions | rendering is Phase 9 |

## 20. What we can and cannot claim

**Can establish** (observed, standards-bound, frame-traceable): the negotiated TLS
version and whether it is prohibited; whether authentication occurred without TLS;
whether a session carried TLS at all; whether a requested STARTTLS upgrade completed;
whether behaviour differs from a prior comparable baseline.

**Can strongly indicate:** that a cleartext configuration is deliberate rather than
manipulated, when a consistent baseline and an unaffected control endpoint both exist.

**Can only prioritise:** which of several established issues an analyst should look at
first, and which sessions are statistically unusual.

**Cannot determine from passive PCAP — and must never claim:** attacker identity or
intent; that STARTTLS stripping occurred (absence is ambiguous, proven byte-identical in
02B); certificate validity, expiry or key strength when the certificate is not
observable; SPF/DKIM/DMARC posture; server configuration beyond what the traffic
exercised; that remediation succeeded; or that the ML lane discovered an attack — it
demonstrated none.
