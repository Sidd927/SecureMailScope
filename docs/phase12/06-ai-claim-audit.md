# Phase 12 — 06. AI claim audit

**Method:** grepped every user-facing and code-comment surface — README, all of `docs/`, all of
`src/`, including the dashboard JS, the HTML/PDF report templates, and every rule's finding text —
for the overclaim patterns the brief lists (*"AI detects attacks," "AI identifies threats," "AI
detects malicious sessions," "AI validates security," "AI proves compromise"*) plus the project's
own broader set (*"secure," "100% secure," "no issues found," "zero false positives," "100%
detection," "attacker attribution," "detects compromise"*).

**No presentation material or demo script exists yet** — those are Phase-12 candidate deliverables
(`13-final-engineering-decision.md`), so this audit covers what actually exists: the codebase and
its documentation. Whatever presentation deck is eventually built must be checked against this
document's findings before use.

---

## 1. Result

**Zero unsupported AI/ML claims found anywhere in the released system.** Every hit on the search
patterns above was either absent entirely or was the discipline's own **negation** of the
overclaim — for example `overview.js:164` contains the string `"secure"` inside a code comment
explaining that the field must never be read as "secure" (*"`dimensions_not_observable` is shown
beside `dimensions_assessed` so 'no issue found' is never mistaken for 'secure'"*), and
`analysis/engine.py:8` contains the string `LLM` only inside the sentence *"No ML, no LLM, no
network, no randomness."*

This is not a coincidence of one late audit — it is the accumulated result of the project's own
review discipline across every phase, most recently the explicit adversarial testing in
`tests/test_phase11_rules.py`, which asserts the forbidden inferences (§3 below) as executable
tests, not only as documentation.

## 2. What the system actually says about its AI/ML component — verbatim, and why it's accurate

Every AI-related surface — the dashboard's Overview ML panel, the HTML report, the PDF report,
the assessment JSON's `model_summary` — renders the **same source string**, not independently
authored per-surface text that could drift:

> `"role": "secondary prioritisation signal only"`

accompanied, per `posture/engine.py:63` and `posture/model.py:285`, by:

> *"the ML lane is a secondary prioritisation signal only; Phase 6 (ADR-0015) measured zero unique
> true detections on every held-out split"*

This is checked against `01-final-requirements-audit.md`'s A-02 entry and is accurate: the model
is real (fitted, unsupervised, reproducible), its role is bounded (`MAX_ML_ADJUSTMENT = 4.0`
against a 30-point severity-tier gap, so it can never move a finding across a severity tier), and
its detection value is honestly reported as zero-demonstrated, not hidden or softened.

## 3. The forbidden inferences, and where each is guarded

| Forbidden conversion | Where it would appear | Guard |
|---|---|---|
| anomaly score high → attack detected | ML panel, findings | `ANOMALY` issue class never penalises the score (`posture/remediation.py:157`); `MLAnomalyResult` carries no `severity`/`status`/`finding` field at all — structurally cannot produce a finding |
| AI/ML capability exists → AI/ML detects something | any AI surface | every surface renders the identical `role` string above, not a per-surface embellishment |
| deviation → attacker | cross-session findings | `test_scene_a_inversion_declines_are_not_attacks` asserts the phrase *"no attacker, intent or attribution is or can be established from a packet capture"* reaches the console verbatim |
| certificate extraction → certificate trust | certificate findings | `SEC-TLS-003` and `SEC-CERT-005` state, in every finding, that trust requires a trust anchor a PCAP does not contain; tests assert no trust/revocation verdict is ever emitted |
| missing evidence → secure | dashboard, reports | six-state evidence model; `test_scene_b_no_findings_is_not_rendered_as_secure` |

## 4. The accurate conceptual model to use in any future presentation material

Exactly as the brief specifies, and confirmed faithful to the implementation by this audit:

> **Deterministic security reasoning** (19 standards-bound rules, 16 single-session + 3
> cross-session) **+ cross-session reasoning** (per-server baselines resolving the STARTTLS
> ambiguity) **+ a secondary unsupervised anomaly signal** (bounded, non-detecting, honestly
> evaluated) **+ bounded evidence fusion** (coverage-gated scoring that never rewards missing
> evidence).

This sentence — or `05-project-explanation.md`'s 60-second version, which says the same thing in
presentation prose — is safe to use verbatim in any slide deck, script, or spoken answer. No
phrase in it needs a caveat added under questioning; every clause is independently defensible from
a specific test or ADR cited above.

## 5. Nothing to fix

Because the search found no violation, there is no replacement to make. This is recorded as a
**positive finding**, not a null result: the discipline the project claims to have (README:
*"ML cannot create security facts"*) is verified, not merely asserted, across every surface a
judge could read.
