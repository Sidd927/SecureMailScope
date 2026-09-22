# Finalization — 08. D-11 and A-02: final decision, not forced implementation

**Status, unchanged and final for this SIH cycle: both PARTIAL.** Full reasoning already exists in
`docs/phase12/13-final-engineering-decision.md` §3–§4 and ADR-0023/ADR-0024; this document states
the decision plainly, confirms none of the brief's anti-fabrication constraints were violated, and
does not re-open the investigation.

---

## D-11 — Certificate chain validation: PARTIAL, passive-PCAP limitation

**Chain structure is fully validated.** Ordering, Authority/Subject Key Identifier linkage, and
self-signed detection are implemented and tested. **Chain trust and revocation are not
validated**, and cannot be from the evidence this project has committed to using:

- **Trust** requires a set of trust anchors (RFC 5280 §6). A passive packet capture contains
  none. There is no evidence *in the capture* that can substitute for one.
- **Revocation** requires OCSP or CRL access (RFC 6960) — a live network transaction. This
  project's entire design commitment is passive, offline analysis; performing a network fetch to
  answer this question would violate that commitment for one finding, which is a worse trade than
  leaving the finding honestly unanswered.

**Confirmed not done, matching every anti-fabrication constraint the brief lists:**

| Constraint | Status |
|---|---|
| Fabricate a trust store | not done |
| Bundle public roots and call that universal validation | not done — explicitly evaluated and rejected in ADR-0023 because it would flag legitimate private-CA enterprise deployments as untrusted |
| Infer revocation status without evidence | not done — revocation is reported as not evaluated, never as "not revoked" |

**What would be needed to move this to COMPLETE:** an operator-supplied trust store, evaluated
narrowly and only for analyses where one is explicitly provided (never as a default, never
inferred). Scoped in full, including effort, risk, and validation burden, in
`docs/phase12/14-proposed-next-phase.md` — **reserved, not authorized**, and not attempted during
this finalization phase, consistent with the brief's explicit instruction that research performed
now "must not delay finalization."

## A-02 — AI-assisted anomaly detection: PARTIAL, no demonstrated detection value

**The model is real.** An unsupervised anomaly score (`robust-z-sum`), fitted on governed
features, integrated with leakage controls, reproducible, and explainable. **It has zero
demonstrated detection value** — zero unique true detections on every held-out split tested,
including with the Phase-11 certificate/key-exchange features specifically re-evaluated for this
purpose (ADR-0024).

**Confirmed not done, matching every anti-fabrication constraint the brief lists:**

| Constraint | Status |
|---|---|
| Manufacture an ML benchmark | not done |
| Train on deterministic findings | not done — `FORBIDDEN_INPUTS` in `ml/features.py` structurally excludes `rule_id`, `severity`, `finding_status` |
| Use labels/generator/scenario metadata | not done — same exclusion list also blocks `ground_truth`, `label`, `generator`, `scenario` |
| Force ML to produce a positive result | not done |
| Alter metrics to make ML look better | not done — the reported metric (zero unique true detections) is the actual measured one |

**Why no further evaluation was attempted this phase:** the limiting factor is the corpus, not
the model. Across all 46 captures this project holds, forward secrecy is constant, certificate
evidence exists in 1 of 46 captures, and a key-exchange-derived feature perfectly separates two
synthetic generators rather than any real security condition — a leakage signature, not a
detection signature (re-confirmed, not re-measured, from `docs/architecture/adr/0024-a02-remains-partial.md`).
Running another bake-off on the same corpus would not produce new information; it would produce a
number, and the number would be either meaningless or favourable for the wrong reason — exactly
the outcome the brief's Workstream H explicitly forbids manufacturing.

## What remains genuinely open, not glossed over

Three specific technical questions were considered for narrowly-scoped, low-risk research this
phase and explicitly **not pursued**, each with a one-line reason:

| Question | Why not pursued this phase |
|---|---|
| D-11 operator-supplied trust material | real effort (new input surface, new UI, new false-positive analysis) exceeds "narrowly scoped and low-risk" — reserved for a future phase per `docs/phase12/14-proposed-next-phase.md` |
| EC certificate fixtures | the current fixtures are all RSA; an EC fixture would close a small documented gap (`docs/phase12/01-final-requirements-audit.md` D-13 row) but adds no judge-visible value proportional to the effort during a finalization phase focused on packaging, not new evidence generation |
| OCSP stapling observability (OQ-59) | genuinely low-effort to *measure* (does a cleartext handshake ever carry a `status_request` response), but the measurement would only matter if it fed into a trust/revocation capability this phase has already decided not to build — investigating it now would be research without a destination |

**None of the three is forgotten.** All three are recorded as explicit, evaluated future work,
not silently dropped.
