# DO NOT CLAIM

**Mandatory check before the deck is exported.** Every prohibited claim below is either false, or
unsupported by anything in this repository. Each has a correct alternative that is just as strong.

---

## AI / ML

| ❌ DO NOT SAY | ✅ SAY INSTEAD | Why |
|---|---|---|
| "AI detects attacks" | "Deterministic, standards-cited rules produce every security finding; the ML lane re-orders them within a severity tier" | ADR-0024: zero unique true detections on every held-out split |
| "ML identifies malicious traffic" | "An unsupervised anomaly model provides a bounded prioritisation signal" | same |
| "AI identifies attackers" | "No attacker, intent or attribution is established — passive capture cannot establish it" | attribution is impossible from transport evidence |
| "AI proves compromise" | "The system reports evidence and deviations, not conclusions about intent" | — |
| "AI automatically determines security" | "Security conclusions are deterministic and provably identical with the AI lane disabled" | `--no-ai` equivalence is proven |
| "AI validates certificates" | "Certificate analysis is deterministic; the ML lane never touches it" | — |
| "ML accuracy / precision / recall is X%" | "Evaluated on generator-held-out data; no independent detection value was demonstrated, and we report that" | any favourable figure would be invented |
| "AI-powered threat detection" | "AI-assisted prioritisation, with deterministic detection" | — |

## Certificates and TLS

| ❌ DO NOT SAY | ✅ SAY INSTEAD | Why |
|---|---|---|
| "We validate certificates" | "We validate certificate **chain structure** where the handshake exposes it" | trust requires an anchor a PCAP lacks (RFC 5280 §6) |
| "Complete certificate validation" | "Structure validated; **trust and revocation are not observable** from passive capture alone" | D-11 is PARTIAL |
| "We check certificate trust" | "Trust validation would require an operator-supplied trust store — scoped as the next capability" | not built |
| "We check revocation" | "Revocation requires OCSP/CRL network access, which a passive tool does not perform" | RFC 6960 |
| "TLS 1.3 certificates are visible / we extract certificates from all sessions" | "TLS 1.3 encrypts the certificate — 0 of our 10 real captures expose one" | RFC 8446 §2, measured |
| "No certificate found = invalid certificate" | "`NOT_OBSERVABLE`, with the specific reason stated" | the core forbidden inference |
| Presenting fixture results without labelling | "**Generated** TLS 1.2 fixture" | the real corpus is entirely TLS 1.3 |

## STARTTLS and detection

| ❌ DO NOT SAY | ✅ SAY INSTEAD | Why |
|---|---|---|
| "We detect every STARTTLS stripping attack" | "We **distinguish** stripping from a benign decline where cross-session evidence exists — and say so explicitly where it doesn't" | consistent stripping with no control endpoint is passively indistinguishable |
| "We detect stripping" (flat claim) | "We report a **deviation** from comparable endpoints at the same server" | the engine's own wording |
| "Zero false positives" | "Ambiguous evidence stays `AMBIGUOUS`; only observed issues penalise the score" | never measured |
| "100% detection" | — (no substitute; delete the claim) | never measured |
| "Reduces false positives by X%" | "Resolves an ambiguity class that a single-session analyser cannot resolve" | **OQ-25 was never closed quantitatively — any percentage is fabricated** |

## Novelty

| ❌ DO NOT SAY | ✅ SAY INSTEAD | Why |
|---|---|---|
| "We are the first" | "Our source-code audit of five competing implementations found none performing cross-session reasoning" | audit-scoped, defensible |
| "We are unique" | same as above | — |
| "No existing tool can do this" | "Cross-connection correlation is standard in network monitoring generally; it is absent from the mail-forensics implementations we audited" | Zeek/Arkime do related things |
| "Revolutionary / breakthrough" | "Integration-grade differentiation for this problem" | our own novelty audit forbids it |

## Performance and scale

| ❌ DO NOT SAY | ✅ SAY INSTEAD | Why |
|---|---|---|
| "Real-time" | "Sub-second per-capture analysis (115–320 ms)" | the system is batch-over-PCAP |
| "Scales to enterprise volumes" | "Runs without network access on an analyst workstation" | **untested** — no capture beyond a few hundred KB |
| "Processes N captures/hour" | — (delete) | never measured |
| "Handles PCAPs of any size" | "A configurable size ceiling is enforced" | bounded by design |

## Impact

| ❌ DO NOT SAY | ✅ SAY INSTEAD | Why |
|---|---|---|
| Market size / TAM / adoption numbers | operational benefits only (offline, passive, citable) | **no verified data exists** |
| ROI, cost savings, "₹X crore" | — (delete) | fabrication |
| "Protects N million mailboxes" | — (delete) | fabrication |
| "Used by X organisations" | — (delete) | not deployed |

## Forensics

| ❌ DO NOT SAY | ✅ SAY INSTEAD | Why |
|---|---|---|
| "Chain of custody" | "Every finding traces to specific frames; artifacts are content-addressed and re-verified" | legal chain-of-custody is a certified process, not what this is |
| "Court-admissible" | — (delete) | unsupported |
| "We decrypt encrypted email" | "We analyse transport metadata and handshakes — **nothing is decrypted**, no keys are used" | categorically false and dangerous |

## The rule behind every row

> If a claim cannot be traced to a specific test, experiment, standard, or source file in this
> repository, it does not go on a slide. **A technically honest partial result beats a fabricated
> complete one** — and a judge who catches one invented number will disbelieve every real one.

---

# PART II — FINAL CLAIM FIREWALL

Added during the final pre-handoff audit. Every rule below was verified directly against
production source on 2026-09-23.

## A. Canonical vocabulary — and the four enums that must never be conflated

**⚠️ A review proposal circulated with this vocabulary:**
`OBSERVED · INFERRED · NOT_OBSERVABLE · NOT_APPLICABLE · AMBIGUOUS · INSUFFICIENT_EVIDENCE`

**That set is NOT canonical and must not be used.** It was verified against production and found
to be a conflation of three separate enums. It is recorded here so the error cannot re-enter.

The system has **four distinct vocabularies**, each with its own job:

| Enum | Source | Values | What it describes |
|---|---|---|---|
| **`EvidenceState`** ← **this is "the six evidence states"** | `evidence/states.py` | `OBSERVED` · `INFERRED` · `UNKNOWN` · `AMBIGUOUS` · `INCOMPLETE` · `NOT_OBSERVABLE` | how well the capture supports one *fact* |
| `FindingStatus` | `analysis/model.py` | `OBSERVED_ISSUE` · `COMPLIANT` · `INFORMATIONAL` · `AMBIGUOUS` · `INSUFFICIENT_EVIDENCE` · `NOT_OBSERVABLE` | the analytic *outcome* of a rule |
| `AbstentionReason` | `posture/model.py` | `INSUFFICIENT_HISTORY` · `AMBIGUOUS_EVIDENCE` · `NOT_OBSERVABLE` · `INSUFFICIENT_CAPTURE` · `CONTRADICTORY_EVIDENCE` · `UNSUPPORTED_PROTOCOL_VARIANT` · `NOT_COMPARABLE` | why the engine declined to conclude |
| `BaselineStatus` | `crosssession/baseline.py` | includes `NOT_APPLICABLE` | whether a cross-session *baseline* could be built |

**Consequences for the deck:**

- When the deck says **"six evidence states"**, it means **`EvidenceState`** — and must list
  exactly: `OBSERVED · INFERRED · UNKNOWN · AMBIGUOUS · INCOMPLETE · NOT_OBSERVABLE`.
- **`NOT_APPLICABLE` is not an evidence state.** It is a `BaselineStatus`. Never put it in the
  six-state strip.
- **`INSUFFICIENT_EVIDENCE` is not an evidence state.** It is a `FindingStatus`. Never put it in
  the six-state strip.
- Do not invent a merged "unified" vocabulary for presentation convenience. The separation is
  deliberate and load-bearing.

## B. Real vs generated evidence — never conflate

| Category | What it is | Required label |
|---|---|---|
| **Real validated captures** | 10 Postfix + Dovecot captures (`research/experiments/oq33r/`) | "real Postfix/Dovecot captures" — safe to call real-vendor traffic |
| **Generated scenario / golden corpus** | 25 controlled scenario captures (`research/experiments/oq28/`), incl. the cross-session demonstrations | "generated scenario corpus" — **never** "real-world" or "production traffic" |
| **Generated TLS 1.2 certificate fixtures** | 3 captures built with OpenSSL for certificate validation (`research/experiments/p11cert/`) | **"GENERATED TLS 1.2 FIXTURE"** — mandatory label every time |
| **Real corpus TLS property** | all 10 real captures negotiate TLS 1.3 | therefore the real corpus **cannot** exercise certificate extraction at all |

**The trap:** the most visually impressive certificate result (RSA-1024 + SHA-1 → CRITICAL) comes
from a **generated fixture**. Presenting it as real-world evidence would be the single most
damaging misrepresentation available in this deck.

**Also note:** the cross-session demonstration (`G_control_endpoint`, `H_no_control`) runs on the
**generated scenario corpus**, not the real-vendor corpus — because the real corpus has too few
comparable same-endpoint sessions to form a baseline. Say "executed on our scenario corpus", not
"observed in production traffic".

## C. Universal quantifiers

Do not use **every · all · always · never · any · 100%** unless the statement is a verified
structural invariant.

| ❌ | ✅ |
|---|---|
| "detects every stripping attack" | "reports a deviation where comparable-session evidence exists" |
| "every session is checked against all others" | "compared against **comparable prior sessions at the same endpoint, protocol and TLS mode**" |
| "always identifies weak certificates" | "assesses observable certificate properties where the handshake exposes them" |

**Verified invariants where absolute language IS permitted** (these are enforced in code):
- "the ML lane can **never** create a finding" — `MLAnomalyResult` carries no severity/status field
- "missing evidence can **never** improve a score" — only `OBSERVED_ISSUE` penalises; non-assertive
  statuses cannot exceed `INFO` severity (constructor raises)
- "the ML adjustment can **never** cross a severity tier" — 4.0 cap vs a 30-point gap, arithmetic

## D. Dependency language

| ❌ | ✅ |
|---|---|
| "zero dependencies" | "**0 third-party Python runtime packages** in the analysis core" |
| "zero runtime dependencies" (unqualified) | same, **and** "**TShark is the required external dissection binary**" |
| "air-gapped capable" / "air-gap certified" | "**runs without network access**" |

**Why:** zero network calls in `src/` was verified by import-set inspection. An actual air-gapped
*deployment* was never separately validated — the honest claim is about network behaviour, not a
certified deployment mode. And TShark is a hard external dependency that must always be named
alongside the "no Python packages" claim, or the statement misleads.

## E. Screenshot and data provenance

Every screenshot used in the deck must be traceable:

- state **which capture** produced it,
- state whether that capture is **real** or **generated**,
- never screenshot a generated-fixture result and caption it as real-world.

## F. AI visual language

- No brain, robot, neural-network, or "AI magic" imagery — it implies autonomous detection, which
  is precisely what the evidence does not support.
- The ML lane must be visually **subordinate** to the deterministic lane, with the arrow into
  findings visibly **blocked**.
- Do not give the ML lane equal visual weight to the rule engine; it does not have equal weight in
  the architecture.

## G. TLS 1.3 visualisation

**"0 of 10" is an observability boundary, not a failure rate.**

- Do not style it red, or as a gauge/score/percentage of failure.
- Do not place it beside pass/fail metrics in a way that implies the system failed 10 times.
- Correct framing: *"TLS 1.3 encrypts the Certificate message (RFC 8446 §2) — 0 of our 10 real
  captures expose one. This constrains every passive observer equally."*
