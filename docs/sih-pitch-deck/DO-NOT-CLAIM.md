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
| "Scales to enterprise volumes" | "Runs offline on an analyst workstation" | **untested** — no capture beyond a few hundred KB |
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
