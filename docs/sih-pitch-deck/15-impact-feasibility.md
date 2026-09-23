# 15 — Impact and feasibility

Slide 5 is where decks fabricate. This document draws the line between **currently demonstrated**
and **future potential**, and forbids everything else.

---

## CURRENTLY DEMONSTRATED (safe to state as fact)

| Claim | Evidence |
|---|---|
| Runs **fully offline / air-gapped** | zero network calls anywhere in `src/`, re-verified by import-set inspection 2026-09-23; live health check succeeded with no internet dependency |
| **No external AI service** required | the ML lane is a local, CPU-only, unsupervised model — no API key, no cloud inference, no model download |
| **Passive** — never touches production mail servers | architectural: the only input is a capture file; no socket is ever opened to a mail server |
| **No keys, no message content** | analyses transport metadata and handshakes only |
| Works on **evidence teams already collect** | PCAP is standard SOC/DFIR capture output — no new instrumentation required |
| **Zero third-party runtime dependencies** in the analysis core | verified; only tshark (external binary) is required |
| **Three export formats** (JSON/HTML/PDF) | verified this phase: valid JSON, script-free HTML, text-extractable PDF |
| Every finding **cites a published standard** | 11 standards, enumerated from the rule registry |
| **Sub-second** per-capture analysis | 115–320 ms measured end-to-end |
| **Multi-protocol**: SMTP, IMAP, POP3 + implicit TLS | validated on 10 real captures across all three |

## FUTURE POTENTIAL (must be labelled as such)

| Claim | Honest framing |
|---|---|
| Operator-supplied trust anchors → fuller certificate validation | *"scoped as the next capability"* — designed, deliberately not built (`docs/phase12/14-proposed-next-phase.md`) |
| Larger-scale / enterprise deployment | **untested**; say "designed to run offline on an analyst workstation", never "scales to enterprise volumes" |
| Batch/continuous analysis pipelines | architecturally plausible; not implemented |

## FORBIDDEN (no evidence exists — do not write these)

- any market size, TAM, adoption number, or user count
- ROI, cost savings, "₹X crore saved", economic-impact figures
- "protects N million mailboxes" / national-scale statistics
- throughput, captures-per-hour, maximum PCAP size
- "real-time monitoring" (the system is batch-over-PCAP)
- "reduces analyst workload by X%"

**No such measurement exists anywhere in this repository.** Inventing one would contradict the
project's entire evidence discipline — and it is exactly what a technical judge probes first.

## The defensible impact argument

> Transport-security failures in email are **silent**: a stripped STARTTLS, a deprecated TLS
> version, or a weak certificate leaves no trace in the message itself. After an incident, the
> packet capture is often the only durable evidence — and today an analyst must either read it
> by hand or accept a tool's unexplained verdict.
>
> SecureMailScope turns that capture into a **standards-cited posture assessment with its
> uncertainty intact**, in under a second, entirely offline, without touching the mail
> infrastructure. The output is a document an analyst can attach to an incident report and defend
> under review — including an explicit statement of what the evidence could *not* establish.

This is operational impact, fully supported, and it does not require a single invented number.

## Feasibility summary for Slide 4

**Built and tested** (1219 tests, 0 failures) · **validated on real vendor traffic** (10 Postfix
and Dovecot captures, 3 protocols, 4 TLS modes) · **reproducible** (20/20 identical repeat runs) ·
**fast** (115–320 ms) · **deployable** (offline, zero runtime dependencies, single external binary).

## Risks, honestly (Slide 4's required pointer)

| Risk | Strategy |
|---|---|
| TLS 1.3 encrypts certificates — 0 of 10 real captures expose one | report `NOT_OBSERVABLE` with the RFC reason; extract fully where TLS ≤1.2 permits |
| Certificate trust needs an anchor a PCAP lacks | validate chain *structure*; state the trust boundary in every finding; operator-supplied trust store scoped as next step |
| ML showed no detection value on held-out data | ship bounded as prioritisation only; deterministic rules remain the source of truth; `--no-ai` equivalence proven |
| tshark is an external dependency | version-checked at startup; fails closed rather than degrading silently |
| Cross-session needs ≥5 comparable sessions | abstains explicitly below that threshold rather than inferring |
