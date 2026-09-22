# Phase 12 — 02. Technical differentiation

**Method:** grounded in `docs/research/01D-sih-competitor-source-audit.md` — a **source-code**
audit of five actual competing SIH26159 repositories (CipherPost, Prahari, saravana-rr0411's
SecureMailScope, gouravsehlangia's SecureMailScope, MailRakhwala), not a README survey. No new
competitor survey was performed for this audit: nothing about the competitive landscape is
knowable to have changed since 2026-09-16 in a way a fresh survey would catch in the time
available, and the brief instructs *"do not blindly perform a new competitor survey unless
required."* It is not required — the existing audit already reasoned from source code, the
strongest evidence tier available short of a live comparison run.

This document is descriptive. It does not rank, score, or declare a winner.

---

## 1. What the source-code audit already found (2026-09-16, unchanged)

Of four *hypothesised* differentiators going in, **three were found already implemented** by at
least one competitor, verified by grep and direct source reading:

| Hypothesis | Verdict |
|---|---|
| Evidence-observability discipline (`NOT_OBSERVABLE`, confidence separate from severity) | ❌ **saravana-rr0411 has it** — `security_posture="NOT_OBSERVABLE"`, `score_confidence`, `is_confirmed_plaintext_payload()` |
| All-three-protocols + implicit-TLS coverage | ❌ **gourav has it** — explicit STLS regexes, an explicit implicit-TLS branch |
| Session-resumption awareness | ❌ **Prahari has it** — a dedicated `CFG-006` rule, though narrower (a rule, not a first-class evidence state) |
| **Cross-session reasoning** | ✅ **verified absent from all five** — every competitor engine reasons about one session at a time; grepped for `for sess in`, `all_sessions`, `group_by`, `correlat`, `per_server` across all five codebases |

One survives the audit unqualified. That result has not changed since 2026-09-16 and nothing in
Phase 11 touched it — Phase 11 added certificate/key-exchange analysis, which is a capability
**four of five competitors already have** in some form (`certificate_analyzer.py`,
`cert_analysis/`, `certificates.py`, `gen_certs.py`). Phase 11 does not create a category
differentiator; it closes a parity gap, and does so with a specific execution difference (§3
below) rather than a category one.

## 2. What is NOT claimed here

Per the brief: no ranking, no scores, no "we beat X at Y." Also, per the project's own novelty
discipline (carried into `12-novelty-audit.md`): no claim of "first," "unique," "revolutionary,"
or "only" without independent proof. What follows is a **descriptive capability comparison**,
stated plainly.

## 3. Concrete capability comparison

| Capability | Generic tshark scripting | Zeek | Suricata | Arkime | NetworkMiner | Snort-style rules | Audited SIH competitors | SecureMailScope |
|---|---|---|---|---|---|---|---|---|
| PCAP-only, no live capture required | yes | can be offline | can be offline | offline-capable | offline | offline | yes | yes |
| Mail-protocol-specific coverage (SMTP/IMAP/POP3 + STARTTLS/STLS) | manual, per-script | generic protocol analyzers, not mail-security-specific | signature-based, not protocol-state-aware | session indexing, not mail-specific | protocol parsing, not security-rule-driven | signature/rule-based, not stateful per-protocol | yes, 4/5 | yes |
| TLS handshake visibility discipline (TLS 1.3 encrypts Certificate — stated as a limit, not worked around) | tshark itself dissects it; nothing *reasons* about the limit | not a design concern of Zeek's scripting layer | not applicable | not applicable | not applicable | not applicable | unverified in source (not the audit's focus) | explicit: `SEC-TLS-003`, `SEC-CERT-001` name the exact reason, every time |
| STARTTLS stripping vs. genuine non-support, resolved **within one session** | no | no (generic protocol logs, not this specific ambiguity) | signature-based, would need a hand-written rule | no | no | would need a hand-written rule; still per-session | **no competitor resolves this** — ambiguity is preserved (correct) or silently collapsed (incorrect), never resolved cross-session | resolved only when cross-session evidence exists; states `AMBIGUOUS` otherwise, never guesses |
| Cross-session / cross-connection reasoning within one capture | no (per-connection scripting) | Zeek's `known-certs` and similar frameworks do this **for other purposes** — this is standard NSM practice, not novel in the field | no | Arkime's session search is human-driven correlation, not an automated cross-session security rule | no | no | **verified absent from all 5** | **present** — 3 rules over per-server baselines (≥5 comparable sessions), directly resolving the STARTTLS ambiguity above |
| Six-state evidence model (not binary secure/insecure) | tshark reports fields; no security-state model at all | Zeek logs are factual, not a posture verdict | binary alert/no-alert | no posture model | no posture model | binary alert/no-alert | saravana has a `NOT_OBSERVABLE`-equivalent; others do not | present, uniformly, across every rule and every layer |
| Certificate provenance labelling (`observed`/`inherited`/`historical`/`retrieved`/`decrypted`) | no | no | no | no | no | no | unverified — not audited for this specific distinction | present, structurally enforced (`Provenance` enum reaches every `EvidenceRef`) |
| AI/ML separated from security findings, with a proof the findings are identical with AI off | not applicable | not applicable | not applicable | not applicable | not applicable | not applicable | **audited: none tested this.** One competitor's ML is circular-and-disclosed, one circular-and-undisclosed, one is an LLM with the conclusion pre-decided, one has no ML located in source | `--no-ai` equivalence **proven** end-to-end through the real API (`test_scene_c_no_ai_equivalence_across_the_whole_stack`), not merely claimed |
| ML evaluation discipline (label-free usability gate, generator-held-out splits, honest negative result) | not applicable | not applicable | not applicable | not applicable | not applicable | not applicable | not verified for any competitor — none appear to run a held-out evaluation at all | measured 98.6% generator-separability, zero unique true detections on every held-out split, reported as PARTIAL rather than hidden |
| Forensic reporting in 3 formats with byte-deterministic identity | manual | log export, not a report | alert export | session export | host/file export | alert export | generic report generators exist (65 KB `builder.py` in Prahari, etc.) — parity, not differentiation | present; `report_sha256` is a content hash of the assessment |

## 4. What technically distinguishes SecureMailScope — stated once, plainly

Two things, at different levels:

1. **Cross-session reasoning is the one capability-level gap verified absent from every audited
   competitor**, and it resolves a real epistemic problem this project's own research identified:
   a STARTTLS advertisement that is absent from one session is indistinguishable, within that
   session, from a server that never supported STARTTLS at all. Observing the *same server*
   advertise STARTTLS on another connection in the same capture resolves it. No audited competitor
   does this. This is **integration-grade differentiation for this specific problem domain, not
   research novelty** — cross-connection correlation is standard practice in network security
   monitoring generally (Zeek, Arkime). The 01D research explicitly makes this distinction and it
   is preserved here rather than inflated.

2. **Forensic honesty is enforced as a system-wide discipline, not a feature.** The six-state
   evidence model, the provenance vocabulary, the coverage-gated score, the `--no-ai` proof, and
   the certificate trust/revocation boundary are not five separate features — they are one
   discipline (never convert missing evidence into a verdict) applied uniformly across every
   layer of the system. At least one competitor (saravana-rr0411) implements a piece of this
   (a `NOT_OBSERVABLE` posture state); none implement it as an end-to-end, structurally-enforced
   discipline reaching from the evidence layer through the finding, the assessment, the report,
   and the dashboard, with tests asserting the discipline cannot be silently broken.

Neither claim is "novel" in an absolute sense. Both are true, specific, and evidence-backed for
*this problem and this competitive set*, which is the only claim this project is in a position to
make and defend under questioning.
