# 08 — Differentiation analysis

Which single differentiator carries the deck, and how it survives a skeptical comparison.

---

## Candidates, ranked by defensibility

| Capability | Differentiating? | Evidence | Verdict |
|---|---|---|---|
| **Cross-session reasoning** | ✅ **strongest** | source-code audit of 5 competing SIH26159 implementations — grepped for `for sess in`, `all_sessions`, `group_by`, `correlat`, `per_server`; **absent from all five** (`docs/research/01D` §4) | **PRIMARY** |
| **Evidence-state model / uncertainty preservation** | ✅ strong, partially contested | one competitor (saravana-rr0411) has a `NOT_OBSERVABLE` posture state + `score_confidence`; **none** applies it as an end-to-end discipline across rules → fusion → scoring → report → UI | **SECONDARY** |
| Forensic provenance (frame-level traceability) | 🔸 moderate | present in our `EvidenceRef`; competitor coverage **not verified** for this specific property | supporting only |
| Standards-bound posture (11 standards) | 🔸 moderate | Prahari also cites standards properly (01D calls it "best rules engine") | **not** differentiating — parity |
| Multi-protocol email reconstruction | ❌ no | gourav has verified STLS regexes + explicit implicit-TLS branch | parity |
| Certificate/X.509 analysis | ❌ no | 4 of 5 competitors ship certificate analysis modules | parity — Phase 11 closed a *gap*, it did not create an advantage |
| AI separated from deterministic facts | ✅ moderate-strong | audited competitor ML is circular (reproduces its own rules, disclosed or not) or an LLM with a pre-decided conclusion; **none tested AI-on/AI-off equivalence** | supporting — strong in Q&A |

## Why cross-session wins

It is the only capability that is simultaneously: (1) **verified absent** from every competitor
examined by source code rather than README; (2) the solution to a **real, articulable inference
problem** (the byte-identical STARTTLS ambiguity) rather than a feature; and (3) **demonstrable on
real data** — it fired a genuine `MEDIUM` finding on `G_control_endpoint.pcap` during finalization.

## Comparison against general-purpose tooling

Only documented capabilities are compared; unknowns are marked, never inferred as absent.

| Capability | tshark | Zeek | Suricata | Arkime | NetworkMiner | Audited SIH competitors | SecureMailScope |
|---|---|---|---|---|---|---|---|
| Offline PCAP analysis | yes | yes | yes | yes | yes | yes | yes |
| Mail-protocol state machines (SMTP/IMAP/POP3 + STARTTLS/STLS) | dissects fields; no security state machine | generic analyzers, not mail-security-specific | signature-based | session indexing | protocol parsing | yes (4/5) | yes |
| Standards-cited security verdicts | no — reports fields | logs facts, not verdicts | alert/no-alert | no posture model | no posture model | yes (varies) | yes, 11 standards |
| **Cross-session security reasoning** | no | correlation frameworks exist for other purposes (standard NSM practice) | no | human-driven search | no | **0 of 5** | **yes** |
| Explicit evidence states / abstention | no | n/a | binary | n/a | n/a | 1 of 5 partial | yes, six states end-to-end |
| AI-on/AI-off equivalence proof | n/a | n/a | n/a | n/a | n/a | **not tested by any** | proven end-to-end |

## The honesty constraint that makes the claim survivable

Cross-connection correlation is **standard practice in network security monitoring generally** —
Zeek's `known-certs`, Arkime's session search. Our claim is therefore deliberately scoped:

> **Integration-grade differentiation for this problem**, verified absent from five competing
> SIH26159 implementations — **not** research novelty in the NSM field.

A judge who knows Zeek will respect the precision and distrust the alternative. This exact
qualification appears in `docs/phase12/12-novelty-audit.md` and must survive into the deck.

## Slide wording

**Safe:** *"Our source-code audit of five competing implementations found none performing
cross-session reasoning."*

**Unsafe:** *"We are the first / the only tool that reasons across sessions."*
