# 16 — Existing solutions positioning

How to represent competition in almost no slide space, without misrepresenting anyone.

---

## The evidence base

`docs/research/01D-sih-competitor-source-audit.md` — a **source-code** audit (not README claims) of
five competing SIH26159 implementations: CipherPost, Prahari, saravana-rr0411/SecureMailScope,
gouravsehlangia/SecureMailScope, MailRakhwala. Capabilities were established by grep and direct
source reading; unknowns were recorded as unknown.

## The rule that governs this slide

> **Compare only documented capabilities. Where a capability was not verified, write "not
> verified" — never infer absence.**

A judge who has seen these repos will instantly catch a misrepresentation, and it would destroy
credibility built everywhere else in the deck.

## What the audit actually found

| Capability | Audited competitors | SecureMailScope |
|---|---|---|
| PCAP ingest + reassembly | 4 of 5 verified | yes |
| SMTP / IMAP / POP3 state machines | 4 of 5 verified (gourav strongest on STLS) | yes |
| TLS version / cipher / key exchange | 4 of 5 verified | yes |
| Certificate analysis | 4 of 5 verified | yes — **parity, not advantage** |
| Standards-cited rules | verified in Prahari; varies elsewhere | yes — parity |
| Evidence-observability states | **1 of 5** partial (saravana: `NOT_OBSERVABLE`, `score_confidence`) | yes — six states, end-to-end |
| **Cross-session reasoning** | **0 of 5** — verified absent by grep across all five | **yes** |
| AI-on/AI-off equivalence proof | **not tested by any** | proven end-to-end |
| ML epistemics | circular in 2 (model reproduces its own rules); LLM with pre-decided conclusion in 1 | evaluated on held-out data; negative result reported |

## Recommended slide treatment: **do not build a comparison table**

A competitor-comparison table on a six-slide deck is a **bad trade**:

- it consumes space the template allocates to *our* solution;
- it invites the judge to audit our characterisation of others;
- the official pointer asks for *"innovation and uniqueness of the solution"* — a positive claim,
  not a competitive teardown.

**Instead: one sentence on Slide 2.**

> *"Our source-code audit of five competing implementations found each reasons about one session at
> a time; none performs cross-session reasoning."*

That single line does everything a table would, is fully defensible, and costs one line.

## If a table is demanded anyway (e.g. by a mentor)

Use **capability rows, not vendor columns** — compare against *approaches*, not named teams:

| Capability | Per-session analyzers | SecureMailScope |
|---|---|---|
| Parse TLS/certificates from PCAP | yes | yes |
| Distinguish stripped STARTTLS from a declined one | not from a single session | yes, where cross-session evidence exists |
| Report what the evidence *cannot* establish | rarely | six evidence states, enforced |
| Security conclusions independent of the ML lane | not tested | proven |

Naming no competitor avoids misrepresentation entirely while keeping every claim true.

## Positioning against general-purpose NSM tooling

If asked about Zeek/Suricata/tshark, the framing is **complement, not replacement**:

> tshark does our dissection — it is a required dependency, not a competitor. Zeek and Suricata are
> general-purpose network monitoring platforms; SecureMailScope is a mail-security-specific
> forensic reasoning layer with standards-cited verdicts and explicit uncertainty. We are not
> claiming to replace them.

Full answer: `docs/finalization/10-final-judge-cheatsheet.md` §M.
