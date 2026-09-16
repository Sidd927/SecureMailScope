# 02 — Architecture Options & Decision Matrix

**Status:** Decided (dissection layer). **Date:** 2026-09-16
Decides the foundational question: what parses the packets. Consequential because 01C established the
extraction layer is commodity and rebuilding it is a poor engineering choice.

---

## 1. Options

- **A — tshark/Wireshark dissectors** → normalized evidence → our analysis engine
- **B — Zeek** → normalized evidence → our analysis engine
- **C — Hybrid tshark + Zeek** → common evidence schema → engine
- **D — Custom packet/protocol implementation**

## 2. Decision matrix

Scores: ✅ strong · 🟡 partial/works-with-effort · ❌ weak/absent. Evidence column cites what we verified.

| Capability | A tshark | B Zeek | C Hybrid | D Custom | Evidence |
|---|:--:|:--:|:--:|:--:|---|
| SMTP dissection | ✅ | ✅ | ✅ | 🟡 | 02B: tshark SMTP dissector extracted EHLO/250/params |
| **IMAP dissection** | ✅ | ❌ (13-line analyzer, no imap.log) | ✅ | 🟡 | 01B §3.1; 02B P_imap validated |
| **POP3 dissection** | ✅ | ❌ (no main.zeek, no pop3.log) | ✅ | 🟡 | 01B §3.1; 02B P_pop3 validated |
| STARTTLS/STLS visibility | ✅ (cleartext fields) | 🟡 (SMTP bool only) | ✅ | 🟡 | 01B; 02B |
| Implicit TLS (465/993/995) | ✅ | ✅ | ✅ | 🟡 | tshark TLS dissector on port |
| TCP reassembly | ✅ mature | ✅ mature | ✅ | ❌ hard (retransmit/OOO/gap) | 02B: our 150-line reassembler worked but is toy vs tshark |
| TLS handshake parsing | ✅ | ✅ | ✅ | 🟡 | 02B: tshark identified hs types, version, SNI |
| X.509 extraction | ✅ | ✅ (x509.log) | ✅ | 🟡 | S-07, S-15 |
| Structured output | ✅ `-T json`/`-T ek`/`-T fields` | ✅ TSV logs | ✅ | n/a | tshark JSON is per-packet, rich |
| Evidence granularity | ✅ per-frame | 🟡 per-session | ✅ | ✅ | tshark gives frame-level; Zeek is session-summarised |
| Offline operation | ✅ | ✅ | ✅ | ✅ | all local |
| Single dependency | ✅ | ✅ | ❌ two heavy deps | ✅ | — |
| Install complexity | 🟡 (Wireshark/tshark pkg) | 🟡 (Zeek build/pkg) | ❌ both | ✅ none | brew/apt both fine |
| Licensing | GPL-2 (CLI use, no linking) | BSD | mixed | n/a | tshark used as subprocess = fine |
| Demo stability | ✅ (proven this session) | ✅ | 🟡 (more moving parts) | ❌ (our code = our bugs) | 02B ran clean |
| STARTTLS security logic | ❌ (none ships) | ❌ (none ships) | ❌ | — | **we build this regardless** — 01B/01C |

## 3. Decision

> **Option A — tshark as the dissection + reassembly + TLS/X.509 parsing layer, consumed as
> structured output; our engine builds the STARTTLS state machine, evidence model, deterministic
> analysis, cross-session reasoning, and ML on top.**

**Why A over B/C/D:**
- **A is the only single tool that fully dissects all three mail protocols.** Zeek has no IMAP/POP3
  logging and Suricata no POP3 parser (01B). Choosing Zeek would force us to build IMAP/POP3 parsing
  anyway — the exact reinvention we're avoiding.
- **Frame-level granularity** (A) beats Zeek's session summaries for a forensic tool that must anchor
  findings to specific frames (I-03).
- **Proven in this session** (02B): tshark 4.6.8's real dissectors parsed our SMTP/IMAP/POP3/TLS
  traffic and recovered every raw fact our engine needs. The 02B finding — *"tshark recovers the same
  raw facts we do; the gap is judgement"* — is the whole argument: reuse the extraction, own the judgement.
- **C (hybrid)** doubles the dependency and deployment surface for no capability A lacks. Rejected for
  the prototype; revisit only if Zeek's session model helps at enterprise scale (kept as an open door).
- **D (custom)** rejected outright — 01C §5 showed reassembly/TLS parsing is commodity and HIGH-effort
  to rebuild; our toy reassembler in 02B is not production-grade and shouldn't be.

**"Aren't we then a tshark wrapper?"** (01C objection #5, faced honestly). The dissection is commodity
and we reuse it deliberately. Our value — validated in 02A/02B — is the deterministic STARTTLS/TLS
security engine, the cross-session reasoning (−72% FP, verified absent from all competitors), the
evidence-provenance model, and the analyst-facing outputs. None of that ships in any tool audited.
Being honest that dissection is reused is stronger than pretending to reinvent it.

## 4. Consequences & risks

- **Dependency:** tshark must be installed/bundled. Mitigation: document install; for the offline demo,
  pin a version and verify presence at startup with a clear error. (ADR-0001.)
- **Interface:** we depend on tshark's JSON/EK field names across versions. Mitigation: a thin
  adapter + a version check + golden-corpus regression catches field drift.
- **Performance:** tshark JSON is verbose. Mitigation: use `-T ek` (newline-delimited) or `-T fields`
  with a curated field set; stream rather than load whole (25 §perf).
- **Not locked:** the *dissection* layer is decided. Everything above it (engine, storage, ML,
  frontend) is decided in ADRs 0002–0011.

Recorded as **ADR-0001**.
