# 11 — Session Reconstruction & Protocol State Machines (Phase 3)

**Status:** Implemented. **Date:** 2026-09-16 · **ADR:** 0012 · **Code:** `src/securemailscope/session/`

Answers *"what does the PCAP show happened?"* — never *"was it malicious?"* (Phase 4's job).

## Pipeline
```
FrameEvidence → group_streams (tshark tcp.stream) → role resolution
  → protocol reconstructor (SMTP | IMAP | POP3) → events → state machine → SessionEvidence
```

## Endpoint roles
Determined from **observed protocol behaviour** — whoever sends the service greeting
(`220`, `+OK`, `* OK`) is the server. Well-known port is a *fallback only*; when neither is
available the role is explicitly indeterminate. Never inferred from port ordering.

## States
`AppState`: CONNECTED → GREETING_OBSERVED → CAPABILITY_REQUESTED → CAPABILITY_OBSERVED →
STARTTLS_ADVERTISED → STARTTLS_REQUESTED → STARTTLS_ACCEPTED | STARTTLS_REJECTED →
TLS_NEGOTIATING → TLS_ESTABLISHED, plus PLAINTEXT_CONTINUATION, IMPLICIT_TLS, CLOSED, INCOMPLETE.

Transitions are a table of `event × from-state → to-state`. An event invalid in the current
state is **ignored and noted**, never forced (fails closed).

## TLS completion semantics
| Evidence | State |
|---|---|
| no TLS records | `NONE` |
| ClientHello only | `CLIENT_HELLO_OBSERVED` |
| ClientHello + ServerHello | `SERVER_HELLO_OBSERVED` (progressed, **completion unproven**) |
| + encrypted application data | `ESTABLISHED` |
| hellos absent but records present | `HANDSHAKE_INTERRUPTED` |

`ESTABLISHED` requires application data because the Finished messages are themselves
encrypted — records flowing is the strongest passive completion evidence available.
A ClientHello (or both hellos) is explicitly **not** treated as success.

## The critical ambiguity
| Situation | Evidence state |
|---|---|
| capability reply contains STARTTLS/STLS | `OBSERVED / True` |
| capability reply seen, capability **absent** | **`AMBIGUOUS / False`** — stripping and genuine non-support are byte-identical (02B §3.1) |
| no capability reply captured | `UNKNOWN` |
| implicit TLS | `NOT_OBSERVABLE` |

`B_strip_advert` (attack) and `I_no_support` (legitimate) produce **identical** state. The
reconstruction does not manufacture differentiation it cannot evidence; Phase 5 cross-session
reasoning is what can sometimes resolve it.

## Implicit TLS
SMTPS/IMAPS/POP3S are modelled as `IMPLICIT_TLS` with all STARTTLS fields `NOT_OBSERVABLE`.
Never represented as a successful upgrade — it is a different protocol behaviour.

## tshark behaviours handled
- SMTP request commands are **truncated to 4 characters** (`STARTTLS` → `STAR`); we match on
  `smtp_command_line`.
- The multi-line SMTP `250` reply is a **list**; capabilities live in later elements, so
  `pick_all()` is required (taking `[0]` silently loses STARTTLS).
- The POP3 **CAPA body is reported as empty strings**; STLS exists only in the reassembled
  `tcp.payload`, which we decode (bounded, untrusted-data-only).

## Provenance
Every transition carries `from/event/to`, causing frame numbers, evidence state, timestamp and
basis. Retransmissions collapse on `(kind, direction, tcp_seq, detail)` so one command is never
counted twice. Streams with no identifiable mail dialogue are still recorded, not dropped.
