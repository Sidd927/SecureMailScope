# ADR-0003 — Session reconstruction & STARTTLS state machine in our engine
**Status:** Accepted 2026-09-16
**Context** No tool ships STARTTLS security state (01B/01C); tshark gives frames/streams, not email
session security state.
**Problem** Where does session + STARTTLS state reconstruction live?
**Options** (a) tshark fields only; (b) our engine over tshark output; (c) Zeek scripts.
**Decision** (b) — our `sessions` component builds TCP→email sessions and the per-session STARTTLS/STLS
state machine (RFC 3207 / 2595) from tshark output, for SMTP, IMAP, POP3, implicit + explicit TLS.
**Rejected** (a) tshark has no STARTTLS security notion; (c) Zeek lacks IMAP/POP3 output (ADR-0001).
**Consequences** + this is our value layer; full protocol coverage. − we own this code and its tests.
**Risks** state-machine gaps on malformed traffic → adversarial corpus (07).
**Open questions** OQ-31 (implement client-command→advertised inference), OQ-32 (positive TLS outranks incomplete teardown).
