# ADR-0004 — Deterministic, standards-bound, versioned security rules
**Status:** Accepted 2026-09-16
**Context** "weak/deprecated/insecure" undefined in PS (AMB-04); competitors use invented thresholds
and outdated defaults (Zeek weak-keys ships TLSv10 minimum — 01B §3.1).
**Problem** How are security verdicts and severities decided?
**Decision** A versioned rule set, each rule bound to a named authority (RFC 8996, NIST SP
800-52r2/800-131A, RFC 7627, RFC 5746, RFC 3207) with `rule_version` stamped on findings. Trust store
for chain validation is configurable and enterprise-internal-CA aware (AMB-05). D-16 is a bounded,
enumerated checklist (AMB-06).
**Rejected** learned severity (no ground truth; not auditable); intuition-based thresholds (indefensible to an evaluator).
**Consequences** + auditable, citable, reproducible; fixes competitors' stale-default gap. − rules need maintenance as standards evolve.
**Risks** rule gaps → test per rule; standards change → versioned, re-bindable.
**Open questions** OQ-08 (any CERT-In/MeitY authority to add) — research, non-blocking.
