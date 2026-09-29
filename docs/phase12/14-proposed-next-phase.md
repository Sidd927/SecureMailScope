# Phase 12 — 14. Proposed next phase

**Status: RESERVED, NOT AUTHORIZED.** `13-final-engineering-decision.md` concludes that no
engineering is justified before the 2026-09-30 idea/abstract submission deadline. This document
exists because the audit did identify one genuinely high-value remaining capability — it is
recorded here in full, scoped rigor, specifically so that *if* SecureMailScope advances to the
December 2026 Grand Finale, a future phase can pick it up without re-deriving the investigation
already done in `13-final-engineering-decision.md` §3.

**This is not a green light.** Nothing in this document is implemented, and nothing should be
implemented from it without a fresh explicit authorization, on the same terms every phase of this
project has used: research gate first, implementation only after the research gate is approved.

---

## Candidate: D-11 operator-supplied certificate trust anchors

### Exact objective

Allow an analyst to optionally supply a trust store (a set of root/intermediate CA certificates)
at analysis time, so that certificate chains extracted from a cleartext handshake can be evaluated
for trust **against that supplied material**, in addition to the structural analysis
(`SEC-CERT-005`) already shipped. Revocation (OCSP/CRL) remains explicitly out of scope even in
this proposal — it requires live network access, which contradicts the passive/offline invariant
this project has held since Phase 1, and nothing in this candidate changes that assessment.

### Requirement it would move

D-11 (*"Certificate chain validation"*), from PARTIAL toward COMPLETE **for analyses where a
trust store is supplied**. Analyses without a supplied trust store would continue to report
exactly what they report today — this must not become the default behaviour, or it silently
reintroduces the exact false-positive risk ADR-0023 rejected.

### Why it matters

It is the one credible path to closing the project's last structurally-partial deliverable, and
doing so honestly — the finding would say "evaluated against the supplied trust store," not
"validated," preserving the provenance discipline this project has held throughout.

### Architecture impact

- A new, clearly optional input surface (API parameter, not a default), so `--no-ai`-style
  equivalence testing extends naturally: a trust-store-supplied analysis and a bare analysis must
  produce identical results for everything **except** the trust finding itself.
- `crypto/certificates.py` gains a trust-evaluation function, kept separate from the existing
  structural-analysis code (which stays untouched, per `09-architecture-freeze-audit.md`'s
  recommendation not to touch that module without new fixture evidence).
- A new `Provenance`-style qualifier distinguishing "structurally analysed" from "evaluated
  against a supplied trust store" — the existing `Provenance` enum already has room for this
  distinction in spirit, though the exact mechanism needs its own design pass.
- `SEC-CERT-005`'s finding text needs a new branch, not a rewrite of the existing one.

### Files likely affected

`crypto/certificates.py` (new function, additive) · `analysis/rules/certificate_rules.py`
(`SEC-CERT-005` new branch) · `backend/schemas.py`, `backend/api.py` (new optional input) ·
`reporting/` (new report content only when a trust store was supplied) · `dashboard/` (new,
conditional display element) · a new ADR.

### Tests required

At minimum: a positive case (supplied trust store validates a legitimate chain), a negative case
(supplied trust store correctly rejects an actually-untrusted chain), a no-trust-store-supplied
case (byte-identical to today's behaviour — this is the regression guard that matters most), and
an adversarial case (a malformed or hostile supplied trust store must fail closed, not crash or
silently pass everything).

### Real-PCAP validation needed

The existing 3 generated TLS-1.2 fixtures are insufficient on their own — they would need to be
paired with **matching trust-store material** (the CA that actually signed them), plus at least
one deliberately-mismatched case to prove the rejection path works. This is buildable with the
same Docker/OpenSSL probe approach Phase 11 used, but it is new fixture-generation work, not
reuse of what exists today.

### Security risks

Accepting arbitrary operator-supplied certificate material is a new attack surface that does not
exist in the current design. It must be parsed with the same "attacker-controlled, never
executed, always length-bounded" discipline already applied to certificate fields extracted from
a capture (`crypto/certificates.py`'s existing `MAX_TEXT_LENGTH`/`MAX_CHAIN_LENGTH` guards would
need equivalents on the supplied side).

### Rollback plan

Because the feature is strictly additive and gated behind an explicit optional input, rollback is
a matter of not calling the new code path — no existing behaviour changes shape. If a defect is
found post-release, the trust-evaluation function can be disabled at the API layer without
touching the structural-analysis path other analyses depend on.

### Estimated effort

Medium-to-large: comparable in scope to the entire D-10–D-14 certificate work delivered in Phase
11 (2023 lines, 97 tests, one full phase), because the honesty and false-positive-avoidance
discipline this project holds itself to applies in full here too — this is not a smaller version
of that work, it is a different, harder problem (evaluating trust is exactly the part Phase 11
explicitly declined for good reason).

### Deadline risk

None for 2026-09-30 (not attempted). For a Grand-Finale timeline (December 2026), realistic if
started with a proper research gate at least several weeks ahead of that date — not a last-week
addition, given the false-positive stakes.

### Definition of done

- No analysis without a supplied trust store changes any existing output (regression-proven).
- A supplied trust store correctly validates a matching chain and correctly rejects a
  non-matching one, each proven against a generated fixture built for this purpose.
- The finding text never says "validated" without qualifying that it was validated **against the
  supplied material**, never against a bundled or assumed authority.
- Hostile/malformed supplied trust material fails closed and is covered by an adversarial test.
- A new ADR records the decision, the false-positive analysis, and what was rejected — following
  the same discipline as ADR-0023.

---

## Everything else considered and explicitly not proposed

Per `13-final-engineering-decision.md` §2's "DO NOT BUILD" row: further A-02 model iteration,
certificate dashboard visualisation, packet-level drill-down, application Docker packaging, the
`DEPRECATED_TLS_VERSION` rename, and speculative hardening of certificate attribution logic
without new fixture evidence. None of these met the bar this document applies to D-11 above —
either the value is not demonstrated, the risk exceeds the value, or the capability was
deliberately excluded from the PS's own scope by earlier research.
