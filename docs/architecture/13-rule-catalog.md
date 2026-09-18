# 13 — Security Rule Catalog (Phase 4)

`rules_version 1.0` · `engine_version 0.4.0`. Severity applies only to OBSERVED_ISSUE.

| Rule | Condition | Evidence consumed | Standard | Status → Severity | Limitations |
|---|---|---|---|---|---|
| **SEC-TLS-001** Negotiated TLS version | Version negotiated in ServerHello | `tls_negotiated_version` | RFC 8996 §4–5; NIST SP 800-52r2 §3.1 | SSL2/SSL3 → CRITICAL · TLS1.0/1.1 → **HIGH** · TLS1.2/1.3 → COMPLIANT/INFO · no ServerHello → INSUFFICIENT_EVIDENCE · unrecognised value → AMBIGUOUS | Absence of a visible version is never treated as a weak version |
| **SEC-TLS-002** Handshake completion | What the handshake evidence establishes | `tls_transition`, `tls_state` | RFC 8446 §2 | ESTABLISHED+confirmed → COMPLIANT · hellos only → INSUFFICIENT_EVIDENCE · state contradicts evidence → AMBIGUOUS | ClientHello (or both hellos) is never treated as success |
| **SEC-TLS-003** Certificate observability | Whether a chain is available to validate | `tls_negotiated_version` | RFC 8446 §2; RFC 5280 (not performed) | NOT_OBSERVABLE → INFO | **No PKI validation is performed.** Absence ≠ invalid certificate |
| **SEC-STLS-001** Upgrade outcome | Outcome of an explicit STARTTLS/STLS attempt | `starttls_requested`, `starttls_accepted`, `tls_transition` | RFC 3207 §6; RFC 2595 | success → COMPLIANT · **server refused → OBSERVED_ISSUE / MEDIUM** · accepted-but-incomplete → INSUFFICIENT_EVIDENCE · contradictory → AMBIGUOUS | A refusal is a configuration/availability condition, not evidence of an attack |
| **SEC-STLS-002** Advertisement posture | Whether the upgrade capability was offered | `starttls_advertised`, `starttls_requested` | RFC 3207 §6; RFC 2595 | advertised+declined → INFORMATIONAL · **absent → AMBIGUOUS / INFO** · none captured → INSUFFICIENT_EVIDENCE | **Stripping and genuine non-support are byte-identical; this rule must never choose between them** |
| **SEC-STLS-003** Implicit TLS | Session began inside TLS | `starttls_advertised`, `tls_transition` | RFC 8314 | INFORMATIONAL → INFO | Absence of STARTTLS here is expected, not a failure |
| **SEC-PLAIN-001** Cleartext authentication | AUTH activity with no TLS protection | `auth_activity`, `tls_transition` | RFC 8314 §3; NIST SP 800-52r2 §3.1 | no TLS at all → **OBSERVED_ISSUE / HIGH** · pre-TLS phase → INFORMATIONAL | Observation of cleartext transmission is **not** evidence of interception; credential values are not extracted |
| **SEC-PLAIN-002** Session carried no TLS | Mail session with no TLS records | `tls_transition`, `starttls_advertised` | RFC 8314 §3; NIST SP 800-52r2 §3.1 | **OBSERVED_ISSUE / MEDIUM** | Cause is not attributed: client choice, server config and interference are indistinguishable here |

## Severity rationale
- **HIGH** for TLS 1.0/1.1: both RFC 8996 (MUST NOT) and NIST (shall not / should not) prohibit them, and handshake integrity depends on SHA-1. Standards non-compliance with a known weakness — not confirmed exploitation, which would require evidence we do not have.
- **HIGH** for cleartext authentication: credentials demonstrably travelled unprotected. Severity reflects exposure, not proof anyone observed it.
- **MEDIUM** for a refused upgrade and for a wholly cleartext session: real weakening of transport protection, but ordinary misconfiguration is the most common cause.
- **INFO** everywhere else. Notably, every AMBIGUOUS/INSUFFICIENT/NOT_OBSERVABLE finding is INFO by construction — we do not assert impact for conditions we have not established.

## Conditions deliberately NOT implemented
| Condition | Why not |
|---|---|
| "STARTTLS was stripped" | Proven indistinguishable from non-support in passive single-session evidence (docs/research/02B §3.1). Requires cross-session comparison — Phase 5 |
| Certificate chain / expiry / key validation | No certificate evidence in the contract; TLS 1.3 encrypts it |
| Extended Master Secret (RFC 7627) | Field not carried by the contract, not present in the corpus |
| Renegotiation indication (RFC 5746) | Same |
| Cipher-suite strength grading | Needs a maintained IANA strength table we have not built or validated |
| Credential compromise / attacker attribution | Passive capture cannot establish that any party observed or obtained anything |
