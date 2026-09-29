# 15 — Cross-Session Rule Catalog (Phase 5)

`cross rules_version 1.0` · `cross engine_version 0.5.0`. Severity is INFO unless status is
`OBSERVED_ISSUE`.

| Rule | Condition | Required history | Evidence | Outcome | Limitations |
|---|---|---|---|---|---|
| **CS-STARTTLS-001** Advertisement deviation | Advertisement behaviour vs prior comparable sessions | ≥ `min_history` (5) consistent | `starttls_advertised` + baseline + contrast | matches baseline → `COMPLIANT/NONE` · differs, no/ambiguous control → `AMBIGUOUS/DEVIATION` · differs **or** self-consistent-but-controls-differ, control unaffected → `OBSERVED_ISSUE/SUSPICIOUS_DEVIATION` (MEDIUM) | **Never claims stripping.** Blind-stripping limitation attached to every outcome. Per-client server policy is indistinguishable from interference |
| **CS-STARTTLS-002** Upgrade deviation | Upgrade outcome vs baseline | ≥ `min_history` consistent | `tls_transition`, `starttls_requested` | differs → `AMBIGUOUS/DEVIATION` (INFO) | **Legitimate-decline guard:** historical success + current decline never becomes an issue. A client declining an available upgrade is legitimate |
| **CS-TLS-001** Version deviation | Negotiated version vs baseline | ≥ `min_history` consistent | `tls_negotiated_version` | improvement → `INFORMATIONAL/NONE` · regression → `OBSERVED_ISSUE/DEVIATION` (MEDIUM) | Cause not established: reconfiguration, client capability and interference are indistinguishable |

## Abstention outcomes (all rules)
| Situation | Result |
|---|---|
| Subject not comparable | `NOT_OBSERVABLE / NOT_ASSESSED` |
| Fewer than `min_history` prior comparable sessions | `INSUFFICIENT_EVIDENCE / NOT_ASSESSED` |
| Prior history inconsistent | `AMBIGUOUS / NOT_ASSESSED` |
| Unrelated sessions only | no baseline, no finding |

## Deliberately NOT implemented
| Condition | Why |
|---|---|
| "STARTTLS was stripped" | Indistinguishable without a control (02A §9 #1; 02B). The engine reports deviation, never cause |
| Cipher/configuration deviation (CS-TLS-002 in the brief) | The cipher value is observed, but no validated strength model exists to say a *change* is a weakening; a bare value change is not security-relevant on its own |
| Authentication-timing deviation (CS-AUTH-001) | `auth_activity` is a coarse boolean in the current contract; a deviation in it would not be interpretable without finer evidence |
| Attacker attribution / exploitation | Passive evidence cannot establish either |
