# 04 — Evidence States & Provenance

**Status:** Locked (this is a correctness contract, not a preference). **Date:** 2026-09-16

The single most important discipline in a forensic tool: never claim more than the capture supports.
Validated repeatedly in 01A/02A/02B; this document makes it binding.

---

## 1. Evidence states

| State | Meaning | Example |
|---|---|---|
| **OBSERVED** | Directly present in captured bytes | `250-STARTTLS` in reassembled server stream |
| **INFERRED** | Logically deduced from observed facts; basis recorded | client sent STARTTLS ⇒ it was advertised (RFC 3207 §4.1) |
| **UNKNOWN** | Insufficient evidence to decide | no server bytes captured |
| **AMBIGUOUS** | Evidence supports >1 valid reading | advertisement absent: stripped **or** unsupported (02B §3.1, byte-identical) |
| **INCOMPLETE** | Capture truncated at the relevant point | capture ends mid-handshake |
| **NOT_OBSERVABLE** | Structurally impossible to observe passively | TLS 1.3 certificate (RFC 8446 §2); any resumed-session cert |

## 2. Forbidden silent conversions (enforced by the EvidenceField wrapper, 03 §2)

`UNKNOWN → FALSE` · `UNKNOWN → SECURE` · `INFERRED → OBSERVED` · `AMBIGUOUS → ATTACK` ·
`INCOMPLETE → NORMAL` · `NOT_OBSERVABLE → FALSE`.

A consumer that reads `.value` without `.state` is a bug; code review (skill) and unit tests
(testing-validation) check for it. The system must be able to output *"the capture does not contain
enough evidence to determine this"* — that is a feature.

## 3. Provenance tags (certificate-class facts)

| Tag | Meaning | Passive-legal? |
|---|---|---|
| `observed` | seen in this session's captured bytes | ✅ |
| `inherited` | linked from a full handshake earlier in the same capture (TLS ≤1.2 session ID) | ✅ but must be labelled — cert may have changed |
| `historical` | seen earlier for this server in our own corpus | ✅ (offline) — a claim about the past, not this session |
| `retrieved` | actively fetched (probe/CT) | ❌ out of core scope — optional labelled mode only |
| `decrypted` | recovered using key material | ❌ optional labelled mode only; never presented as passive |

A finding that presents a `retrieved` or `decrypted` cert as if `observed` is a false forensic claim.

## 4. Reproducibility contract

Same PCAP + same `analysis_version` + `rule_version` + `model_version` ⇒ identical evidence, findings,
and (seeded) anomaly scores. Capture SHA-256 recorded on ingest; every finding stamped with versions
and frame refs. Verified in practice already (02B: identical output hash across 3 runs).

## 5. Evidence confidence vs model confidence

Two orthogonal fields that must never be conflated (10B §11):
- **evidence_confidence** (sufficient / limited / insufficient) — a property of the *capture*.
- **anomaly_score / model confidence** — a property of the *model*, in the separate anomaly lane.

A fluent, high-score anomaly on a `NOT_OBSERVABLE` fact is still `NOT_OBSERVABLE`. The UI must never let
model output read as evidential strength.
