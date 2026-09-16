# 06 — Threat Model

**Status:** Draft for security review (invoke `security-reviewer`). **Date:** 2026-09-16
**Method:** STRIDE-informed, grouped by attack surface. Assets and boundaries stated; not every
framework forced.

---

## 1. Assets & trust boundaries

**Assets:** the analyst's trust in findings; evidence integrity (chain of custody); the analyst
workstation; the report artifacts. **Trust boundary:** *everything derived from the PCAP is untrusted
data.* The PCAP may have been produced by an attacker (it captures attacker-controlled SMTP/IMAP/POP3
content and attacker-influenced TLS). This is the governing principle.

## 2. Input attacks (PCAP layer)

| Threat | Impact | Mitigation |
|---|---|---|
| Malformed / corrupted PCAP | crash, wrong parse | tshark handles; wrap in error boundary; fuzz in adversarial tests |
| Huge PCAP | memory exhaustion / DoS | stream tshark output (`-T ek`), bounded memory, background job, size guard |
| Fragmentation / retransmit storm / OOO | wrong reassembly | rely on tshark reassembly; validated survivable (02B §6); regression tests |
| Truncated capture | false "insecure" verdict | `INCOMPLETE`/`NOT_OBSERVABLE`, never a finding (02B §5 — all truncation cases abstained) |
| Pathological TCP (overlaps, seq wrap) | parser confusion | tshark's mature stack; adversarial corpus |

## 3. Protocol attacks

| Threat | Handling |
|---|---|
| Malformed SMTP/IMAP/POP3 | state machine tolerates unknown lines; unmatched → `AMBIGUOUS`/`UNKNOWN` |
| STARTTLS manipulation (strip/inject/fake-error/downgrade) | modelled as evidence, reported as DEVIATION where context exists — never as attribution (01B §7, 02B) |
| TLS handshake anomalies | `handshake_status` states; feeds anomaly lane |
| Certificate abuse (self-signed, expired, bad chain) | deterministic rules vs configurable trust store; expiry vs capture time |

## 4. AI/ML attacks

| Threat | Impact | Mitigation |
|---|---|---|
| **Poisoned training data** | model learns attacker-shaped "normal" | unsupervised, generator-held-out eval, multi-generator corpus (05 §6); ML never authoritative |
| Model drift / concept drift | stale baseline | `model_version` + `training_context` stamped; re-fit path; scores are advisory |
| Adversarial features | evade anomaly lane | ML is a *secondary* signal; deterministic rules still fire independently |
| **Prompt injection via email/network text** | LLM manipulated | **demonstrated contained (10B §12):** PCAP text is data, excluded from prompts; AI gets structured evidence only; findings immutable & pre-computed; citation post-validator |
| Malicious text in reports (stored XSS) | analyst browser compromise | escape/sanitise all PCAP-derived text in HTML/PDF; treat as untrusted (§5) |

## 5. Application attacks

| Threat | Mitigation |
|---|---|
| Resource exhaustion | size/time guards; background job; bounded output |
| Path traversal (capture upload / artifact paths) | keyed by hash, no user-controlled paths; validate filenames |
| Report injection / stored XSS | context-aware escaping of all PCAP-derived strings in HTML; PDF via a renderer that doesn't execute script |
| Unsafe HTML/PDF rendering | render offline, no remote resources, no JS execution in PDF path |
| SQL injection | parameterised queries only (SQLite) |

## 6. Analyst risks (the subtle ones)

| Risk | Mitigation |
|---|---|
| False positives | cross-session reasoning (−72% FP, 02A/02B); abstention over guessing |
| False negatives | honest limits stated (100%-stripping-no-control is undetectable — 02B §12); never claim completeness |
| Overtrust in a clean report | coverage-aware posture (03 §4): "assessed 13/18, 5 NOT_OBSERVABLE" |
| Model output mistaken for evidence | evidence confidence ≠ model confidence, separated in UI (04 §5) |
| Deviation misread as attack | verdict enum is `DEVIATION`, never `ATTACK`; UI wording enforced |

## 7. Forensic integrity

Capture SHA-256 on ingest; immutable source refs; frame-anchored evidence; versioned analysis/rule/
model; reproducible runs (04 §4). Chain of custody preserved so findings are defensible.

## 8. Residual risks (accepted, documented)

- Universal stripping with no control endpoint is undetectable from capture alone (02B §12). Stated, not hidden.
- Single-vendor corpus until OQ-33r; ML generalisation unproven cross-generator (05 §6).
- tshark version/field drift could change parsing — caught by golden-corpus regression, not prevented.
