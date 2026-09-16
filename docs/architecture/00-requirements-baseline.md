# 00 — Requirements Baseline (Architecture)

**Source of truth:** [docs/research/19-authoritative-ps-verification.md](../research/19-authoritative-ps-verification.md)
(portal-confirmed 2026-09-16). **Status:** Locked. **Date:** 2026-09-16

This is the frozen requirement set the architecture is built against. IDs are stable and carried from
research doc 01. Every architecture component and test traces to these.

---

## 1. Confirmed requirements (FACT — official portal)

### Input & scope
- **INPUT:** passive analysis of participant-generated **PCAP/PCAPNG** files. No provided dataset.
- **PROTOCOLS:** SMTP, IMAP, POP3, and implicit-TLS SMTPS/IMAPS/POP3S (dataset hint names these).
- **PASSIVE ONLY.** No active probing, DNS/SPF/DKIM/DMARC, CT logs, or key logs in core scope.

### Deterministic extraction — D-01…D-18
D-01 PCAP ingest · D-02 protocol ID · D-03 TCP reassembly · D-04 STARTTLS detection · D-05 STARTTLS
**validation** · D-06 TLS handshake reconstruction · D-07 version · D-08 cipher · D-09 key exchange ·
D-10 X.509 extraction · D-11 chain validation · D-12 expiry · D-13 public-key/length · D-14 signature
algorithm · D-15 weak/deprecated crypto · D-16 insecure configuration · D-17 Forward Secrecy · D-18
cryptographic feature extraction.

> **Passive-observability caveat (01A):** D-10…D-14 are conditionally unavailable — TLS 1.3 encrypts
> the certificate and all resumed sessions omit it. Only 5/22 deliverables are cert-dependent. The
> architecture must represent this as `NOT_OBSERVABLE`, never as failure or as a false finding.

### AI/ML — A-01…A-05 (explicitly required by the PS)
A-01 cryptographic risk classification · A-02 **AI-assisted anomaly detection for suspicious TLS
sessions** · A-03 posture scoring · A-04 threat prioritisation · A-05 mitigation recommendation.

> **Correction from 10B (per Phase-11 §3):** the PS explicitly names "AI/ML techniques" and
> "AI-assisted anomaly detection." The architecture **must contain a real, separate ML anomaly
> component** (05-ai-anomaly-design.md). It must not be forced/bad: the deterministic engine remains
> the security authority; ML is an independent signal, selected empirically.

### Outputs — R-01…R-05
R-01 prioritised findings · R-02 comprehensive posture assessment · R-03 exportable reports in
**JSON, PDF, HTML** · R-04 interactive visualization dashboard · R-05 comprehensive forensic reports.

### Users
SOC · Digital Forensics · Incident Response · enterprise administrators.

---

## 2. Ambiguous requirements (tracked, not resolved)

| ID | Ambiguity | Handling |
|---|---|---|
| AMB-04 | "weak"/"deprecated"/"insecure" undefined | Bind to RFC 8996 / NIST SP 800-52r2 / 800-131A (05, 06) |
| AMB-05 | chain-validation trust anchor | Configurable trust store; enterprise internal-CA aware (ADR-0004) |
| AMB-06 | "insecure protocol configurations" open-ended | Bounded, versioned rule checklist (04, ADR-0004) |
| AMB-07 | shape of "posture assessment" artifact | We define it: coverage-aware score + findings + evidence (03) |
| **OQ-35** | Does a `--no-ai`-capable design satisfy "AI-Assisted"? | Ship a real ML component (A-02) so the answer is yes; `--no-ai` is a fallback, not the default posture |

## 3. Explicit NON-requirements (out of scope)

DNS/SPF/DKIM/DMARC/DANE/MTA-STS/BIMI/DNSSEC · active probing · CT logs · key-log decryption (optional
labelled mode only) · attacker attribution · rebuilding TCP/TLS/X.509 parsers · email content analysis.

## 4. Remaining assumptions (NOT facts)

| ID | Assumption | Status |
|---|---|---|
| I-01 | Offline/air-gapped deployment | **Our inference**, not PS text. Architecture is offline-capable but does not present this as a PS requirement. |
| A-05(exp) | Team can generate lab PCAP corpus | Needed for the golden corpus; low risk (validated we can craft + tshark-verify). |

## 5. Requirement→architecture pointer

Full trace in [requirements-traceability.md](requirements-traceability.md). Deadline **30 Sep 2026**;
near-term deliverable is the idea/abstract, build window runs to the Dec Grand Finale. Confirm SPOC
internal cutoff (team).
