---
name: security-analysis
description: Threat modeling and cryptographic-correctness reasoning. Trigger when evaluating a security control, TLS/cipher/cert logic, severity assignment, or any claim about what an attacker can/cannot do.
---
# security-analysis

Bind every crypto judgement to a named authority (RFC 8996 for deprecated TLS, NIST SP 800-52r2 /
800-131A for algorithm strength, RFC 7627 EMS, RFC 5746 renegotiation, RFC 3207 STARTTLS). No invented
severities or thresholds.

Discipline:
- State what a control protects against AND what it does not.
- "weak"/"deprecated"/"insecure" must reference the authority, not intuition.
- Detection ≠ attribution. We detect DEVIATION, never "attacker X did Y."
- Absence of evidence ≠ evidence of a problem (see evidence-provenance).
- Passive-PCAP only; anything needing active probing/keys/CT is out of scope or an optional labelled mode.
