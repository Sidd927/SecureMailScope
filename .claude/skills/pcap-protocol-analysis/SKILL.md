---
name: pcap-protocol-analysis
description: SMTP/IMAP/POP3 + STARTTLS/STLS + implicit TLS + TLS handshake + X.509 + TCP evidence from PCAP. Trigger for any packet/protocol reasoning, state-machine design, or extractor logic.
---
# pcap-protocol-analysis

State machines (RFC 3207 SMTP, RFC 2595 IMAP/POP3): banner → EHLO/CAPABILITY/CAPA →
STARTTLS/STLS advertisement → command → response → TLS handshake → (re-issue EHLO). Model deviations:
advert stripped, command altered, response removed/faked (454/-ERR), cleartext continuation,
handshake failure, injection, EHLO→HELO downgrade.

Hard facts (validated 01A/02B):
- TLS 1.3 encrypts everything after ServerHello incl. Certificate (RFC 8446 §2). Resumed sessions omit
  Certificate at ANY version (§2.2). Only 5/22 deliverables are cert-dependent.
- Read `supported_versions`, NOT `legacy_version` (pinned 0x0303) for the negotiated version.
- Absent advertisement is AMBIGUOUS (stripped vs unsupported) — byte-identical, proven 02B §3.1.
- Implicit TLS (465/993/995) has no cleartext banner: ID via port + SNI + cert SAN (≤1.2) + shape.
- Reuse tshark for dissection/reassembly; do not rebuild TCP/TLS.
