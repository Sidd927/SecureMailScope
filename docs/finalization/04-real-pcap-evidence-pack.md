# Finalization — 04. Real PCAP evidence pack

**Every number below was produced by running the real, released pipeline against the real corpus
this phase** — `demo/evidence/real_pcap_evidence_pack.json` is the machine-readable form, written
by direct execution, not transcribed from an earlier phase's report. Every figure matches what
Phase 11's release audit and Phase 12's documentation independently measured, which is itself a
third independent confirmation of determinism.

---

## 1. The three-way distinction this pack exists to make precise

The brief asks this document to explicitly separate three things that are easy to conflate and
dangerous to conflate:

| Term | Meaning | Example from this corpus |
|---|---|---|
| **"not observed"** | the capture could show this, but doesn't (a genuine absence, evidenced) | `postfix_smtp_no_starttls_offered.pcap`: STARTTLS was genuinely never advertised — observed absence |
| **"not supported"** | not applicable to this project's design at all | active certificate retrieval, OCSP fetching — not attempted by design, not a capture property |
| **"not observable from passive PCAP"** | the capture *cannot* show this regardless of what happened, because the protocol itself hides it | every TLS 1.3 session's certificate — RFC 8446 §2 encrypts it; this is true no matter what the actual certificate was |

Collapsing the third into the first ("no certificate shown" → "no certificate exists" or "bad
certificate") is the exact forbidden inference this entire project's evidence model exists to
prevent, and it is checked explicitly per-capture in §3 below.

## 2. Corpus inventory (real captures)

| Capture | Protocol | TLS mode | Sessions | Posture | Score |
|---|---|---|---|---|---|
| `postfix_smtp_client_declines.pcap` | SMTP | STARTTLS offered, client declines | 1/1 | ADEQUATE | 88.0 |
| `postfix_smtp_no_starttls_offered.pcap` | SMTP | no STARTTLS advertised (2 sessions, cross-session-eligible) | 2/2 | ADEQUATE | 85.0 |
| `postfix_smtp_plaintext_session.pcap` | SMTP | plaintext throughout | 1/1 | ADEQUATE | 88.0 |
| `postfix_smtp_starttls_upgrade.pcap` | SMTP | STARTTLS upgrade completes (2 sessions) | 2/2 | ADEQUATE | 88.0 |
| `dovecot_imap_starttls_upgrade.pcap` | IMAP | STARTTLS upgrade completes (2 sessions) | 2/2 | ADEQUATE | 88.0 |
| `dovecot_imap_plaintext_login.pcap` | IMAP | plaintext throughout | 1/1 | WEAK | 60.0 |
| `dovecot_imap_imaps_implicit_tls.pcap` | IMAP | implicit TLS (IMAPS) | 1/1 | STRONG | 100.0 |
| `dovecot_pop3_stls_upgrade.pcap` | POP3 | STLS upgrade completes | 1/1 | STRONG | 100.0 |
| `dovecot_pop3_plaintext_login.pcap` | POP3 | plaintext throughout | 1/1 | WEAK | 60.0 |
| `dovecot_pop3_pop3s_implicit_tls.pcap` | POP3 | implicit TLS (POP3S) | 1/1 | STRONG | 100.0 |

All 10 negotiate **TLS 1.3** where TLS is used at all — a fact with a direct consequence for §3.

## 3. Certificate visibility, per capture — the honest answer

**Zero of the 10 real captures show a certificate.** Not because extraction failed — because
every one negotiates TLS 1.3, which encrypts the Certificate message by protocol design. This is
stated as `NOT_OBSERVABLE` in every relevant finding, with the specific RFC 8446 §2 reason named,
never as an absent or invalid certificate.

| | |
|---|---|
| Real captures showing a certificate | **0 of 10** — TLS 1.3 encrypts it structurally |
| Generated fixtures showing a certificate | **3 of 3** — deliberately built as TLS 1.2, cleartext handshake, specifically to exercise this capability, since the real corpus cannot |
| Consequence stated honestly | D-10–D-14 (certificate extraction/expiry/key-strength/signature) are validated against **generated fixtures only** for real-world traffic — this is `docs/phase12`'s OQ-60, and it is repeated here rather than left in only one document |

## 4. Generated certificate fixtures — clearly labelled as generated

| Fixture | What it proves | Posture | Score |
|---|---|---|---|
| `smtps_tls12_chain_rsa2048.pcap` | healthy 2-certificate chain, negative control | STRONG | 100.0 |
| `smtps_tls12_selfsigned_rsa2048.pcap` | self-signed leaf, structurally detected via AKI=SKI | ADEQUATE | 88.0 |
| `smtps_tls12_weak_sha1_rsa1024.pcap` | RSA-1024 + SHA-1 signature, both flagged HIGH | CRITICAL | 44.0 |

**These are not real-world captures.** They were generated with OpenSSL and a Docker-based probe
script in Phase 11, specifically because the real corpus cannot exercise this capability at all.
Any presentation of these results must state this plainly — `docs/finalization/09-presentation-evidence.md`
and `demo/RUNBOOK.md` both do.

## 5. Cross-session-eligible captures

Only `postfix_smtp_no_starttls_offered.pcap`, `postfix_smtp_starttls_upgrade.pcap`, and
`dovecot_imap_starttls_upgrade.pcap` contain 2 sessions each — still short of the ≥5 comparable
sessions the cross-session rules require to form a baseline. **No real capture in this corpus
triggers a live cross-session finding.** This is stated here as a corpus property, not glossed
over, and is the reason `docs/finalization/06-cross-session-demo.md` uses a worked example rather
than a live corpus run.

## 6. Evidence-state distribution, aggregated across the real corpus

From `observation_counts` across all 10 real captures: `OBSERVED` values dominate (the
protocol/session-state facts that are always directly visible), `UNKNOWN` appears where a
handshake or capability response wasn't fully captured, `NOT_OBSERVABLE` appears exclusively on
the certificate-family findings (§3), and `AMBIGUOUS` appears exactly once — on
`postfix_smtp_no_starttls_offered.pcap`, correctly, because an absent STARTTLS advertisement is
genuinely indistinguishable from stripping within a single session (the exact case Scene A
demonstrates).

**Abstention reasons observed:** `NOT_OBSERVABLE` (certificate, every TLS 1.3 session),
`INSUFFICIENT_CAPTURE` (partial protocol dialogue), `AMBIGUOUS_EVIDENCE` (the one STARTTLS case
above). No capture in this corpus ever collapses one of these into a compliant or secure verdict —
independently re-verified this phase by inspecting `abstention_reasons` on every entry in
`demo/evidence/real_pcap_evidence_pack.json`.

## 7. Provenance — traced, not merely asserted

Every entry in the evidence pack carries its `capture_id` (the PCAP's own SHA-256) and
`assessment_id` (content-addressed from the assessment document, excluding run-specific fields).
Both were captured directly from the real assessment output this phase, not computed separately —
the same identity chain documented in `docs/architecture/22-forensic-reporting.md` was exercised
live, once per capture, 13 times, with no mismatch.
