# Phase 12 — 05. Project explanation at four lengths

Every version below is checked against the same rule: no claim exceeds what
`01-final-requirements-audit.md` and `06-ai-claim-audit.md` can defend under direct questioning.
The two forbidden phrases from the brief — *"AI detects attacks"* and *"we validate
certificates"* — do not appear in any version, because neither is true: the AI lane has zero
demonstrated detection value (A-02, PARTIAL), and certificate work is extraction and structural
analysis with an explicit trust/revocation boundary (D-11, PARTIAL).

---

## 10 seconds

> "SecureMailScope reads a captured email session — SMTP, IMAP, or POP3 — and reports exactly
> what its encryption actually was, citing the evidence for every claim and stating plainly what
> it couldn't determine."

## 30 seconds

> "SecureMailScope is a passive forensic tool for email transport security. Given a PCAP capture
> of an SMTP, IMAP, or POP3 session, it reconstructs whether TLS was negotiated correctly, whether
> STARTTLS was stripped or genuinely absent, and what the certificate and cipher configuration
> actually was — each conclusion tied to specific packet evidence and a cited standard. Where the
> capture doesn't show enough to conclude something, it says so explicitly rather than guessing.
> It runs entirely offline, against a real capture, with no live network access."

## 60 seconds

> "SecureMailScope analyses email transport security from a passive packet capture — no active
> probing, no server access, no message content. Given SMTP, IMAP, or POP3 traffic, it
> reconstructs the session's protocol state, TLS handshake, certificate chain where one was
> visible, and cipher configuration, then evaluates each against RFC and NIST standards with
> citations.
>
> Its main technical difference from a per-session security scanner is that it reasons across
> every session in a capture, not just one at a time — which resolves a real ambiguity: a client
> declining STARTTLS looks identical, in isolation, to an attacker stripping it. Comparing that
> session against others from the same server in the same capture tells them apart.
>
> It also refuses to convert missing evidence into a verdict. TLS 1.3 encrypts the certificate by
> design, so a TLS 1.3 session correctly reports 'certificate not observable,' never 'certificate
> invalid.' An included unsupervised ML model provides a secondary ranking signal on top of the
> deterministic findings — evaluated honestly, it currently adds no proven detection value, and
> the tool says that rather than hiding it. Output is a scored posture assessment, prioritised
> findings, and exportable JSON, PDF, and HTML reports."

## 2 minutes

> "SecureMailScope is a passive network forensic tool that assesses the transport-layer security
> of email traffic — SMTP, IMAP, and POP3, including their implicit-TLS variants (SMTPS, IMAPS,
> POP3S) — from a PCAP capture file. It never connects to a live server, needs no private keys,
> and reads no message content: everything it reports comes from what the capture's own
> handshakes and protocol dialogue show.
>
> **What it does.** It reconstructs each session's protocol state machine, detects and validates
> STARTTLS/STLS upgrades, identifies the negotiated TLS version, cipher suite, and key-exchange
> mechanism, extracts X.509 certificate details where the handshake exposes them in cleartext, and
> assesses forward secrecy and a bounded set of insecure-configuration patterns — each finding
> cited to a specific RFC or NIST publication, not an invented weight.
>
> **Why passive-only, and why that matters.** Active scanning or key material would answer a
> different, easier question — the certificate right now, not the certificate actually used in
> the captured session. That distinction matters for incident response and audit use cases, where
> the question is what happened, not what's currently configured.
>
> **The differentiator.** Every per-session security scanner — including every other SIH26159
> submission audited so far by source code, not by README claims — evaluates one connection at a
> time. That makes a genuinely important ambiguity unresolvable: a session where STARTTLS was
> never advertised looks byte-identical, within that one session, whether the server never
> supported it or an attacker stripped it in transit. SecureMailScope resolves that by comparing
> a session against every other session observed with the same server in the same capture — a
> capability verified absent from every competing implementation examined.
>
> **How it stays honest.** Every conclusion carries one of six evidence states — observed,
> inferred, unknown, ambiguous, incomplete, or not-observable — never collapsed into a binary
> secure/insecure. TLS 1.3 encrypts the certificate by protocol design, so a TLS 1.3 session
> correctly reports the certificate as not observable rather than guessing at it or, worse,
> reporting it as invalid. Certificate trust and revocation are stated as genuinely unavailable
> from passive evidence alone, rather than claimed and quietly wrong. And an included unsupervised
> ML model, required by the problem statement's explicit AI/ML mandate, is proven — end to end,
> with the exact same security conclusions produced with it switched on or off — to be a secondary
> ranking signal only. It currently demonstrates no independent detection value on the data
> available, and the tool reports that fact rather than manufacturing a positive result.
>
> **Output.** A scored, coverage-aware posture assessment, prioritised findings with remediation
> guidance, and exportable forensic reports in JSON, PDF, and HTML — plus an interactive dashboard
> for an analyst working through a batch of captures. Everything runs offline, with zero
> third-party runtime dependencies in the core analysis engine."
