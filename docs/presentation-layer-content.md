# SecureMailScope presentation copy

Text the running app shows. Values in `{braces}` are filled from the loaded analysis, the health check, or the file the user picked. They are not written in the page.

Browser title: SecureMailScope: Cryptographic Security Posture Assessment

---

## Shell

Skip to main content

**Brand:** SecureMailScope

**Case:** `{filename}` — Active capture: `{filename}` (`{n}` sessions, `{n}` findings). Click to switch.

**Score:** `{STRONG | ADEQUATE | WEAK | CRITICAL | INSUFFICIENT EVIDENCE | POSTURE WITHHELD}` `{score} / 100`

**Status:** Demo Fixture — or — Engine Live

**Actions:** ⌘K · ? · + Intake

**Rail**

- Understand — Overview 1 · Findings 2
- Investigate — Protocol 3 · Certificates 4 · Cross-Session 5
- Trace — Provenance 6
- Deliver — Report 7
- Demo Fixture — or — Engine Live · 0.8.0

**Load failure:** This investigation could not be loaded. The analysis engine returned no data for this run. Back to Case Desk

---

## Home

Secure email analysis

Check whether an email connection is secure.

Upload a saved recording. The mail server is never contacted.

.pcap · .pcapng · .cap

**How a check works**

1. Upload a recording — Select a .pcap, .pcapng or .cap file.
2. Check security — We analyse the recording locally.
3. Read the score and report — Get a score with a short report.

**Check a recording**

Upload a saved email capture. You get a score and a short report.

Choose file · or drag and drop it here

.pcap, .pcapng, or .cap · up to `{size, default 256 MB}`

**File staged**

Capture staged for forensic analysis · Change file

`{filename}` · `{size}` · Format: `{EXT}` · SHA-256 `{hash or Computing…}`

Deterministic rules & cross-session reasoning will be executed locally.

Analyze Capture

**While it runs**

Analyzing capture

Reconstructing the email connection and checking its security...

`{filename}` · `{size}` · (`{n}`s limit)

**If it fails**

This recording could not be checked

`"{filename}" is not a recognized packet capture format. Please provide a .pcap or .pcapng file.`

`"{filename}" ({size}) exceeds the maximum allowed upload limit of {limit}.`

Technical diagnostic details · Retry Analysis · Choose a different file

**If the engine is down**

The analysis service is unavailable. Saved checks can still be opened. New recordings cannot be checked until it is back.

**Recent checks**

`{n}` total recorded — or — Loading…

No checks yet. Upload a recording above. Finished checks will appear here.

`{posture}` `{score} / 100` `{filename}` Active `{time}` `{n}` sessions · `{n}` findings · Open

`{n}` unfinished checks hidden.

**Try an example**

- Outdated certificate — This server's certificate is old and easy to break. CRITICAL 44.0 / 100 · Open
- Encryption missing on one server — One server offers a secure upgrade. A matching server does not. CRITICAL 22.15 / 100 · Open
- Not enough to judge — This recording does not show the certificate, so no fault is claimed. STRONG 100.0 / 100 · Open

---

## Overview

**Determination**

`{STRONG | ADEQUATE | WEAK | CRITICAL}` `{formula id}` `{score} / 100`

Clean capture: TLS on every observed session. No plaintext credentials on the wire.

Otherwise one of:

- Authentication activity was observed without TLS protection across `{n}` sessions.
- Cryptographic weaknesses detected in X.509 certificate (RSA-1024 / SHA-1) on SMTPS :465.
- STARTTLS baseline deviation detected between subject and control endpoints across `{n}` sessions.
- Mail sessions exchanged without TLS transport encryption across `{n}` sessions.
- `{finding conclusion or title}`
- Cryptographic security assessment completed with findings requiring forensic review.

`{severity}` `{certainty}` `{rule id}` `{standard}` `{n}` sessions affected

Clean capture: `{n}` sessions assessed · Compliant

Other verdicts · None on this capture. · Also recorded on this capture.

Open Frame #`{n}` · Trace Provenance · Inspect Finding

**Why this score**

Baseline 100, then rule deductions. One control: Inspect calculation.

| Row | Label | Note | Value |
|---|---|---|---|
| Start | Baseline | Full score before deductions | `{100.00}` |
| Middle | No deductions | - | 0.00 |
| Middle | `{issue}` · `{n}` sessions | Rule deduction | −`{penalty}` |
| End | Final score | `{formula id or Deterministic scoring}` | `{score}` · `{band or UNRATED}` |

No deductions applied. — or — −`{total}` total deduction across `{n}` factor groups

**Score breakdown**

Component · Severity · Sessions · Weight · Multiplier · Penalty

Starting score `{n}` · Total penalty `{n}` · Final score `{n}`

The engine reported no penalty components for this capture.

`{posture basis}` · `{withheld note}`

**Proof**

No violations

All observed protocol handshake messages established transport layer security.

PROTOCOL_TRANSPORT TLS_PROTECTED · PLAINTEXT_CREDENTIALS NONE_OBSERVED · EVALUATED_FRAMES `{#first–#last or All frames}`

Open handshake

When a finding exists: AUTH_ACTIVITY · TLS_TRANSITION · PUBLIC_KEY RSA 1024-bit · SIGNATURE_ALGORITHM SHA-1 · STARTTLS_ADVERTISED FALSE (Subject: 10.0.0.6) · CONTROL_ENDPOINT TRUE (Control: 10.0.0.7) · ISSUE_CLASS · STATUS · FRAME · STREAM · OBSERVED

Open Frame #`{n}` · Trace · Inspect finding

**Investigation path**

Capture bytes → wire events → posture · Click a node

Capture bytes · Wire events · Frame #`{n}` · `{n}` TCP sessions · Protocol analysis · Findings · `{n}` findings · Score & posture

**Observability boundary**

What this capture can prove

Established: Wire-level protocol events · TLS transitions · Observable certificates · Cross-session deviations

Not observable: Attacker identity · Server-side configuration · Trust store validation · Revocation when unavailable · Encrypted TLS 1.3 certificate content

Limitations — or — Hide limitations

Normative Limitations · `{limitation from the analysis}`

Engine Abstentions (`{n}`): `{what could not be concluded}`: `{why}` (Resolution: `{resolved by}`)

**Investigate further**

- Ranked Findings — Severity, certainty, and the frames for each finding. — Inspect Findings
- Protocol Journey — SMTP, IMAP, and POP3 from greeting to close. — Open Protocol Journey
- Certificate Forensics — Key size, signature algorithm, and TLS 1.3 visibility. — Examine Certificates
- Cross-Session Analysis — Compare TCP sessions for the same service. — or — Active behavioral deviation: Subject 10.0.0.6 lacks STARTTLS capability advertised by Control 10.0.0.7. — Compare Sessions
- Traceability & Provenance — PCAP bytes, rule citation, and the posture score. — Trace Chain
- Forensic Report — Posture assessment as PDF, HTML, or JSON. — Generate Report

**Case strip**

`{filename}` / SHA-256 `{hash}` · `{n}` TCP sessions · `{n}` findings · `{duration}` ms · engine `{version}` · analysed `{time}`

---

## Findings

What is wrong, how serious it is, and the evidence.

Filter · `{Observed | Inferred | Unknown | Ambiguous | Incomplete | Not observable}`

**Findings** `{n}`

No findings in this capture.

`{severity}` `{title}` · Open Frame #`{n}` · Trace provenance

**Focused evidence**

Select a finding.

`{finding title}`

What happened — `{conclusion, or: This capture was checked against the mail-security rules.}`

Why it matters — `{explanation}`

Evidence — No cited fields for this finding. — or — Assessment failed to load: `{error}`

`{field}` `{value}` `{state}` Frame #`{n}` `{basis}` · More · Less

Technical details · Rule `{id}` · Standards `{citation}` · What to do `{action}` · Limits of this capture

Trace provenance

**Session evidence** `{client → server}`

Stream `{#id protocol client → server}`

Endpoints not recorded. — or — Missing side shown as not recorded.

| Label | Value | Status | Explanation | Frame |
|---|---|---|---|---|
| STARTTLS advertised | `{value or —}` | `{state}` | `{basis}` | `{frame}` |
| STARTTLS requested | | | | |
| STARTTLS accepted | | | | |
| TLS transition | | | | |
| Plaintext continuation | | | | |
| TLS version | | | | |
| Cipher suite | | | | |
| Cipher suite ID | | | | |
| Key exchange | | | | |
| Named group | | | | |
| Forward secrecy | | | | |
| Certificates in chain | | | | |
| Authentication activity | | | | |

Groups: Transport & upgrade · Negotiated parameters · Certificate · Authentication

A row appears only when that field is in the session.

Session evidence failed to load · No evidence recorded for this capture

---

## Protocol

Protocol journey

One TCP stream, in frame order.

Stream `{#id protocol client → server}`

Client `{ip:port or not recorded}` · Server `{ip:port or not recorded}` · Protocol `{name or not identified}` · Application `{state}` · TLS `{state}` · Capture `{completeness}` · Packets `{n}` · Frames `#{first} to #{last}` · Duration `{n}` ms

**Protocol progression**

Click a row to open that frame.

| Frame | State | Evidence |
|---|---|---|
| `{first}` | CONNECTED | TCP session up |
| `{frame}` | GREETING | `{detail or Server greeting}` |
| `{frame}` | EHLO | `{detail or Client EHLO}` |
| `{frame}` | CAPABILITIES | `{detail or Server capabilities}` |
| `{frame}` | STARTTLS ADVERTISED | Upgrade offered |
| `{frame}` | TLS UPGRADE | STARTTLS accepted |
| `{frame}` | PROTECTED CHANNEL | `{n}` Cert(s) Inspected — or — TLS 1.3 Active |
| `{frame}` | STARTTLS NOT ADVERTISED | Absent from the 250 — or — Upgrade not advertised |
| `{frame}` | PLAINTEXT AUTH | Credentials without TLS |
| `{frame}` | AUTHENTICATION | Protected authentication |
| `{frame}` | PLAINTEXT CONTINUATION | Cleartext after AUTH |
| `{last}` | CLOSED | Session ended |

Rows appear only when the session matches that step.

**Raw event timeline**

Frame, direction, event, and evidence state, in order.

Failed to load protocol data · No protocol events in this capture · Stream #`{n}` carried no dissected protocol messages or state transitions.

---

## Certificates

X.509 certificates parsed from cleartext handshake records. Trust anchors and revocation are not observable from a passive capture.

Stream `{label}`

**Weak certificate**

CRYPTOGRAPHIC WEAKNESS · Public Key · Signature Algorithm · SHA-1 signature · Severity HIGH · Evidence Frame #`{n}`

Why it matters — `{explanation, or: The RSA-1024 key size and SHA-1 signature algorithm fail modern minimum cryptographic standards (RFC 8996, NIST SP 800-52r2) and are vulnerable to factorization and collision attacks.}`

Open Frame #`{n}` in Protocol Journey · Inspect technical certificate details · Hide technical certificate details

**Nothing in the clear**

CERTIFICATE CONTENT: NOT OBSERVABLE · RFC 8446 Encrypted Handshake

Under TLS 1.3 (RFC 8446), the server Certificate and CertificateVerify messages are encrypted under temporary handshake keys. In a passive offline capture without private key disclosure, the certificate payload cannot be dissected in cleartext.

Observable on wire

- TLS mode and version negotiation (TLS 1.3 negotiated)
- Handshake structure and record sequencing (ClientHello, ServerHello)
- Available wire metadata, cipher suite ID, and key exchange group

Not observable from capture

- Certificate payload and X.509 public key modulus (encrypted in flight)
- Intermediate chain hierarchy and authority key identifiers
- Local trust store validation and revocation status (OCSP/CRL)

Forensic honesty boundary

SecureMailScope performs strictly passive offline wire dissection. Without active adversary interception or endpoint key disclosure, the encrypted certificate payload is cryptographically protected and deliberately reported as NOT_OBSERVABLE rather than fabricated.

Open Handshake in Protocol Journey

**Certificate fields**

none reported · Public key · Valid from · Valid until · Serial · X.509 version · Subject key ID · Authority key ID · Self-signed · SAN DNS names

Certificate chain evidence · Technical certificate details · `{n}` certificate(s) · Not attributable from this capture

Failed to load certificate data · No sessions in this capture

---

## Cross-session

How each TCP stream in this capture compares, field by field. Determinations come from the engine's baseline and control-endpoint reasoning, not from this view.

Single-session capture. Cross-session comparison requires multiple TCP streams to the same service.

Failed to load session data

**Control-endpoint comparative analysis**

`{n}` total streams evaluated

SUBJECT ENDPOINT `{ip}` · STARTTLS NOT OBSERVED (`{n}` sessions) · AUTH · VS

CONTROL BASELINE `{ip}` · STARTTLS OBSERVED (`{n}` sessions) · TLS

Dimension · Divergence

NOT OBSERVED · OBSERVED · Divergent · CLEAR · ESTABLISHED · PLAINTEXT · PROTECTED

SUPPORTED DEVIATION (CS-STARTTLS-001)

“This endpoint consistently lacks the upgrade capability while comparable endpoints at the same server consistently have it.”

Forensic boundary: This supports a deviation from comparable endpoint behaviour. It does not establish capability removal, attacker identity, or causality beyond the observed capture.

**Engine determinations**

`{SUSPICIOUS DEVIATION | DEVIATION | NONE | NOT ASSESSED}` · `{severity}` · `{rule}` · subject stream #`{n}` · frame `{n}`

`{conclusion or title}` · `{explanation}` · `{standards}`

**Matrix**

Full evidence matrix by session · `{n}` streams

Cells show each stream's reported value, tinted by evidence state. Rows marked "varies" differ between streams; a difference is evaluated under the engine's deterministic baseline rules.

Field · varies · Evidence by session · subject of a cross-session finding · no value · Not reported

Collapse session matrix · Open full `{n}`-session matrix

---

## Provenance

The forensic trace from capture bytes to a posture deduction: which stream, which evidence fields and frames, which rules, which standards.

No findings to trace. The capture has zero findings.

No findings for this capture. There is nothing to trace.

Findings · Evidence chain

1. CAPTURE — `{filename}` · SHA-256
2. TCP STREAM #`{n}` — `{client} → {server}` — Finding observed across `{n}` sessions
3. WIRE FRAME — Frame #`{n}` — Jump to packet dissection →
4. WIRE EVIDENCE — `{field}` = `{value}` `{state}` — or — EVALUATION · Observed wire evidence
5. DETERMINISTIC RULE — `{rule id}`
6. NORMATIVE STANDARD — `{standard}`
7. POSTURE FINDING — `{severity}` `{certainty}` `{status}` `{title}`
8. SCORE DEDUCTION — −`{n}` pts — or — Rule deduction · F2-group-damped scoring

---

## Report

FORENSIC ASSESSMENT

`{posture}` `{score} / 100`

Capture: `{filename}` · Sessions: `{n}` evaluated · Findings: `{n}` confirmed · Engine: `{version}` · SHA-256: `{hash}`

PDF · HTML · JSON

Report artifacts & verifiable signatures

Format · Renderer · Schema · Status · SHA-256 Digest · Rendered · Ready

Evaluation under deterministic rule engine

Complete deterministic provenance chain from wire frames to posture assessment.

Rendering report…

Run an analysis to generate a report

Report generation failed

Report unavailable. No assessment data is loaded for this capture.

**Document**

SecureMailScope forensic report

Cryptographic security posture assessment

Capture · SHA-256 · Assessment · Generated · Engine · ML lane enabled (ranking only) — or — disabled

Determination · `{score basis}`

Findings that lowered the score · `{title}` · `{certainty}` · `{n}` sessions · `{citation}`

Remediation · Action: `{action}` · Verify: `{check}`

What the engine declined to conclude · `{n}` abstentions · Engine note: `{note}`

Limitations · Provenance

---

## Command palette

Jump to a view, finding, session or analysis

Esc · ↑↓ move · Enter open · Esc close

- Summary — Posture, score and findings — 1
- Evidence & Findings — Each finding with the evidence it cites — 2
- Protocol Journey — Events, evidence and transitions per session — 3
- Certificates — Certificate evidence per TLS session — 4
- Cross-Session — Sessions compared, with engine deviations — 5
- Provenance — Trace a finding back to capture bytes — 6
- Report — Preview and download HTML, PDF, JSON — 7
- Home — Upload a capture or open a recent analysis
- Keyboard shortcuts

Findings, sessions, and analyses in the list use their titles from the loaded run.

## Open an analysis

Filter by filename, SHA-256 or posture

`{filename}` · `{posture}` · `{score}` · `{time}`

## Keyboard shortcuts

Views: 1 Summary · 2 Evidence & Findings · 3 Protocol Journey · 4 Certificates · 5 Cross-Session · 6 Provenance · 7 Report · ← → Previous or next tab when the tab bar has focus

Anywhere: ⌘K / Ctrl K Command palette · ? This list · Esc Close the open dialog

Command palette: ↑ ↓ Move through results · Enter Open the selected result

---

## Words used across screens

**Posture:** STRONG · ADEQUATE · WEAK · CRITICAL · INSUFFICIENT EVIDENCE · POSTURE WITHHELD

**Evidence state:** Observed · Inferred · Unknown · Ambiguous · Incomplete · Not observable

**Finding status:** OBSERVED ISSUE · COMPLIANT · INFORMATIONAL · AMBIGUOUS · INSUFFICIENT EVIDENCE · NOT OBSERVABLE

**Certainty:** `{value from the analysis}` · Certainty not reported

**Missing endpoint:** not recorded · endpoints not recorded

**Basis lines the page rewrites when it recognizes them**

- Certificate was visible during the handshake.
- STARTTLS does not apply. The session started in TLS.
- TLS started. A completed handshake was not proven.
- Encrypted from the first record.
- TLS version comes from the ServerHello.
- Name of cipher suite 0xc030.
- Cipher suite chosen in the ServerHello.
- No named group was seen in the ServerHello.
- Login details stay inside TLS and cannot be read here.
- Key exchange is part of `{suite}`.
- This cipher uses ECDHE, so it has forward secrecy.

Any other basis sentence is shown as the analysis wrote it.
