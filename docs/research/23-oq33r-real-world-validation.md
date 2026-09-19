# 23 — OQ-33r: Real-World Multi-Vendor Validation

**Date:** 2026-09-20 · **Verdict: PASS WITH LIMITATIONS**
**Corpus:** `research/experiments/oq33r/` · **Matrix:** `results/validation-matrix.json`
**Tests:** `tests/test_posture_corpora.py` (real-vendor section)

---

## 1. What this closes, and what it does not

Every SecureMailScope evaluation number before this document rests on captures **our own
generators produced**. OQ-33r has been the named blocking gap since Phase 6: a model, a
parser and a score validated only against traffic we invented tell us about our
generators, not about mail servers.

This validation runs the full pipeline over traffic whose application bytes were emitted
by **Postfix** and **Dovecot** — two independently written codebases whose banners,
capability ordering, continuation style, timing and segmentation we do not control and
did not design around.

It does **not** close the gap entirely. See §6.

## 2. Environment

| Capability | Status |
|---|---|
| Live capture on the host | ❌ `/dev/bpf0` is root-only; no sudo available |
| Docker | ✅ via a **pre-existing** Colima VM (not started by this work) |
| Network for image pulls | ✅ |
| Host Postfix/Sendmail binaries | present, but running them needs root and mutates the host |

Approach: real servers in a disposable container, `tcpdump` on the container's loopback,
driven by Python's own `smtplib` / `imaplib` / `poplib`. Genuine packets, genuine server
software, no host changes.

**Safety:** throwaway container, one local account, synthetic message text, a self-signed
certificate generated per run and **git-ignored**, no real mail and no personal data. The
container was removed afterwards; pre-existing images were untouched.

## 3. Corpus

**10 scenarios, 10 captured, 64 KB total.**

| Vendor | Protocol | TLS mode | Scenario |
|---|---|---|---|
| Postfix | SMTP | STARTTLS | upgrade completes |
| Postfix | SMTP | STARTTLS | advertised, client declines |
| Postfix | SMTP | cleartext | plaintext session |
| Postfix | SMTP | none | STARTTLS not offered (`smtpd_tls_security_level = none`) |
| Dovecot | IMAP | STARTTLS | upgrade completes |
| Dovecot | IMAP | cleartext | plaintext LOGIN |
| Dovecot | POP3 | STARTTLS | STLS upgrade completes |
| Dovecot | POP3 | cleartext | plaintext USER/PASS |
| Dovecot | IMAP | implicit | IMAPS on 993 |
| Dovecot | POP3 | implicit | POP3S on 995 |

Diversity achieved: **2 vendors · 3 protocols · 4 TLS modes** (cleartext, STARTTLS,
implicit, none).

## 4. Results — 10 / 10 PASS

Each row was checked three ways: the scenario's declared expectation, SecureMailScope's
conclusion, and an **independent raw-byte read by tshark**.

| Vendor | Proto | Scenario | Advertisement | TLS | Version | Issues | Band |
|---|---|---|---|---|---|---|---|
| postfix | smtp | starttls_upgrade | `True/OBSERVED` | ESTABLISHED | TLS1.3 | SEC-PLAIN-002 | ADEQUATE 88 |
| postfix | smtp | client_declines | `True/OBSERVED` | NONE | — | SEC-PLAIN-002 | ADEQUATE 88 |
| postfix | smtp | plaintext_session | `True/OBSERVED` | NONE | — | SEC-PLAIN-002 | ADEQUATE 88 |
| postfix | smtp | no_starttls_offered | **`False/AMBIGUOUS`** | NONE | — | SEC-PLAIN-002 | ADEQUATE 85 |
| dovecot | imap | starttls_upgrade | `True/OBSERVED` | ESTABLISHED | TLS1.3 | SEC-PLAIN-002 | ADEQUATE 88 |
| dovecot | imap | plaintext_login | `True/OBSERVED` | NONE | — | **SEC-PLAIN-001**, SEC-PLAIN-002 | **WEAK 60** |
| dovecot | pop3 | stls_upgrade | `True/OBSERVED` | ESTABLISHED | TLS1.3 | — | **STRONG 100** |
| dovecot | pop3 | plaintext_login | `True/OBSERVED` | NONE | — | **SEC-PLAIN-001**, SEC-PLAIN-002 | **WEAK 60** |
| dovecot | imap | imaps_implicit_tls | **`None/NOT_OBSERVABLE`** | ESTABLISHED | TLS1.3 | — | STRONG 100 |
| dovecot | pop3 | pop3s_implicit_tls | **`None/NOT_OBSERVABLE`** | ESTABLISHED | TLS1.3 | — | STRONG 100 |

### The four results that matter most

1. **Postfix genuinely not advertising yields `False/AMBIGUOUS`, not a confident
   negative.** The project's central discipline — absence of a STARTTLS advertisement is
   ambiguous, because stripping and non-support are byte-identical — now holds on real
   vendor traffic, not only on captures built to demonstrate it.

2. **Implicit TLS yields `NOT_OBSERVABLE`.** On IMAPS and POP3S there is no cleartext
   capability exchange at all, and the engine says so rather than reporting absence.

3. **Plaintext authentication is detected on real Dovecot traffic.** `SEC-PLAIN-001`
   fires on genuine cleartext IMAP LOGIN and POP3 USER/PASS, producing WEAK 60. This is
   a real security detection on software we did not write.

4. **TLS 1.3 was correctly extracted from real OpenSSL handshakes.** The
   `supported_versions` handling (RFC 8446 §4.2.1) — the trap that would misreport TLS
   1.3 as TLS 1.2 — is validated against genuine handshakes for the first time.

## 5. One failure, and it was ours

The first validation run reported **4 FAIL / wrong-security-claim** on the Dovecot rows:
"we report an advertisement tshark does not see".

That was **a defect in the validation harness, not in the product**. The comparison used
`imap.response.command contains "STARTTLS"` and `pop.response.description contains
"STLS"`. Neither field carries what was assumed: IMAP capabilities arrive on untagged
`*` lines, and tshark exposes the POP3 CAPA body as empty strings — the same dissector
gap Phase 2 already had to work around. The client logs settled it independently:
`poplib.capa()` returned `STLS`, and `imaplib.starttls()` succeeded, so the capability
was unambiguously on the wire.

The comparison now asks tshark for the **raw bytes** from the server side
(`tcp.srcport==… && tcp contains "STARTTLS"`), which is genuinely independent of the
per-protocol dissector. Classification: **test-infrastructure issue**, recorded rather
than quietly corrected — a harness that agrees with the product by construction validates
nothing.

## 6. Limitations — what remains unvalidated

1. **Two vendors, not five.** Exim was built (`Dockerfile.exim`) but not driven; Zimbra
   and Sendmail were not attempted. Postfix + Dovecot covers the SMTP and IMAP/POP3
   sides, not MTA diversity.
2. **Loopback only.** No WAN path, no MTU-driven segmentation, no loss, no reordering,
   no middleboxes. The OQ-47 segmentation cases remain crafted, because a loopback path
   does not produce them naturally.
3. **One client stack.** Python's `smtplib`/`imaplib`/`poplib`. No Thunderbird, Outlook,
   or mobile client behaviour.
4. **Default-ish configurations.** No deliberately weak local server configs (deprecated
   TLS versions, weak ciphers) were exercised, so `SEC-TLS-001` has still only been
   validated against crafted captures.
5. **Small populations.** One or two sessions per capture, so cross-session reasoning —
   the Phase-5 mechanism — is **not** exercised by this corpus at all. Baselines need ≥5
   comparable sessions.
6. **No message-content diversity.** Synthetic bodies only, by design.

## 7. Verdict

> **PASS WITH LIMITATIONS.**

Passing is justified: 10/10 scenarios, 2 real vendors, 3 protocols, 4 TLS modes, every
conclusion agreeing with an independent raw-byte read, and the two evidence-discipline
properties that matter most (ambiguous absence, unobservable implicit TLS) holding on
software we did not write.

"With limitations" is equally justified: this does not validate MTA diversity, WAN path
behaviour, client diversity, weak-crypto detection, or cross-session reasoning. The
Phase-6 statement that ML generalisation is unestablished is **unchanged** — this corpus
is far too small to revisit it, and no ML claim is made on the strength of it.

## 8. Reproduction

```bash
export DOCKER_HOST="unix://$HOME/.colima/default/docker.sock"
docker build -t sms-oq33r -f research/experiments/oq33r/Dockerfile research/experiments/oq33r
docker run --name sms-oq33r-run --rm -d --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$PWD/research/experiments/oq33r:/corpus" sms-oq33r sleep 3600
docker exec sms-oq33r-run python3 /corpus/capture.py
docker rm -f sms-oq33r-run
PYTHONPATH=src python3 research/experiments/oq33r/validate.py
```

Captures are committed (64 KB); the certificate and key are regenerated per run and
git-ignored. Packet timings and TLS randoms differ between runs, so the pcaps are **not**
byte-reproducible — unlike the crafted corpora, which are.

## 9. Next steps for OQ-33r

1. Drive the Exim image (already built) for MTA diversity.
2. Add deliberately weak local configurations to validate `SEC-TLS-001` against a real
   server negotiating TLS 1.0/1.1.
3. Generate multi-session populations (≥5 per client/endpoint) so cross-session
   reasoning is exercised on real traffic.
4. Introduce a constrained-MTU path so segmentation arises naturally rather than by
   construction.
