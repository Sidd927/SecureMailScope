# 01 — Project truth model

What SecureMailScope actually is, reconstructed from the repository, not from a template. Every
claim here is traceable; anything uncertain is marked.

---

## A. What is the problem?

Email transport security fails **silently and invisibly**. A mail session can be downgraded to
plaintext, negotiate a deprecated TLS version, or present a weak certificate, and nothing in the
mail itself records that. After an incident, the only durable evidence is often a packet capture.

The hard part is that **the evidence is encrypted and incomplete by design**:

- TLS 1.3 encrypts the certificate (RFC 8446 §2) — a passive observer cannot see it *at all*,
  regardless of tooling. Measured: **0 of 10** real captures in this project's corpus expose a
  certificate; all 10 negotiate TLS 1.3.
- A session where STARTTLS was never advertised is **byte-identical** whether the server never
  supported it or an attacker stripped it in transit. Within one session, the distinction is
  genuinely unresolvable.
- Certificate **trust** cannot be established from a capture at all: RFC 5280 §6 path validation
  requires trust anchors a PCAP does not contain.

So the real problem is not "parse TLS from PCAP" (tshark already does that). It is: **how do you
produce a defensible security conclusion when the evidence is partly encrypted, partly ambiguous,
and partly absent — without guessing?**

## B. Who experiences the problem?

Supported by the PS text itself (`docs/research/19-authoritative-ps-verification.md` §8, item 5):
**SOC analysts, digital-forensics investigators, incident-response teams, and enterprise mail
administrators.** The PS names these users; this is not an invented persona.

## C. What is the input?

A **PCAP capture file** containing SMTP, IMAP, or POP3 traffic — explicit TLS (STARTTLS/STLS) or
implicit TLS (SMTPS/IMAPS/POP3S), on standard or non-standard ports. Nothing else. No keys, no
server access, no live traffic, no message content.

## D. What does the system actually do?

```
PCAP
 → tshark dissection (exit-code-typed: OK / EMPTY / TRUNCATED / MALFORMED / TOO_LARGE)
 → crypto reference derivation (suite → key exchange; OID → algorithm; modulus → key length)
 → per-protocol session reconstruction (SMTP / IMAP / POP3 state machines, explicit + implicit TLS)
 → 16 deterministic single-session rules, each bound to an RFC/NIST citation
 → 3 cross-session rules over per-server baselines (≥5 comparable sessions required)
 → ML anomaly lane (unsupervised, bounded, secondary — never creates a finding)
 → evidence fusion + F2-group-damped posture scoring (coverage-gated)
 → SQLite catalogue + content-addressed artifact store
 → JSON / HTML / PDF reports + 4-screen analyst dashboard
```

## E. What does it output?

A **canonical `PostureAssessment`**: a coverage-aware posture band and score, prioritised findings
with remediation and standards citations, explicit abstentions with what would resolve each, full
provenance (frame numbers, TCP stream, timestamps), and three export formats. Plus an interactive
dashboard over the same document — which recomputes nothing.

## F. What is the technical core?

| Layer | What it contributes | Verified |
|---|---|---|
| Packet ingestion | typed classification of untrusted input; SHA-256 capture identity | `tests/test_tshark_adapter.py` |
| Session reconstruction | protocol state machines, explicit + implicit TLS | Phase 3, regression suite |
| Deterministic analysis | **16 rules**, every finding citing one of **11 distinct standards** (RFC 2595, 3207, 5280, 6960, 8314, 8446, 8996, 9155; NIST SP 800-52r2, 800-57, 800-131A) | verified by enumerating `ALL_RULES` |
| Cross-session reasoning | **3 rules**, per-server baselines, ≥5 comparable sessions | `crosssession/rules.py` |
| Evidence fusion | six evidence states never collapsed — **`OBSERVED · INFERRED · UNKNOWN · AMBIGUOUS · INCOMPLETE · NOT_OBSERVABLE`** (this is `EvidenceState`; `INSUFFICIENT_EVIDENCE` belongs to `FindingStatus` and `NOT_APPLICABLE` to `BaselineStatus` — see `DO-NOT-CLAIM.md` §A) | `evidence/states.py` |
| Posture scoring | `F2-group-damped`; INFO 0 → CRITICAL 55 weights; band withheld below 50% coverage | `posture/scoring.py` |
| ML | `robust-z-sum`, bounded at **4.0** against a **30-point** severity-tier gap | `MAX_ML_ADJUSTMENT`, verified |
| Reporting | one model → 3 formats, byte-deterministic, `report_sha256` identity | Phase 9 |
| Provenance | PCAP SHA-256 → capture_id → frame/stream/timestamp → finding → report | Phase 11 `EvidenceRef` |

## G. What is actually new/different?

Not "we use tshark" — everyone does. The two genuinely defensible differentiators:

1. **Cross-session reasoning.** Baselines are built from **prior comparable sessions at the same
   endpoint, protocol and TLS mode** (`DEFAULT_MIN_HISTORY = 5`), not from "every session with the
   server". A source-code audit of five competing SIH26159 implementations
   found every one reasons about a single session at a time; cross-session reasoning was
   **verified absent from all five** (`docs/research/01D-sih-competitor-source-audit.md` §4). This
   is what resolves the STARTTLS stripping-vs-non-support ambiguity that is unresolvable within a
   single session.
2. **Uncertainty preserved as a first-class output.** Six evidence states, coverage-gated scoring,
   and explicit abstentions mean missing evidence never becomes a security verdict in either
   direction. One competitor has a partial equivalent (a `NOT_OBSERVABLE` posture state); none
   applies it as an end-to-end discipline.

Honest framing: this is **integration-grade differentiation for this problem**, not research
novelty — cross-connection correlation is standard practice in network security monitoring
generally (Zeek, Arkime).

## H. What is proven?

- **1234 tests**, 0 failures, 0 skips — run 3× independently in finalization.
- **10 real captures** (Postfix + Dovecot, SMTP/IMAP/POP3, 4 TLS modes) score identically before
  and after the Phase-11 certificate work — zero regression, verified against the tag.
- **Cross-session reasoning demonstrated live** on real multi-session data: a `MEDIUM` finding
  where one client deviates from 6 other clients at the same server, and the honest negative case
  (no control endpoint → `COMPLIANT` + explicit stated limitation).
- **`--no-ai` equivalence proven end-to-end**: identical posture, score, and penalising findings
  with the ML lane on or off (`demo/expected/scene_c_no_ai_equivalence.json`).
- **Certificate analysis works where observable**: a generated TLS 1.2 capture yields 38 distinct
  X.509 fields; RSA-1024 and SHA-1 both correctly flagged HIGH → CRITICAL posture (44.0).
- **Performance**: full PCAP → assessment in **115–320 ms**; 20/20 repeated demo executions stable.
- **0 third-party Python runtime packages** in the analysis core; **TShark is the required external dissection binary** — re-verified this phase.

## I. What is NOT proven?

Stated plainly, because pretending otherwise is the failure mode this project was built to avoid:

- **D-11 (certificate chain validation) — PARTIAL.** Chain *structure* is validated (ordering,
  AKI↔SKI linkage, self-signed detection). Chain *trust* and *revocation* are not, and cannot be,
  from passive evidence alone.
- **A-02 (AI anomaly detection) — PARTIAL.** The model is real, unsupervised, leakage-controlled
  and evaluated — and produced **zero unique true detections on every held-out split**, including
  after Phase-11 features were added. The limiting factor is the corpus (98.6% separable by
  generator), not the model.
- **Certificate extraction is validated only on generated fixtures**, because the entire real
  corpus is TLS 1.3 and structurally cannot exercise it.
- **Scale is untested.** No capture beyond a few hundred KB has been run. No load testing exists.
- **Cross-session reasoning does not fire on the real 10-capture corpus** — those captures have
  too few same-server sessions to form a ≥5-session baseline. It is demonstrated on the golden
  corpus instead, which is real generated traffic but not real-world vendor traffic.
