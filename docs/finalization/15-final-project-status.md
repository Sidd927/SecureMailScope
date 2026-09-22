# Finalization — 15. Final project status

**The authoritative source of truth for the presentation and final submission materials.**
Everything below is drawn from, and citable to, a specific document, test, ADR, or execution
already performed in this repository — nothing is asserted without a pointer to its evidence.

---

### 1. What exactly does SecureMailScope do?

Reconstructs email transport-security behaviour from a passive PCAP capture — SMTP, IMAP, and
POP3, including implicit-TLS variants — and reports a cited, evidence-backed security posture:
TLS version and cipher, key exchange, X.509 certificate properties where a cleartext handshake
exposes them, forward secrecy, STARTTLS/STLS integrity, plaintext exposure, and insecure
configuration. It never connects to a mail server, needs no keys, and reads no message content.
*(`README.md`; `docs/finalization/05-project-explanation.md` for the four-length version.)*

### 2. What protocols are supported?

SMTP, IMAP, POP3 — explicit-TLS (STARTTLS/STLS) and implicit-TLS (SMTPS/IMAPS/POP3S), on standard
and non-standard ports. *(`docs/phase12/00-release-state-audit.md` §4 capability map.)*

### 3. What cryptographic properties are assessed?

TLS version and deprecation status, cipher suite, key-exchange mechanism, forward secrecy, X.509
certificate extraction/expiry/public-key-strength/signature-algorithm where visible, chain
structure, and a declared 7-item insecure-configuration checklist. 19 standards-bound rules total.
*(`docs/finalization/04-real-pcap-evidence-pack.md`.)*

### 4. What is observable?

Anything present in cleartext protocol dialogue or a cleartext TLS handshake: protocol state,
STARTTLS negotiation, TLS version/cipher/key-exchange, and — only when the handshake is TLS ≤1.2
and complete — the certificate itself. *(`docs/finalization/04-real-pcap-evidence-pack.md` §1, §3.)*

### 5. What is not observable?

Certificate content under TLS 1.3 (encrypted by protocol design, RFC 8446 §2 — measured this
phase: 0 of 10 real captures show a certificate, all TLS 1.3); certificate trust and revocation at
any TLS version (no trust anchor, no OCSP/CRL access, from passive evidence alone); attacker
identity or intent, at any layer. *(`docs/finalization/04-real-pcap-evidence-pack.md`;
`docs/finalization/08-open-requirements.md`.)*

### 6. How does session reconstruction work?

Per-protocol state machines (SMTP/IMAP/POP3) track the full dialogue — greeting, capability
negotiation, STARTTLS command/response, TLS handshake — and assign one of six evidence states
(`OBSERVED · INFERRED · UNKNOWN · AMBIGUOUS · INCOMPLETE · NOT_OBSERVABLE`) to every derived fact,
never collapsing them. *(`docs/phase12/00-release-state-audit.md` §3; `docs/phase12/07-forensic-honesty-audit.md`.)*

### 7. How does cross-session reasoning work?

Compares one session's behaviour against a baseline built from ≥5 comparable sessions to the same
server, distinguishing a genuine deviation from a self-consistent-but-unremarkable pattern. Real,
live example this phase: a client whose own history is self-consistent (5-for-5 no upgrade) is
still flagged `MEDIUM` because 6 *other* clients at the same server consistently do upgrade — a
capability difference no single-session analysis could see. The honest negative case — no control
endpoint exists at all — is reported `COMPLIANT` with an explicit stated limitation that passive
evidence alone cannot rule out consistent stripping in that situation.
*(`docs/finalization/06-cross-session-demo.md`, verbatim real engine output.)*

### 8. What does ML actually do?

Computes a bounded, unsupervised anomaly score (`robust-z-sum`) that can re-order findings within
one severity tier. Structurally cannot cross a tier boundary (`MAX_ML_ADJUSTMENT=4.0` against a
30-point tier gap). *(ADR-0015; `docs/finalization/10-final-judge-cheatsheet.md` §G.)*

### 9. What does ML NOT do?

Create, upgrade, or downgrade a finding. Detect anything with demonstrated value — zero unique
true detections on every held-out split tested, including the Phase-11 certificate/key-exchange
features specifically re-measured for this question. Change any security conclusion — proven,
not claimed: `demo/expected/scene_c_no_ai_equivalence.json`, generated this phase, shows identical
`overall_posture`, `score_value`, and `penalising_issue_classes` with AI on or off.
*(ADR-0024; `docs/finalization/08-open-requirements.md`.)*

### 10. How is evidence preserved?

Content-addressed at every layer: PCAP SHA-256 → `capture_id` → `assessment_id` (both
content-addressed, excluding run-specific fields) → `report_sha256`. Re-hashed on access, not
trusted from write time — verified live this phase via `list_artifacts(verify=True)`.
*(`docs/finalization/05-report-pack-audit.md` §4.)*

### 11. How is posture calculated?

`F2-group-damped` scoring: only `OBSERVED_ISSUE` findings penalise; the band is withheld below
50% assessed coverage, so missing evidence never produces a falsely reassuring score.
*(`docs/architecture/19-evidence-fusion-and-posture.md`; ADR-0016.)*

### 12. What reports are generated?

JSON (the canonical assessment, verbatim), HTML (standalone, zero-dependency, offline-openable),
and PDF (ReportLab-composed from the same model, text-extractable). All three verified this phase
against freshly generated reports — valid JSON, zero `<script>` tags, correct extractable PDF
content. *(`docs/finalization/05-report-pack-audit.md`.)*

### 13. What does the dashboard show?

Four screens — History, Overview, Findings, Evidence — rendering the canonical assessment. Computes
no security conclusion of its own. No packet-level drill-down, by design: the assessment contract
does not carry one. *(`README.md`; `docs/architecture/23-dashboard-architecture.md`.)*

### 14. What is technically differentiated?

Cross-session reasoning, verified absent from five audited SIH26159 competitor implementations by
direct source-code inspection — the one capability-level gap that survives that audit.
Forensic-honesty discipline (six evidence states, provenance, coverage-gated scoring, proven
`--no-ai` equivalence) enforced system-wide, not as an isolated feature.
*(`docs/research/01D-sih-competitor-source-audit.md`; `docs/phase12/02-technical-differentiation.md`.)*

### 15. What are the strongest empirical results?

All 10 real captures score identically to the Phase-10 baseline after Phase 11's certificate work
landed — re-verified this phase, zero regression. 20/20 repeated demo-scene executions succeeded
with stable results. `--no-ai` equivalence proven end-to-end, not merely asserted. Cross-session
reasoning fired a real `MEDIUM` finding on real multi-session data this phase, with the correct
honest negative case demonstrated alongside it. *(`docs/finalization/03-demo-rehearsal.md`;
`docs/finalization/06-cross-session-demo.md`.)*

### 16. What are the known limitations?

D-11 (certificate trust/revocation) and A-02 (ML detection value) — both PARTIAL, both with
specific, evidence-backed reasons, neither an unfinished-work gap. `main` frozen at Phase 3 by
process choice. Real corpus is 100% TLS 1.3, so certificate extraction validation rests on
generated fixtures. No dashboard screenshots yet exist in the demo bundle.
*(`docs/finalization/14-final-release-gate.md` "KNOWN LIMITATIONS".)*

### 17. Which SIH requirements are complete?

24 of 31 tracked requirements: D-01–09, D-12–15, D-17, D-18, A-01, A-03–05, R-01–05, and the
confirmed-inference set (I-01, I-02, I-03, I-05, I-06, I-08). *(`docs/phase12/01-final-requirements-audit.md`.)*

### 18. Which are partial?

D-10, D-11, D-12, D-13, D-14 ("complete where observable" — a structural, protocol-level boundary,
not an engineering gap), D-16 ("complete, bounded" — a declared, versioned interpretation of an
underspecified PS phrase), A-02, I-04, I-07. *(same document.)*

### 19. What remains future work?

D-11 operator-supplied trust anchors (reserved, scoped, not authorized —
`docs/phase12/14-proposed-next-phase.md`), EC certificate fixtures, OCSP stapling measurement
(OQ-59), dashboard screenshots, the actual slide-deck build-out. None release-blocking.
*(`docs/finalization/14-final-release-gate.md` "REMAINING NON-BLOCKING FUTURE WORK".)*

### 20. What can be demonstrated live?

Three core scenes (STARTTLS inversion, certificate/evidence honesty, `--no-ai` equivalence), one
backup scene (generated weak-certificate fixture, clearly labelled as generated), and — new this
phase — two cross-session deep-dive scenes with real, live, previously-undemonstrated engine
output. All nine captures are staged in `demo/captures/`, all verified reliable across 20 repeated
executions of the four core scenes, all runnable fully offline.
*(`demo/README.md`; `docs/finalization/03-demo-rehearsal.md`.)*
