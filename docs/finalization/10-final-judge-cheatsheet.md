# Finalization — 10. Final judge cheat sheet

Condensed, category-organized, scannable during live Q&A. Full-depth answers for every question
already exist in `docs/phase12/11-judge-question-bank.md` — this document reorganizes and
compresses them into the brief's exact category structure and adds the questions Phase 12 didn't
cover (M–R). **Overclaim column is the one line never to soften under pressure.**

---

## A. Problem understanding

**Q: What problem does this solve?**
SHORT: email transport security fails silently; this tool reconstructs what actually happened
from a PCAP. TECHNICAL: passive reconstruction of SMTP/IMAP/POP3 sessions, TLS/STARTTLS
integrity, certificate posture, all cited to RFC/NIST. EVIDENCE: `docs/research/19`. OVERCLAIM TO
AVOID: don't imply this replaces active monitoring — it answers a different, complementary
question.

## B. Architecture

**Q: Walk me through the pipeline.**
SHORT: dissect → crypto → session → rules → cross-session → ML → fusion → posture → report.
TECHNICAL: 10 stages, zero third-party runtime dependencies in the core, 1219 tests. EVIDENCE:
`docs/finalization/00-start-state-audit.md` §1. OVERCLAIM: none of the individual stages is
novel; the integration is the contribution (see I).

## C. Cryptography

**Q: What crypto properties do you assess?**
SHORT: TLS version, cipher, key exchange, certificate details where visible, forward secrecy,
insecure configuration. TECHNICAL: 19 standards-bound rules, each cited. EVIDENCE:
`docs/finalization/04-real-pcap-evidence-pack.md`. OVERCLAIM: "we validate certificates"
unqualified — say "structure where visible; trust and revocation are out of scope" (see J).

## D. TLS 1.3

**Q: Why can't you see the certificate in most of your real captures?**
SHORT: TLS 1.3 encrypts it, by protocol design — RFC 8446 §2. TECHNICAL: measured this phase, 0
of 10 real captures show a certificate, all negotiate TLS 1.3; a generated TLS 1.2 fixture shows
38 fields with the identical toolchain, proving it's the protocol, not the tool. EVIDENCE:
`docs/finalization/04-real-pcap-evidence-pack.md` §3. OVERCLAIM: never "certificate invalid" or
"certificate absent" for a TLS 1.3 session — it's `NOT_OBSERVABLE`, a different claim.

## E. STARTTLS

**Q: How do you detect STARTTLS stripping?**
SHORT: we distinguish it from a benign decline where cross-session evidence allows; we don't
claim to "detect" an attack. TECHNICAL: an absent advertisement is byte-identical whether
stripped or genuinely unsupported, within one session; cross-session baselining (≥5 comparable
sessions) resolves it where possible. EVIDENCE: `docs/finalization/06-cross-session-demo.md`.
OVERCLAIM: "we detect stripping" as a flat claim.

## F. Cross-session reasoning

**Q: What does cross-session reasoning actually show?**
SHORT: real example — one client's session deviates from what 6 *other* clients at the same
server consistently do. TECHNICAL: `CS-STARTTLS-001` fired `MEDIUM` on `G_control_endpoint.pcap`
this phase, live. The honest negative case (`H_no_control.pcap`, no control endpoint) reports
`COMPLIANT` with an explicit stated limitation. EVIDENCE:
`docs/finalization/06-cross-session-demo.md` — verbatim real engine text. OVERCLAIM: "we detected
the attacker" — never said; the finding says "deviation," always.

## G. AI/ML

**Q: What does the AI actually do?**
SHORT: a bounded, secondary prioritisation signal; it never creates a finding. TECHNICAL:
`robust-z-sum`, unsupervised, `MAX_ML_ADJUSTMENT=4.0` against a 30-point severity-tier gap —
structurally cannot cross a tier. Zero unique true detections on every held-out split, including
the newest certificate/key-exchange features, re-measured specifically for this question.
EVIDENCE: ADR-0015, ADR-0024, `demo/expected/scene_c_no_ai_equivalence.json` (real, generated
this phase). OVERCLAIM: "AI detects attacks" — the model's own role string, rendered everywhere,
says "secondary prioritisation signal only."

## H. Forensics

**Q: How do you preserve forensic integrity?**
SHORT: SHA-256 content addressing at every layer, re-hashed on access. TECHNICAL: PCAP SHA-256 →
capture_id → assessment_id (both content-addressed) → report_sha256; verified live this phase via
`list_artifacts(verify=True)`. EVIDENCE: `docs/finalization/05-report-pack-audit.md` §4.
OVERCLAIM: don't call this "chain of custody" in a legal-evidentiary sense — it's traceability
within the tool, not a certified legal process.

## I. Novelty / differentiation

**Q: What's novel here?**
SHORT: cross-session reasoning, verified absent from five audited SIH26159 competitors by source
code. TECHNICAL: "integration-grade differentiation for this problem, not research novelty" —
cross-connection correlation is standard NSM practice generally (Zeek, Arkime). EVIDENCE:
`docs/research/01D-sih-competitor-source-audit.md` §4; `docs/phase12/12-novelty-audit.md`.
OVERCLAIM: "first," "only," "unique," "revolutionary" — none of these words describe this project
accurately, and none should be used.

## J. Limitations

**Q: What doesn't this tool do?**
SHORT: certificate trust/revocation (D-11), and AI detection (A-02) — both honestly PARTIAL with
specific reasons, not unfinished work. TECHNICAL: D-11 needs a trust anchor a passive capture
doesn't contain; A-02's corpus carries no usable signal for the features tested. EVIDENCE:
`docs/finalization/08-open-requirements.md`. OVERCLAIM: presenting either as "nearly complete" —
they are structurally limited by the evidence available, not by remaining engineering time.

## K. Deployment

**Q: Can this run air-gapped?**
SHORT: yes, verified this phase. TECHNICAL: zero network calls anywhere in `src/`, confirmed by
import-set inspection; live health-check succeeded with no internet reachable. EVIDENCE:
`docs/finalization/11-deployment-runbook.md` (§ below), `docs/finalization/12-offline-demo-audit.md`.
OVERCLAIM: claiming enterprise-scale readiness — untested at scale, I-04 is honestly PARTIAL.

## L. Security

**Q: What happens with a malicious PCAP?**
SHORT: it's classified explicitly (malformed/truncated/too-large/empty), never silently trusted.
TECHNICAL: tshark exit codes mapped to typed outcomes; a historically flaky classification test
was made deterministic in the v0.6.0-phase11 release-hygiene commit. EVIDENCE:
`docs/finalization/13-final-security-audit.md`. OVERCLAIM: "we sanitize all input" — the correct
claim is narrower: input is classified, bounded, and never executed or interpreted as markup.

## M. Why not just run Zeek/Suricata/tshark?

SHORT: those are general-purpose NSM tools; this is a mail-security-specific forensic reasoning
engine built on top of tshark, not a replacement for it. TECHNICAL: tshark does the dissection
(a hard, acknowledged dependency); this project adds the mail-protocol state machines, the
19 standards-bound security rules, cross-session reasoning, evidence-state discipline, and
posture synthesis — none of which tshark, Zeek, or Suricata provide out of the box for this
specific problem. EVIDENCE: `docs/phase12/02-technical-differentiation.md` §3 (capability
comparison table). OVERCLAIM: don't disparage those tools' general capability — the claim is fit
for *this* problem, not general superiority.

## N. Why AI if deterministic rules already exist?

SHORT: the PS mandates AI/ML explicitly; it's included honestly, as a bounded secondary signal,
rather than either omitted or oversold. TECHNICAL: doc 19 confirms *"Application of AI/ML
techniques"* is explicitly required text, not optional; the deterministic engine remains the sole
source of security conclusions by design (ADR-0008). EVIDENCE: `docs/research/19-authoritative-ps-verification.md`
§3. OVERCLAIM: implying AI was included only to satisfy a checkbox — it was evaluated seriously
(a real bake-off, ADR-0015) and reported honestly regardless of what that evaluation found.

## O. What happens if evidence is incomplete?

SHORT: the specific gap is named — `INSUFFICIENT_EVIDENCE`, `INCOMPLETE`, `UNKNOWN` — never
silently treated as secure or insecure. TECHNICAL: coverage-gated scoring; the posture band is
withheld below 50% assessed coverage. EVIDENCE: `docs/phase12/07-forensic-honesty-audit.md` §1.
OVERCLAIM: implying a confident posture verdict is always produced regardless of coverage — it
isn't, deliberately.

## P. What happens with hostile/malicious PCAP content?

SHORT: attacker-controlled text (a certificate field, a SAN entry) is treated as inert data,
never executed or rendered unescaped. TECHNICAL: a 15-payload hostile-content matrix (script
tags, event handlers, style/prototype injection) was driven through finding → report → dashboard
in Phase 11's release audit with zero escapes; re-checked this phase against the freshly
generated reports (zero `<script` occurrences). EVIDENCE: `docs/finalization/05-report-pack-audit.md`
§2; `docs/phase12/07-forensic-honesty-audit.md`. OVERCLAIM: "we sanitize everything" — the precise
claim is narrower and testable (see L).

## Q. What happens with prompt injection?

SHORT: there's no LLM for a prompt to be injected into; extracted text is data, never
instructions. TECHNICAL: the AI lane is a numerical unsupervised model with no natural-language
interface; the golden corpus includes a dedicated `X_prompt_injection.pcap` regression fixture.
EVIDENCE: `docs/phase12/11-judge-question-bank.md` (full answer). OVERCLAIM: claiming
"prompt-injection defences" as if an LLM surface exists to defend — it doesn't, by design.

## R. What cannot be inferred from passive PCAP?

SHORT: attacker identity or intent, certificate trust/revocation, anything TLS 1.3 encrypts, and
anything about a server this capture never touched. TECHNICAL: each is a structural limit of
passive evidence, stated explicitly in the relevant finding every time it applies, never
collapsed into a guess. EVIDENCE: `docs/phase12/07-forensic-honesty-audit.md` (the full forbidden-inference
table). OVERCLAIM: any of the five forbidden conversions in that table — missing evidence =
secure/insecure, anomaly = attack, deviation = attacker, certificate absence = invalid, structure
= trust.
