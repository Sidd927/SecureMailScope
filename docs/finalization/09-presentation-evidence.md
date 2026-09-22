# Finalization — 09. Presentation evidence package

Authoritative content for a 9-slide deck (within the brief's 8–10 range). Not the final
PowerPoint — the claim, evidence, demo support, figure suggestion, and explicit "what NOT to
claim" for each slide, so whoever builds the deck cannot accidentally introduce an overclaim the
rest of this project has spent five phases avoiding.

---

### Slide 1 — Problem

**Claim:** email transport security failures (stripped STARTTLS, weak TLS, misconfigured
certificates) are invisible without forensic tooling, and passive PCAP analysis is how an
incident-response or audit team answers "what actually happened here" after the fact.

**Evidence:** `docs/research/19-authoritative-ps-verification.md` — the PS itself frames this as a
*"passive network forensic framework"* problem.

**Demo evidence:** none needed at this stage.

**Figure:** none — a one-sentence problem statement.

**What NOT to claim:** do not claim active scanning or live monitoring is "worse" — it answers a
different question and was out of scope by design, not by inferiority.

### Slide 2 — Why existing approaches fall short *(folded into one bullet on this slide per Phase 12's "smallest persuasive structure" finding, not a full comparison slide)*

**Claim:** generic packet-analysis tools (tshark, Zeek, Suricata) and every audited SIH26159
competitor reason about one session at a time, which cannot resolve the core ambiguity — a client
declining STARTTLS looks identical, within one session, to an attacker stripping it.

**Evidence:** `docs/research/01D-sih-competitor-source-audit.md` §4 — source-code audit of five
competitor implementations, cross-session reasoning verified absent from all five.

**Demo evidence:** Scene A.

**Figure:** side-by-side of the two byte-identical-looking sessions.

**What NOT to claim:** do not name-drop Zeek/Suricata as inferior tools — they solve different
problems well; the point is architectural fit for *this* ambiguity, not general quality.

### Slide 3 — SecureMailScope architecture

**Claim:** a ten-stage pipeline — dissection, crypto derivation, session reconstruction,
deterministic rules, cross-session reasoning, ML (secondary), evidence fusion, posture scoring,
persistence, and three-format reporting — with zero third-party runtime dependencies in the core.

**Evidence:** `docs/finalization/00-start-state-audit.md` §1 (release identity), architecture
diagram in `docs/phase12/00-release-state-audit.md` §3.

**Demo evidence:** History screen showing a completed run in well under 300 ms.

**Figure:** the pipeline diagram.

**What NOT to claim:** do not claim the architecture is novel — the individual stages (dissection,
rule engines, ML scoring) are standard techniques; the differentiation is in the specific
integration (Slide 5).

### Slide 4 — Passive forensic pipeline

**Claim:** every finding traces to a specific frame number, TCP stream, and timestamp; the tool
never connects to a mail server, needs no keys, reads no message content.

**Evidence:** `docs/architecture/22-forensic-reporting.md`; `docs/finalization/04-real-pcap-evidence-pack.md`
§7 (provenance traced across 13 real executions this phase, zero mismatches).

**Demo evidence:** Evidence screen, a frame number visible on any finding.

**Figure:** the PCAP → frame → stream → finding → report provenance chain.

**What NOT to claim:** do not claim forensic-grade chain-of-custody in a legal sense — this is
evidence traceability within the tool's own analysis, not a certified forensic chain-of-custody
process.

### Slide 5 — Cryptographic security assessment

**Claim:** TLS version, cipher suite, key exchange, X.509 certificate properties where a
cleartext handshake exposes them, forward secrecy, and a bounded insecure-configuration checklist
— 19 standards-bound rules, each citing a specific RFC or NIST publication.

**Evidence:** `docs/phase12/01-final-requirements-audit.md` (D-09–D-17); this phase's own
`demo/reports/backup_weak_certificate.pdf`, real, verified by text extraction this phase to show
RSA-1024 and SHA-1 findings at HIGH severity with their citations.

**Demo evidence:** the weak-certificate backup scene.

**Figure:** a screenshot of the RSA-1024/SHA-1 finding pair.

**What NOT to claim:** do not say "we validate certificates" unqualified. Say "we validate chain
*structure* where a certificate is visible; trust and revocation are explicitly out of scope from
passive evidence alone" (Slide 8 covers this fully).

### Slide 6 — Cross-session reasoning

**Claim:** the one capability verified absent from every audited competitor — comparing a
session's behaviour against every other session with the same server, in the same capture,
resolves the stripping-vs-decline ambiguity where enough evidence exists, and says so honestly
where it doesn't.

**Evidence:** `docs/finalization/06-cross-session-demo.md` — real engine output from
`G_control_endpoint.pcap` (a genuine `MEDIUM` deviation finding) and `H_no_control.pcap` (the
honest negative case: `COMPLIANT`, with an explicit stated limitation).

**Demo evidence:** the two newly-staged deep-dive scenes in `demo/captures/`.

**Figure:** the SESSION/BASELINE/CONTROL-ENDPOINT/CONCLUSION/LIMITATION structure from that
document, with the two real quoted findings.

**What NOT to claim:** never "we detected the attacker" or "we detected stripping" as a flat
capability claim. The real finding text says *"consistently lacks the upgrade capability while
comparable endpoints... consistently have it"* — a deviation, not an attack.

### Slide 7 — AI/ML role

**Claim:** a real, evaluated, unsupervised anomaly-scoring model, structurally bounded so it can
never create or promote a finding across a severity tier, and proven — not merely claimed —
identical in every security conclusion with AI on or off.

**Evidence:** ADR-0015, ADR-0024; `demo/expected/scene_c_no_ai_equivalence.json`, generated this
phase, showing `ai_true`/`ai_false` producing identical `overall_posture`, `score_value`, and
`penalising_issue_classes`.

**Demo evidence:** Scene C.

**Figure:** the side-by-side AI-on/AI-off comparison table from the manifest.

**What NOT to claim:** do not claim AI "assists detection" in a way that implies unproven value.
State plainly: zero unique true detections on any held-out split or any corpus this project
holds, including the newest certificate/key-exchange features, specifically re-measured for this
question (`docs/phase12/13-final-engineering-decision.md` §4).

### Slide 8 — Evidence, provenance, and reporting; and the two honest limitations

**Claim:** six evidence states never collapsed into secure/insecure; every certificate finding
distinguishes "not observed" from "not observable from passive PCAP" (TLS 1.3 encrypts it by
protocol design); D-11 and A-02 are reported PARTIAL with specific, evidence-backed reasons.

**Evidence:** `docs/phase12/07-forensic-honesty-audit.md`; `docs/finalization/08-open-requirements.md`;
`docs/finalization/04-real-pcap-evidence-pack.md` §3 (0 of 10 real captures show a certificate —
measured, not assumed).

**Demo evidence:** Scene B.

**Figure:** the six-state evidence model, with the certificate-visibility example.

**What NOT to claim:** this slide exists specifically to prevent overclaiming elsewhere in the
deck — state D-11 and A-02's status and reasons exactly as written above, not softened toward
"nearly complete."

### Slide 9 — Demo, results, and closing

**Claim:** 1219 tests, three independent full-suite runs, 13 real and generated captures
evidenced fresh this finalization phase, zero drift from the Phase-11 release, reproducible
end-to-end in well under 300 ms per capture, fully offline.

**Evidence:** `docs/finalization/03-demo-rehearsal.md` (20/20 repeated executions succeeded);
`docs/finalization/14-final-release-gate.md` (once written).

**Demo evidence:** the live demo itself, or the pre-rendered `demo/reports/` as fallback.

**Figure:** none needed — this is the closing summary.

**What NOT to claim:** no "first," "only," "unique," or "revolutionary" — close with the scoped
differentiation thesis from `docs/phase12/12-novelty-audit.md` §3, quoted exactly, not
paraphrased into something stronger.
