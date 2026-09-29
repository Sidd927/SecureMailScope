# Phase 12 — 11. Judge question bank

Every answer below is checked against `01-final-requirements-audit.md` and `06-ai-claim-audit.md`
before being written — no answer here claims more than those documents can defend.

---

### "Why PCAP only? Why not active scanning?"

**Short answer:** because the PS asks for a passive forensic tool, and active scanning answers a
different question — the certificate right now, not the certificate actually used in the captured
session.

**Technical answer:** the PS states *"passive network forensic framework"* explicitly (I-02,
confirmed against the official portal). Active probing would also require touching the mail
server, which is outside a passive tool's threat model and would need separate authorisation in
any real incident-response or audit deployment.

**Evidence:** `docs/research/19-authoritative-ps-verification.md` §4; `docs/phase11/03-scope-lock.md` Category D (active retrieval rejected, with reasons).

**Overclaim to avoid:** do not imply active scanning was considered and technically impossible —
it was **rejected as out of scope**, a design decision, not a limitation.

---

### "Why TShark? Why not Zeek?"

**Short answer:** tshark gives direct, versioned, field-level access to the exact protocol fields
this project needs, with no additional dependency; Zeek is a live-monitoring platform, not a PCAP
forensic library.

**Technical answer:** tshark's `-T ek` output already decodes TLS handshake and X.509 fields the
project needs (measured: 38 distinct X.509 fields on a cleartext handshake, zero new dependency).
Zeek's scripting layer is built for live network monitoring workflows and would add an entire
platform dependency for a passive, single-capture forensic use case.

**Evidence:** `docs/architecture/adr/0001-packet-dissection.md`; `docs/phase11/02-x509-observability-research.md` §7.

**Overclaim to avoid:** do not claim Zeek "can't" do protocol dissection — it can; the point is
fit for this specific offline, single-capture, zero-dependency use case, not a capability gap.

---

### "Why AI? Why not deep learning?"

**Short answer:** the PS mandates AI/ML explicitly but does not prescribe a method; an unsupervised
model matched to the available evidence, evaluated honestly, was chosen over a deep model that
the available data could not train or validate meaningfully.

**Technical answer:** the corpus available (46 captures across all sources) is far too small and
too separable-by-generator (98.6%) to train or validate a deep model without simply memorising
which script wrote each file. An unsupervised approach on governed features, with a label-free
usability gate, was the defensible choice given the actual data.

**Evidence:** `docs/architecture/adr/0015-ml-model-selection.md`; `docs/phase11/04-ai-reassessment.md`.

**Overclaim to avoid:** do not say deep learning was "not needed" as if it were a strength — say
plainly that the data available does not support it, which is the honest constraint.

---

### "Why A-02 is PARTIAL"

**Short answer:** the model is real and evaluated; it produced zero unique true detections on
every held-out split tested, including with the newest Phase-11 features, so the tool reports
that instead of hiding it.

**Technical answer:** measured across all 46 available captures — forward secrecy is constant
(True in 31, False in 0), certificate evidence exists in only 1 of 46 captures, and a
key-exchange-derived feature perfectly separates two of the synthetic generators (a leakage
signature, not a detection signature). None of the three new Phase-11 feature families carry
usable information on this data.

**Evidence:** `docs/architecture/adr/0024-a02-remains-partial.md`; `01-final-requirements-audit.md` A-02 row.

**Overclaim to avoid:** never say "the ML doesn't work" without the corpus context — the finding
is that **this data** cannot support more, not that the approach is flawed.

---

### "How do you prevent false positives?"

**Short answer:** by refusing to assert a conclusion the evidence doesn't support — ambiguous
evidence stays `AMBIGUOUS`, and only `OBSERVED_ISSUE` findings ever penalise the score.

**Technical answer:** six evidence states, never collapsed; a status/severity invariant enforced
in code (`SecurityFinding.__post_init__`) forbids any non-`OBSERVED_ISSUE` status from carrying a
penalising severity; cross-session baselining specifically resolves the STARTTLS
decline-vs-stripping false-positive class other tools cannot.

**Evidence:** `07-forensic-honesty-audit.md`; `analysis/model.py` `_NON_ASSERTIVE` set.

**Overclaim to avoid:** never claim "zero false positives" — that has not been independently
measured at scale and the brief explicitly forbids this exact phrase without proof.

---

### "How do you detect STARTTLS stripping?"

**Short answer:** we don't claim to detect an attack — we distinguish a genuine strip from a
benign decline by checking whether the same server advertised STARTTLS on another session in the
same capture.

**Technical answer:** within one session, an absent STARTTLS advertisement is byte-identical
whether it's stripping or genuine non-support (01B research). Cross-session baselining (≥5
comparable sessions) resolves it where enough evidence exists; where it doesn't, the finding
stays `AMBIGUOUS` and states exactly that.

**Evidence:** `docs/research/01B-starttls-prior-art.md`; `crosssession/rules.py`; Scene A.

**Overclaim to avoid:** never say "we detect stripping" as a flat capability claim — say "we
distinguish it from a benign decline where the evidence allows."

---

### "Can you prove an attack?"

**Short answer:** no, and we say so explicitly in every relevant finding — a passive capture
establishes behaviour, not intent.

**Technical answer:** the finding text for every deviation-class rule states verbatim *"no
attacker, intent or attribution is or can be established from a packet capture,"* and this is
asserted as a test, not only documented.

**Evidence:** `test_scene_a_inversion_declines_are_not_attacks`.

**Overclaim to avoid:** this is the single most important line not to soften under pressure —
under no framing should the answer become "yes, in cases X and Y."

---

### "Can you attribute an attacker?"

**Short answer:** no. A passive capture has no basis for attribution, and the tool never claims
one.

**Technical answer:** same guard as above — attribution requires information (source
identity/intent) that transport-layer packet evidence structurally cannot provide.

**Evidence:** same as above.

**Overclaim to avoid:** same — no exceptions, no "in a future version we could."

---

### "How does TLS 1.3 affect certificate visibility?"

**Short answer:** TLS 1.3 encrypts the Certificate message by protocol design (RFC 8446 §2), so
it's invisible to any passive observer — not a limitation specific to this tool.

**Technical answer:** measured directly — all 10 real captures in this project's corpus negotiate
TLS 1.3 and yield zero X.509 fields under full tshark field extraction; a generated TLS 1.2
capture yields 38 fields with the identical toolchain, confirming the difference is the protocol,
not the extraction code.

**Evidence:** `docs/phase11/02-x509-observability-research.md` §2.

**Overclaim to avoid:** never imply this is a solvable engineering gap — it is a property of the
protocol every passive observer faces equally.

---

### "Why is D-11 PARTIAL?"

**Short answer:** chain structure is fully validated; chain *trust* needs a trust anchor a packet
capture does not contain, and revocation needs live network access a passive tool deliberately
doesn't use.

**Technical answer:** RFC 5280 §6 defines path validation as an algorithm over a set of trust
anchors. A bundled public root store was considered and rejected — it would flag legitimate
private-CA enterprise mail deployments as untrusted, a systematic false positive on exactly the
PS's target population.

**Evidence:** `docs/architecture/adr/0023-certificate-and-key-exchange-analysis.md`.

**Overclaim to avoid:** do not say "we validate certificates" unqualified — say "we validate chain
structure; trust requires material we deliberately do not have."

---

### "Can you validate certificate trust?"

**Short answer:** no, and we explain exactly why in every relevant finding rather than
approximating it.

**Technical answer:** see D-11 above. The alternative (bundling a trust store) was evaluated and
rejected as introducing more false positives than it would resolve.

**Evidence:** same as above.

**Overclaim to avoid:** same.

---

### "How do you handle private CAs?"

**Short answer:** we don't attempt to distinguish a private CA from an untrusted one — that's
precisely why bundling a public root store was rejected; it would misclassify every private-CA
deployment.

**Technical answer:** an operator-supplied trust store is the only defensible path to answering
this, and it's an open question (OQ-04) — a future capability, not a current one, and not
attempted without a concrete corpus to validate it against.

**Evidence:** `docs/architecture/adr/0023-certificate-and-key-exchange-analysis.md` "Rejected" section.

**Overclaim to avoid:** do not promise this is "coming soon" without qualification — it's a
genuinely open question with real deployment-complexity trade-offs, discussed honestly in
`13-final-engineering-decision.md`.

---

### "How do you handle truncated captures?"

**Short answer:** explicitly, and distinctly from other absence reasons — a truncated handshake
is reported as truncated, never as an absent certificate or a failed check.

**Technical answer:** `SEC-CERT-001`'s absence-reason logic distinguishes encrypted (TLS 1.3),
not-sent (resumption), and truncated capture as three separate, named reasons, because they carry
different evidential weight and different remediation implications.

**Evidence:** `analysis/rules/certificate_rules.py` `_absence_reason()`.

**Overclaim to avoid:** none identified — this is a genuinely strong answer as-is.

---

### "How do you handle malformed PCAPs?"

**Short answer:** they're classified explicitly (`MALFORMED`, distinct from `EMPTY`, `TRUNCATED`,
`TOO_LARGE`) via tshark's own exit codes, never silently treated as valid.

**Technical answer:** the adapter maps tshark exit code 3 to `MALFORMED`, exit 14 to `TRUNCATED`,
exit 0 with zero packets to `EMPTY` (not `OK`) — each a typed, tested outcome. The one historical
nondeterminism in this exact test path (a random-bytes test occasionally matching a legacy
format's magic number) was found, root-caused, and fixed with a deterministic fixture in the
Phase-11 release-hygiene commit.

**Evidence:** `dissect/tshark.py` `_status_for()`; `tests/test_tshark_adapter.py`.

**Overclaim to avoid:** none identified.

---

### "How do you preserve forensic integrity?"

**Short answer:** every artifact is content-addressed by SHA-256, re-hashed on access, and every
finding traces back to specific frame numbers.

**Technical answer:** PCAP SHA-256 → `capture_id` → `assessment_id` (both content-addressed,
run-independent) → `report_sha256`; artifacts are re-verified on read, not trusted from write
time; tamper is detected, not merely logged.

**Evidence:** `docs/architecture/22-forensic-reporting.md`; `posture/engine.py` provenance block.

**Overclaim to avoid:** none identified.

---

### "How do you handle prompt injection?"

**Short answer:** there is no LLM in this system for a prompt to be injected into, and any text
extracted from a hostile capture is treated as inert data, never as instructions or markup.

**Technical answer:** the AI lane is an unsupervised numerical model with no natural-language
interface; a 15-payload hostile-content matrix (script tags, event handlers, style/prototype
injection) was driven through the full finding → report → dashboard path with zero escapes
during Phase 11's release audit, and the golden corpus includes a dedicated
`X_prompt_injection.pcap` fixture from earlier phases.

**Evidence:** `research/experiments/oq28/pcaps/X_prompt_injection.pcap`; Phase-11 release audit §10 (this session, hostile-content matrix).

**Overclaim to avoid:** do not conflate this with "we have prompt-injection defences" as if an
LLM surface exists — the accurate framing is that the attack surface doesn't exist in the first
place.

---

### "What is novel?"

**Short answer:** cross-session reasoning, verified absent from every competing SIH26159
implementation examined by source code, for this specific problem.

**Technical answer:** see `12-novelty-audit.md` in full — the claim is scoped precisely
("integration-grade differentiation for this problem, not research novelty in the field of
network security monitoring generally") and does not use the word "novel" unqualified.

**Evidence:** `docs/research/01D-sih-competitor-source-audit.md`.

**Overclaim to avoid:** never say "first," "only," or "unique" without the same qualification —
see `12-novelty-audit.md`.

---

### "What is your real-world validation?"

**Short answer:** 10 real captures from Postfix and Dovecot across SMTP/IMAP/POP3, all transport
modes; plus 3 generated fixtures for the certificate family the real corpus can't exercise.

**Technical answer:** all 10 real captures re-validated this phase to score identically to the
Phase-10 baseline; the certificate/key-exchange family is validated only on generated TLS 1.2
fixtures because the entire real corpus is TLS 1.3 — stated plainly, not hidden.

**Evidence:** `docs/phase11/06-final-audit.md` §4; `00-release-state-audit.md` §5.

**Overclaim to avoid:** do not imply the certificate work is validated against real-world traffic
— it explicitly is not, and that's OQ-60, open.

---

### "How does the system scale?"

**Short answer:** untested at enterprise scale; the PS's "enterprise email infrastructures"
phrase is about traffic scope, not a stated throughput target.

**Technical answer:** every measured capture in this project's corpus is a few KB to a few hundred
KB; end-to-end analysis completes in under 300 ms per capture regardless. No capture larger than
that has been exercised, and no load or concurrency test exists.

**Evidence:** `04-demo-reliability.md` §1; `01-final-requirements-audit.md` I-04 row.

**Overclaim to avoid:** do not claim enterprise-scale readiness — I-04 is honestly marked PARTIAL
in this audit for exactly this reason.

---

### "What happens without enough history?"

**Short answer:** the cross-session rules simply don't fire — they require at least 5 comparable
sessions to form a baseline, and below that threshold the tool says so rather than guessing.

**Technical answer:** `crosssession/` baseline construction requires ≥5 comparable sessions;
below that, no cross-session finding is produced, and the single-session deterministic findings
stand on their own.

**Evidence:** `docs/architecture/14-cross-session-reasoning.md`.

**Overclaim to avoid:** none identified.

---

### "What happens without certificate visibility?"

**Short answer:** the finding states plainly that no certificate was observable and names the
specific reason — it is never silently omitted or treated as a pass.

**Technical answer:** `SEC-CERT-001` returns `NOT_OBSERVABLE` with the specific cause; every
downstream certificate rule (`SEC-CERT-002`–`005`) correctly does not fire when there is no
certificate to assess.

**Evidence:** `07-forensic-honesty-audit.md` §1.

**Overclaim to avoid:** none identified.

---

### "What does the ML model actually do?"

**Short answer:** it computes a bounded anomaly score from governed features and can re-order
findings within one severity tier — it never creates a finding and never crosses a tier.

**Technical answer:** `robust-z-sum`, an unsupervised model, scores each session against a
population baseline; `MAX_ML_ADJUSTMENT = 4.0` is smaller than the narrowest gap between adjacent
severity tiers (30), so it is mathematically incapable of moving a finding across a tier boundary.

**Evidence:** `docs/architecture/adr/0015-ml-model-selection.md`; `posture/prioritise.py`.

**Overclaim to avoid:** never call this "detection" — the model's own role string, rendered
verbatim everywhere it appears, says "secondary prioritisation signal only."
