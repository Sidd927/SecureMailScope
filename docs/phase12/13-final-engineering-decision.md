# Phase 12 — 13. Final engineering decision

Folds in brief §18 (remaining-work value analysis), §19 (candidate ledger), §20 (D-11 deep-dive),
§21 (A-02 deep-dive), and §31 (release freeze strategy) — the six questions in §28 are answered
directly, each grounded in a document already produced this phase rather than re-argued here.

---

## 0. The fact that governs this entire decision

**2026-09-30 is the SIH26159 idea/abstract submission deadline, not a working-system demo
deadline.** Re-confirmed directly against `docs/research/19-authoritative-ps-verification.md` §6
this phase: *"The near-term deliverable is the idea/abstract submission, not a working system
(Grand Finale is December 2026)."* Today is 2026-09-22 — **8 days remain** to that submission.

This changes the calculus completely. It means:

- **Zero engineering urgency exists for 2026-09-30.** Nothing in `src/` needs to change for the
  submission to succeed; the submission is written content plus, at most, a repository a judge
  might click into.
- The actual pressure this audit should optimise against is: **is the abstract/idea compelling
  and defensible, and does the repository survive scrutiny if someone clicks through it?** Both
  are documentation and packaging questions, not engineering questions.
- The Grand Finale (December 2026, if selected) is the actual live-demo deadline, and it has
  **months of runway**, not 8 days. Any genuinely valuable-but-not-urgent engineering work (D-11
  trust-store support, in particular — §3 below) belongs there, with the same research-first
  discipline every prior phase has used, not rushed into the next 8 days.
- **One item cannot be resolved by this audit at all**, carried unchanged from doc 19: *"confirm
  with your SPOC that the college internal deadline is not earlier than the national 30
  September"* — this is the one action item that is genuinely time-sensitive and genuinely
  outside engineering's ability to close.

## 1. Answers to the six questions (brief §28)

### Q1 — What remains technically incomplete?

Two requirements: **D-11** (chain trust/revocation, not observable from passive PCAP alone) and
**A-02** (zero demonstrated ML detection value on any corpus held). Both are documented in
`01-final-requirements-audit.md` with specific, measured reasons — neither is "unfinished," both
are "closed as far as the available evidence permits."

One packaging gap: no demo bundle, no pre-rendered example reports, a stale README. Not a
technical incompleteness — a presentation-readiness gap.

### Q2 — What remaining incompleteness actually matters to SIH?

Neither D-11 nor A-02 blocks the abstract/idea submission — the PS asks for these capabilities
and this project delivers them honestly-scoped, which is itself the correct SIH answer (a
technically honest PARTIAL beats a fabricated COMPLETE, the standard this entire project has held
throughout). The packaging gap **does** matter, because a judge who clicks into the repository
before the Grand Finale forms an impression from what they find — a stale README or a missing
demo bundle costs credibility for free, with zero technical justification for leaving it stale.

### Q3 — What can realistically be completed before 2026-09-30?

Everything in the "MUST DO" row of §2 below: README accuracy, a scripted demo bundle over
existing captures, 3–7 pre-rendered example reports, and the presentation artifacts the
submission itself requires. All of it is packaging and documentation work over an already-tested
system — zero production-code risk, and every piece was independently measured as low-effort
during this audit (§10 of `10-demo-environment.md`).

### Q4 — What creates the highest defensible judge-visible value?

The demo bundle and an accurate README, specifically because they are the two artifacts most
likely to be the **first** thing anyone (a judge, a SPOC, a teammate) encounters, and both
currently understate what the system actually does (README says "Phases 1–10," omits the entire
Phase-11 certificate/key-exchange capability; no bundle exists to demonstrate anything at all
without manually running commands).

### Q5 — What should NOT be built?

Every candidate in the "DO NOT BUILD" row of §2, most importantly: **D-11 trust-anchor support**,
attempted now, and **any further A-02 model iteration** on the current corpus. Both are explained
in full in §3 and §4.

### Q6 — Should we implement anything?

**In `src/`: no.** In documentation and demo packaging: **yes, a small, low-risk, high-value set
of items**, listed exactly in §2.

## 2. Remaining-work classification (brief §18/§19)

Classification, not ranking, exactly as instructed.

| Candidate | Why | Value | Effort | Risk | Deadline impact | Decision |
|---|---|---|---|---|---|---|
| README accuracy (Phase 11 capabilities, correct phase count, `crypto/` package) | first thing any reader sees; currently stale | high judge-visibility | trivial | none (docs only) | can complete today | **MUST DO** |
| Point judge-facing instructions unambiguously at `v0.6.0-phase11` / the correct branch, since `main` is frozen at Phase 3 | mitigates the single highest-visibility risk found this audit (doc 00 §1) | high | trivial | none | can complete today | **MUST DO** |
| Demo bundle (`demo/` directory: captures + manifests + scripts) per `10-demo-environment.md` §5 | closes the "no packaged demo exists" gap identified this audit | high, directly serves the abstract/idea and the eventual Grand Finale | small — scripting over already-tested `submit_path` calls | none — outside `src/`, no production code touched | can complete this week | **MUST DO** |
| 3–7 pre-rendered example reports (JSON/HTML/PDF) committed alongside the bundle | closes the R-03 packaging note in `01-final-requirements-audit.md` | medium | trivial (existing render path, <100ms each) | none | can complete today | **MUST DO** |
| Presentation slide deck, using `03-demo-journey.md` §4's evidence plan | this **is** the actual near-term submission artifact | highest | moderate (content assembly, not engineering) | none | must complete before submission | **MUST DO**, but owned by the presenter, not an engineering task |
| Staged multi-session capture for the cross-session deep-dive (currently unstaged per `04-demo-reliability.md`) | closes the one identified live-demo gap for a capability otherwise well-tested | medium — only matters if a judge asks | small (generate + validate one fixture, following the same rigor as Phase 11's cert fixtures) | low if the same measured-not-assumed discipline is used | can complete this week if desired | **SHOULD CONSIDER** |
| D-11 operator-supplied trust anchors (OQ-04) | the one PS-adjacent capability that could move a status from PARTIAL toward COMPLETE | real, but only realizable with a genuine research-and-validation cycle | Medium–Large (new input surface, new UI, new report content, new tests) | **High** — a wrong trust-store implementation creates a new false-positive class against exactly the private-CA deployments this PS targets; ADR-0023 already rejected the naive version for this reason | **not needed for 2026-09-30** (paper deadline); if pursued, belongs before the Grand Finale, with a dedicated research gate first | **DO NOT BUILD now — see §3, reserved for a future phase (`14-proposed-next-phase.md`)** |
| Further A-02 model iteration / a different model on the same corpus | "make the AI show more value" | none defensible | wasted, regardless of size | **the actual risk**: manufacturing a positive result on data measured to carry no signal is the overclaim this entire project's discipline exists to prevent | none — actively harmful to attempt | **DO NOT BUILD — see §4** |
| Certificate-chain semantics beyond the current RSA fixtures (e.g. EC certificates, OCSP stapling investigation for OQ-59) | would close small stated gaps (`01-final-requirements-audit.md` D-13 row) | low judge-visibility | small | low | none | **ONLY IF TIME PERMITS**, and only as research, not new rules |
| Dedicated certificate dashboard visualisation | would look impressive | low incremental value — Findings/Evidence screens already show cert data (doc 08) | real — new component, new security-matrix cases | touches R-04, a component `09-architecture-freeze-audit.md` explicitly recommends not touching | none, deadline-wise, but risks regressing a stable component for a demo the existing screens already carry | **DO NOT BUILD** |
| Raw packet-level drill-down in the dashboard | requested nowhere in this audit's evidence; the assessment contract deliberately carries no packet view | none identified — the README already states this design boundary | Large, and requires a canonical-contract scope change | High | would eat the entire remaining runway for a capability not asked for by the PS | **DO NOT BUILD** |
| Docker packaging of the application itself (distinct from the existing fixture-generation scripts) | not requested; the environment audit found the system already runs everywhere in 2 commands | none demonstrated | real — new dependency surface | introduces a dependency that doesn't exist today for a problem that doesn't exist today | none | **DO NOT BUILD** |
| Rename `DEPRECATED_TLS_VERSION` for naming consistency with the Phase-11 fix applied to `FORWARD_SECRECY` | cosmetic consistency | negligible | small code change | breaks fusion identity of every historical assessment (`07-forensic-honesty-audit.md` §4) | none | **DO NOT BUILD** |
| Harden `crypto/certificates.py` attribution logic further, speculatively | "make the fragile part less fragile" | none provable without new evidence | wasted without a real multi-cert fixture to measure against | re-creates the exact failure mode already caught once (assumption instead of measurement) | none | **DO NOT BUILD without new fixture evidence first (`09-architecture-freeze-audit.md` §2)** |

## 3. D-11 deep-dive (brief §20) — investigated, not implemented

Investigated whether operator-supplied trust anchors would:

| Question | Finding |
|---|---|
| Remain within PS scope? | Arguably yes — *"Extraction and validation of X.509 digital certificates"* (Objectives) could be read to cover trust validation given operator-supplied material; this is a defensible reading, not a certain one |
| Materially improve SIH coverage? | Yes, potentially — it is the one credible path from D-11 PARTIAL toward COMPLETE |
| Introduce false positives? | **Yes, this is the central risk.** A naive implementation (bundling a public root store) was already evaluated and rejected in Phase 11 (ADR-0023) for exactly this reason — it would flag every legitimate private-CA enterprise deployment as untrusted, a systematic false positive on the PS's own target population |
| Introduce deployment complexity? | Yes — an operator must supply, maintain, and trust a trust-store input, which is a new operational surface this passive, zero-configuration tool does not currently have |
| Require new dependencies? | Likely yes, for parsing/validating arbitrary supplied certificate material beyond what tshark already decodes |
| Require new security risks? | Yes — accepting operator-supplied trust material as an input is a new attack surface (a malicious or malformed trust store) that does not exist in the current passive-only design |
| Require new UI? | Yes — the dashboard and API currently have no concept of a per-analysis or per-deployment trust configuration |
| Require new reports? | Yes — every certificate finding's language would need to change to distinguish "no trust material supplied" from "trust material supplied and evaluated" |
| Require new tests? | Yes, extensively — the false-positive risk above would need the same rigor Phase 11 applied to every other claim: measured, not assumed |
| Realistically validated before 2026-09-30? | **No.** Even setting aside that 2026-09-30 doesn't require this, 8 days is not enough runway to design the input surface, implement it, and re-prove no new false-positive class against a private-CA scenario with the same discipline this project has held throughout |

**Conclusion: genuinely worth a future phase, not worth attempting now.** Documented as a reserved,
not-yet-authorized option in `14-proposed-next-phase.md`.

## 4. A-02 deep-dive (brief §21) — confirmed, not re-attempted

Verified, not merely asserted:

| Claim | Verification this phase |
|---|---|
| ML capability exists | confirmed — `ml/` untouched since Phase 6, unchanged by this audit |
| Unsupervised approach is real | confirmed — `robust-z-sum`, fitted on governed features, no labels involved |
| `--no-ai` equivalence is proven | confirmed — `test_scene_c_no_ai_equivalence_across_the_whole_stack` passes, asserted end-to-end through the real API |
| Deterministic findings are not used as ML labels | confirmed — `FORBIDDEN_INPUTS` in `ml/features.py` explicitly excludes `rule_id`, `severity`, `finding_status`, `ground_truth`, `label`, `generator`, `scenario` |
| Generator leakage is a known, honestly-reported concern | confirmed — 98.6% generator-separability measured and reported (ADR-0015), and the Phase-11 features were independently re-measured this session to make the leak *worse*, not better, if used (`docs/architecture/adr/0024-a02-remains-partial.md`) |
| New Phase-11 features did not demonstrate meaningful detection value | confirmed by direct re-check of the underlying measurement: across all 46 available captures, forward secrecy is constant (31 True, 0 False), certificate evidence exists in 1 of 46 captures, and the key-exchange feature perfectly separates two synthetic generators rather than any real security condition |

**No further model, no LLM, no synthetic labels are justified.** The corpus is the limiting
factor, not the model choice, and the corpus cannot be manufactured by engineering effort without
re-creating the exact authorship-leakage problem already identified and avoided once (OQ-61,
deliberately deferred in Phase 11 for this reason).

## 5. Release freeze strategy (brief §31)

```
CODE FREEZE           -- now. src/ is frozen at v0.6.0-phase11. No further commits to src/
                          are justified by this audit; see 09-architecture-freeze-audit.md for
                          the component-level reasoning.
  |
DEMO FREEZE            -- once the demo/ bundle (SS2, MUST DO items) is committed and its
                          scripted run reproduces the expected-output table in
                          10-demo-environment.md SS5.2 exactly.
  |
PRESENTATION FREEZE    -- once the slide deck (03-demo-journey.md SS4) is built from this
                          audit's evidence plan and checked against 06-ai-claim-audit.md and
                          12-novelty-audit.md for overclaim.
  |
SUBMISSION             -- 2026-09-30, the idea/abstract deadline. Confirm the SPOC-internal
                          cutoff independently -- this is the one item this audit cannot close.
```

**No further release tag is created by this phase**, per the brief's explicit instruction. If the
demo/documentation work in §2 is carried out, it should land as ordinary commits on
`phase/12-sih-final-audit` (or a successor branch), reviewed and merged at the human's discretion
— this audit does not authorize itself to tag a new release.

## 6. Final recommendation

**FREEZE the codebase. The only justified further work is small, zero-production-risk demo and
documentation packaging** (§2's MUST-DO row) **— classified under the brief's "SMALL
DEMO/UX IMPROVEMENTS" category, with the explicit caveat that "UX" here means the demo bundle,
example reports, and documentation accuracy, not any change to dashboard or report source code**,
all of which `09-architecture-freeze-audit.md` independently recommends leaving untouched.

This is not an enthusiasm-driven choice. It follows directly from three independent facts
established this phase: the architecture is measurably stable (9 of 13 components untouched for a
full phase or more), every remaining requirement gap has a specific evidence-backed reason rather
than an unfinished-work reason, and the actual near-term deadline is a paper submission with no
engineering dependency at all.
