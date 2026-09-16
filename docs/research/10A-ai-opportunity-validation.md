# 10A — AI Opportunity Validation (OQ-21)

**Question:** Where does AI legitimately help when the core security detections are deterministic
state-machine checks?
**Status:** Complete (v1) · **Date:** 2026-09-16
**Verdict up front:** **Of 12 candidate roles, 3 are defensible.** The security engine needs no AI
whatsoever, and we should say so openly. The PS nevertheless mandates AI/ML (requirements A-01…A-05),
and there is an honest way to deliver it — **by inverting what every competitor does.**

---

## 1. Starting position: what the competitor audit established

From [01D](01D-sih-competitor-source-audit.md) §6, verified at source level:

| Competitor | AI | Verdict |
|---|---|---|
| gouravsehlangia | Cerebras `llama3.1-8b`, cloud | **Report rewriter.** Severity is a hardcoded if/elif chain *inside the prompt builder*; a template fallback produces the same content with no API key. Removable with zero loss. ⚠️ Also breaks offline operation. |
| saravana | RandomForest on 2,500 self-generated synthetic archetypes | **Rules engine laundered through ML.** Learns its own generator. Reported "confidence" measures agreement with its own synthetic data. Circularity **undisclosed**. |
| CipherPost | HistGB + IsolationForest + SHAP | Same circularity, **disclosed in a source comment**. Honest, still epistemically empty. |

**Nobody's AI does anything deterministic rules cannot.** This is the single most useful finding for
our own AI design, because it tells us where the bar actually is — and it is low.

---

## 2. Reading the PS requirement honestly

**FACT (verbatim PS).** The title says *"**AI-Assisted** Cryptographic Security Posture
Assessment"* — *assisted*, not *AI-driven* or *AI-based*. But the Objectives are more specific and
we must not hide behind the title:

> *"Application of AI/ML techniques for: Cryptographic risk classification. Detection of anomalous
> TLS behavior. Security posture scoring. Threat prioritization. Recommendation of mitigation
> measures."*

So A-01…A-05 are **explicitly required**. We cannot simply declare AI unnecessary and skip it — that
would be under-delivering against a stated deliverable.

**The honest reconciliation:** deliver all five, implement each in the most defensible form
available, and **document which are genuinely ML-suited and which are better served deterministically
with ML in a supporting role.** Stating that reasoning openly is stronger than pretending a
RandomForest adds insight, and it is exactly the kind of judgement an NTRO reviewer can check.

---

## 3. Candidate AI roles — full analysis

Scoring: **Offline** = runnable air-gapped · **Repro** = reproducible output · **Halluc.** =
hallucination risk · **Comp.** = do competitors have it?

| | Role | Deterministic alternative | Genuine AI advantage | Failure modes | Halluc. | Repro. | Offline | Comp. | PS req. | Verdict |
|---|---|---|---|---|---|---|---|---|---|---|
| **A** | NL explanation of findings | String templates per finding type | Fluency only | Fabricated crypto claims | **High** | ❌ | 🟡 local LLM | ✅ gourav | A-05 | ❌ **NOT JUSTIFIED alone** — gourav's own template fallback disproves the need |
| **B** | Evidence-grounded report generation | Jinja templates + structured findings | Marginal | Invented severities | **High** | ❌ | 🟡 | ✅ all | R-03/R-05 | ❌ **NOT JUSTIFIED** — Prahari's 65 KB template builder produces better reports than an LLM would |
| **C** | **Analyst NL query over evidence** | Query DSL / filters | **Real** — NL→structured query removes the expertise gate that *is* the root problem (doc 01 §10.1) | Wrong query generated | **Low** ✅ | ✅ | ✅ small local model | ❌ **none** | — | ✅ **DEFENSIBLE** — §4 |
| **D** | Finding prioritization | severity × exposure × asset ordering | Would need ground truth on real analyst choices — **we have none** | Arbitrary ranking presented as learned | Med | 🟡 | ✅ | ✅ all | **A-04** | ⚠️ **DELIVER DETERMINISTICALLY**, document why |
| **E** | **Anomaly clustering over sessions** | GROUP BY on known fields | **Real** — unsupervised, needs **no fabricated labels**; finds groupings not specified in advance | Clusters without meaning | **None** ✅ | ✅ seeded | ✅ sklearn | 🟡 circular versions | **A-02** | ✅ **DEFENSIBLE** — §4 |
| **F** | Cross-session behavioural summarisation | Aggregation queries | Moderate — depends on E | Overgeneralisation | Med | 🟡 | ✅ | ❌ none | — | 🟡 **CONDITIONAL on E** |
| **G** | Hypothesis generation for analyst | Rule-derived next steps | Low | **Plausible-sounding false leads in a forensic tool** | **Very high** | ❌ | 🟡 | ❌ | — | ❌ **REJECT** — unsafe here |
| **H** | Root-cause explanation | Evidence graph traversal | Low — the graph *is* the causal chain | Invented causation | High | ❌ | 🟡 | ❌ | — | ❌ **NOT JUSTIFIED** |
| **I** | Remediation planning | Standards-bound remediation text per rule | Low | **Dangerous** — ungrounded crypto advice | **Very high** | ❌ | 🟡 | ✅ | **A-05** | ⚠️ **TEMPLATE + citation**, LLM only for phrasing, if at all |
| **J** | Pattern discovery | — | Overlaps E | — | — | — | ✅ | 🟡 | A-02 | 🟡 **= E** |
| **K** | Analyst copilot | — | Bundle of C + F | Scope creep | Med | ❌ | 🟡 | ❌ | — | 🟡 **= C + F** |
| **L** | **Nothing — AI adds no value** | — | — | — | — | — | — | — | — | ⚠️ **PARTIALLY TRUE — §5** |

---

## 4. The two defensible roles, and why

### 4.1 (E) Unsupervised anomaly detection — *inverted*

🎯 **The key design decision in this document.**

Every competitor trains a classifier on labels produced by their own rules engine. The model learns
to reproduce the rules; agreement is guaranteed and meaningless. CipherPost admits this in a comment.

**Invert it. Use ML to find what the rules missed — not to reproduce what the rules found.**

```
Sessions ──> deterministic rules ──> findings (authoritative)
    │
    └──────> unsupervised clustering / outlier detection over session feature vectors
                   │
                   └──> sessions that are STATISTICAL OUTLIERS but were flagged CLEAN
                                              │
                                              └──> surfaced to the analyst as
                                                   "unusual, not covered by any rule"
```

**Why this is defensible where the competitors' approach is not:**

| Property | Competitors | Inverted approach |
|---|---|---|
| Labels required | Yes — fabricated from own rules | **None** — unsupervised |
| Circular? | **Yes** | **No, by construction** |
| Adds information? | No — approximates the rules | **Yes** — covers the rules' blind spots |
| Testable claim | "accuracy vs. our own labels" (vacuous) | **"how many genuine issues did clustering surface that no rule caught?"** |
| Failure mode | Silent disagreement with rules | Meaningless clusters — **visible and harmless** |
| ML decides security? | Effectively yes | **No** — rules remain authoritative; ML only *routes attention* |

This also directly satisfies **A-02 ("Detection of anomalous TLS behavior")** in the PS's own words,
using the one technique genuinely suited to it (doc 01 §6.5), and it **feeds H7 (cross-session
reasoning)** — the only surviving differentiator from 01D. The AI serves the differentiator instead
of being bolted on beside it.

⚠️ **Honest limitation.** Clustering over a synthetic corpus we generated finds structure *we* put
there. Its real value appears only on captures with genuine diversity. **This must be disclosed, and
the metric above ("issues found that no rule caught") must be reported honestly, including when it
is zero.**

### 4.2 (C) Natural-language query over structured evidence

The analyst asks *"show me every session where the server offered STARTTLS but the client never
upgraded"*; the system emits a **structured query**, displays it, runs it, and returns evidence-linked
sessions.

**Why the hallucination risk is genuinely low here, unlike A/B/I:** the LLM's output is **a query,
not a claim**. A wrong query is visible (it is shown to the analyst) and its results are verifiable
against the evidence store. The LLM never asserts a security fact; it only helps navigate facts the
deterministic engine established.

This attacks the root problem identified in doc 01 §10.1 — that posture assessment is **expertise-
gated**. Knowing *what to ask* is the expertise. NL query lowers that gate without moving any
security decision into the model.

**No competitor has this** (01D §2). Product differentiation, not novelty — text-to-query is a
mature, well-understood LLM application.

### 4.3 Offline feasibility

| Component | Offline? |
|---|---|
| (E) clustering — sklearn IsolationForest/DBSCAN | ✅ Trivially. No network, deterministic under a fixed seed |
| (C) NL→query — small quantised local model (e.g. a 7–8B class model via llama.cpp/Ollama) | ✅ Feasible on a workstation. ⚠️ Model weights must ship with the tool; size and licensing need checking → **OQ-26** |
| Any cloud API | ❌ Violates I-01/A-02 — **and is exactly how gouravsehlangia's design fails** |

**Constraint to adopt: no network calls at inference time, ever.** This is both a correctness
requirement for a forensic tool and a concrete discriminator against at least one competitor.

---

## 5. Part 7 — the mandatory "no AI" test

### 5.1 The strongest SecureMailScope with zero AI

1. Deterministic STARTTLS/STLS state machines for SMTP, IMAP, POP3 (explicit + implicit TLS)
2. TLS handshake and X.509 analysis from cleartext handshake data
3. Rules bound to published authorities — RFC 8996, NIST SP 800-52r2/800-131A, RFC 7627, RFC 5746,
   CA/B Forum — with citations, **not invented weights**
4. Evidence provenance typing: `observed` / `inherited` / `historical` / `retrieved` / `decrypted`,
   plus explicit `NOT_OBSERVABLE` with a typed cause (TLS 1.3 / resumption / truncation / ECH)
5. **Cross-session baselining** — the H7 differentiator, which is pure deterministic aggregation
6. Findings linked to frame numbers and stream IDs
7. Templated JSON/PDF/HTML reports with remediation text per rule

### 5.2 What disappears if AI is removed?

> **Almost nothing of security consequence.**

| Lost | Consequence |
|---|---|
| NL query (C) | Analyst uses filters instead. **Convenience, not capability.** |
| Outlier surfacing (E) | Lose coverage of *unknown* problems — real, but bounded, and unproven on synthetic data |
| LLM-phrased explanations | **Nothing.** Templates are more accurate, reproducible and auditable. gouravsehlangia's own fallback proves it |

**Every security capability survives.** The detections are state-machine checks and standards
lookups; ML cannot improve a lookup of RFC 8996.

**Say this openly in the submission.** An evaluator who asks *"what does your AI actually do?"* and
receives a precise answer — including what it deliberately does *not* do — is in a different
conversation from one told "AI-powered risk scoring" by four other teams whose models are learning
their own rule outputs.

### 5.3 The boundary architecture

```
      PCAP
        ↓
  DETERMINISTIC SECURITY ENGINE     ← all security decisions. Auditable. Reproducible.
        ↓
    STRUCTURED EVIDENCE             ← findings + provenance + frame refs + NOT_OBSERVABLE
        ↓
   ┌────┴──────────────────────┐
   │                           │
UNSUPERVISED ML (E)      AI ANALYST LAYER (C)
routes attention          NL → query → evidence
   │                           │
   └────► never writes ◄───────┘
           a finding
```

**Enforceable invariants:**

1. **No AI component may create, modify or delete a finding.** Findings come only from the
   deterministic engine.
2. **Every AI statement must cite a structured evidence object by ID.** Uncitable ⇒ not shown.
3. **ML output is a pointer, never a verdict** — "look at this session", never "this session is
   insecure".
4. **The tool must run, and produce identical security output, with AI disabled.** A `--no-ai` flag
   that changes no finding is the proof.

⚠️ Invariant 4 is testable and demoable: run the same capture twice, with and without AI, and diff
the findings. **That is a strong, concrete answer to "is your AI real or decorative?" — inverted
into evidence of discipline.**

---

## 6. Mapping to the PS's AI requirements

Honest delivery of all five, with the reasoning documented:

| PS req | Our approach | Why |
|---|---|---|
| **A-01** risk classification | **Deterministic**, standards-bound, with ML as a *cross-check* that flags disagreements for review | "TLS 1.0 is deprecated" is RFC 8996, not a learned pattern. A classifier here is a worse lookup table |
| **A-02** anomalous TLS behaviour | ✅ **Unsupervised outlier detection, inverted** (§4.1) | The one genuinely ML-suited requirement; no labels needed; non-circular |
| **A-03** posture scoring | **Deterministic weighted model, coverage-aware** (score reported with how much was observable) | Auditable; no ground truth exists to learn a score from |
| **A-04** threat prioritisation | **Deterministic** severity × exposure × cross-session prevalence | No data on real analyst priorities; inventing it would be dishonest |
| **A-05** remediation recommendation | **Templates bound to the citing standard**; LLM phrasing optional and clearly marked | Ungrounded crypto advice in a security tool is a safety problem |

**Net: 1 of 5 uses ML as the primary mechanism; 4 are deterministic with ML in support.** That is
fewer AI components than competitors — and, per §1, more *functional* AI than any of them.

---

## 7. Answers to OQ-21

| Question | Answer |
|---|---|
| Does AI have a legitimate role? | **Yes, but narrow:** unsupervised outlier detection (inverted) and NL query over evidence. Nothing else survived. |
| Core or analyst-facing? | **Analyst-facing, strictly.** No AI in the security decision path. |
| Would removing AI break the tool? | **No.** All security capability survives. Stating this is a strength. |
| Do competitors already do it? | They have *more* AI and *less* functional AI (§1). Nobody has NL query; everyone's classifier is circular. |
| Is it offline-feasible? | Yes — sklearn trivially; a small local LLM with caveats (**OQ-26**). |
| Biggest risk? | That we over-build the AI layer and become the fourth team with an impressive-sounding empty model. |

---

## 8. New open questions

| ID | Question | Priority |
|---|---|---|
| **OQ-25** | Does cross-session baselining measurably reduce false positives vs. per-session analysis? **The whole thesis rests on this and it is untested.** | 🔴 **Highest** |
| **OQ-26** | Is shipping a local LLM (size, licensing, workstation RAM) practical for an offline forensic tool? If not, role (C) is deterministic-query-only | High |
| **OQ-27** | On a synthetic corpus, does inverted outlier detection surface anything the rules miss — or is the honest answer "zero"? **We must be willing to report zero.** | High |

---

## 9. Recommendation

1. **Adopt the boundary architecture** (§5.3) with all four invariants, including the `--no-ai`
   equivalence test.
2. **Implement A-02 as inverted unsupervised detection** — the only non-circular ML design found.
3. **Deliver A-01/A-03/A-04/A-05 deterministically**, and *document the reasoning* rather than hiding
   it. The documentation is itself the differentiator against three teams whose models learn their
   own outputs.
4. **No cloud calls at inference, ever.**
5. **Treat OQ-25 as the highest-priority experiment.** If cross-session reasoning does not reduce
   false positives, the thesis in 01D §12 fails and we need a different one — better to learn that
   from a test than from an evaluator.
