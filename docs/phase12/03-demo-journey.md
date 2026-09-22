# Phase 12 — 03. Demo journey

Folds in brief §9 (judge-visibility test), §10 (journey), §11 (scene selection), and §25 (the
slide-level presentation evidence plan) — each is a section below, in dependency order: first
establish what is actually demonstrable, then design the journey around it, then map it to slides.

---

## 1. The "judge can see it in 30–90 seconds?" test (brief §9)

| Capability | Backend exists? | Evidence exists? | Real-PCAP validated? | Dashboard visible? | Report visible? | Easy to demonstrate? | Requires explanation? | Confusion risk | Best demo scene |
|---|---|---|---|---|---|---|---|---|---|
| PCAP ingest + hashing | yes | yes | yes | History screen | yes | yes | no | none | opening |
| STARTTLS ambiguity (never guessed) | yes | yes | yes | Findings screen | yes | **yes, if framed correctly** | some — "why doesn't it just say attack?" | medium — a judge expecting a red alert may read `AMBIGUOUS` as weakness | Scene A |
| Cross-session reasoning | yes | yes | yes, but the 10-capture real corpus has too few *same-server* sessions to trigger a baseline live | Findings screen (when triggered) | yes | **no** — needs a multi-session capture, which the live demo corpus does not reliably have | high — the mechanism (≥5 comparable sessions) needs stating before it means anything | high if attempted live without a prepared multi-session capture | deep-dive only, with a **prepared** capture |
| Certificate observability (TLS 1.3 encrypted) | yes | yes | yes (10/10 real captures) | Evidence screen | yes | yes | some — "why can't you see the certificate?" is the single most likely judge question | low, if the RFC 8446 reason is stated plainly | Scene B |
| Certificate extraction (TLS 1.2, generated fixtures) | yes | yes | **no** — only generated fixtures, real corpus is 100% TLS 1.3 | Findings/Evidence screens | yes | yes, and it is visually strong (RSA-1024 + SHA-1 → CRITICAL) | some — must state these are generated, not captured-in-the-wild | medium — a sharp judge will ask "is that a real capture?"; answer honestly | deep-dive (certificate track) |
| Forward secrecy | yes | yes | yes (10/10 real: all TLS 1.3, all forward secret) | Findings screen | yes | yes, but the real corpus never shows a *negative* case | low | low | folded into Scene B or the cert deep-dive |
| Evidence abstention / `NOT_OBSERVABLE` | yes | yes | yes | Evidence screen | yes | yes | some — needs the "missing evidence ≠ secure" framing | medium if not framed | Scene B (core) |
| ML secondary signal | yes | yes | yes | Overview ML panel | yes | yes, but the honest story ("no detection value, and here's why") is a harder sell than a green checkmark | high — the whole point requires explaining what it is *not* | high if the presenter undersells the honesty as weakness | Scene C |
| `--no-ai` equivalence | yes | yes, proven end-to-end | yes | toggle in the demo, or two side-by-side runs | yes | yes, and it is one of the strongest 30-second beats available | low — the demonstration explains itself | low | Scene C (core) |
| Provenance (frame/stream/timestamp per fact) | yes | yes | yes | Evidence screen | yes, in all 3 formats | **no**, not without explanation — a judge will not spontaneously notice a frame number matters | high | high if not pointed at directly | technical deep-dive only |
| Posture scoring (`F2-group-damped`) | yes | yes | yes | Overview screen | yes | yes, the number itself is intuitive | some — coverage-gating needs one sentence | low | opening/closing |
| PDF/HTML/JSON report | yes | yes | yes | download links | is the artifact | yes | no | low | closing |

**Conclusion of this test.** Two capabilities are technically excellent but poorly demonstrable
live without preparation: **cross-session reasoning** (needs a multi-session capture staged in
advance, not present in the current 10-capture real corpus by coincidence of session count) and
**provenance** (real, but invisible unless the presenter points at a frame number on screen). Both
are solved by **fixture and script preparation**, not engineering — see `04-demo-reliability.md`
for the exact pre-demo staging each needs.

## 2. Demo scene selection (brief §11)

| Scene | Classification | Why |
|---|---|---|
| **Scene A** — STARTTLS inversion (`smtp_declines` + `smtp_no_starttls`) | **CORE DEMO** | real captures, tested end-to-end, resolves the exact epistemic ambiguity this project's differentiation thesis rests on, clear judge-facing narrative ("this is not an attack, and here is why the engine knows that") |
| **Scene B** — evidence honesty / certificate observability (`imap_implicit`) | **CORE DEMO** | real capture, tested, directly answers the single most likely hard question ("can you see the certificate?"), demonstrates the six-state model without jargon |
| **Scene C** — `--no-ai` equivalence | **CORE DEMO** | real capture, tested, the fastest possible proof that AI is not decorative — a single side-by-side comparison closes the most dangerous line of questioning (AI overclaiming) in under 60 seconds |
| Cross-session baselining (full, live) | **TECHNICAL DEEP-DIVE**, not core | mechanism needs explaining before the result means anything, and the live real corpus does not reliably produce ≥5 comparable sessions per server; demonstrate only if asked, with a **prepared** capture |
| Certificate extraction on generated TLS 1.2 fixtures (self-signed, RSA-1024/SHA-1) | **BACKUP DEMO** | visually strong (a CRITICAL finding with a concrete cause) but must be honestly labelled as generated, not real-world, traffic — good as a follow-up if a judge asks "show me a bad certificate," weak as an opening beat because it invites the "is that real?" question before the core story lands |
| Provenance / frame-level drill (JSON report inspection) | **TECHNICAL DEEP-DIVE** | real and correct, but requires the presenter to point at a specific line of a report; not a 30-second beat |
| Posture scoring internals (F2-group-damped formula walkthrough) | **TECHNICAL DEEP-DIVE** | correct and defensible but is a "why" answer to a question, not a demo beat |
| Raw packet-level drill-down | **NOT WORTH DEMONSTRATING** | does not exist, and the README states why (the canonical assessment carries no packet-level view by design) — do not imply it exists by fumbling for it live |
| ML model internals (robust-z-sum math) | **NOT WORTH DEMONSTRATING** as a visual, but the honest limitation **is** worth stating in Scene C | the math is not judge-facing; the *honesty about a negative result* is the actual value, and that is already Scene C's content |

## 3. The recommended 5–8 minute core journey

```
OPENING (30s)
  -> state the problem in one sentence, load a PCAP, show its SHA-256 on screen
PROBLEM (45s)
  -> "email transport security fails silently: STARTTLS can be stripped, TLS 1.3 hides
     the certificate, and existing tools either guess or stay silent about it"
INPUT PCAP (20s)
  -> the capture is a real Postfix/Dovecot session, not synthetic; say so
ANALYSIS (15s)
  -> point at the History screen: run completes in well under half a second, no
     internet, no external service touched
EVIDENCE (45s)
  -> open the Evidence screen for one session; point at a frame number backing one
     finding; this is the provenance chain in one glance, no separate explanation needed
SECURITY FINDING -- SCENE A (90s)
  -> show smtp_declines and smtp_no_starttls side by side; both are benign; point at
     the AMBIGUOUS/COMPLIANT states and the explicit "no attacker, intent or
     attribution is established" text; this is the differentiation thesis, demonstrated
CROSS-SESSION REASONING (30s, verbal only unless asked)
  -> explain the mechanism in one sentence ("the same claim, checked against every
     other session with the same server, not just this one"); do not attempt the live
     multi-session drill unless a judge asks for it, then switch to the prepared capture
CERTIFICATE / CRYPTO POSTURE -- SCENE B (60s)
  -> open imap_implicit; show the certificate abstention and its stated reason (RFC
     8446 SS2, TLS 1.3 encrypts it); state plainly this is a limit of passive capture,
     not a tool limitation
OVERALL POSTURE (30s)
  -> Overview screen: score, coverage percentage, band; one sentence on why the band
     is withheld below 50% coverage
REPORT (30s)
  -> click through to the HTML report for the same session; note it is the same
     content, byte-deterministic, offline-openable
AI TRANSPARENCY -- SCENE C (60s)
  -> run smtp_starttls with AI on and off side by side; identical posture, identical
     score; state the ADR-0015 result (zero unique true detections) as a finding, not
     an apology
HONEST LIMITATION (30s)
  -> name D-11 (trust/revocation) and A-02 (detection value) explicitly, with their
     one-sentence reasons; this is the moment that most differentiates the demo from a
     sales pitch
CLOSING (20s)
  -> one sentence restating the differentiation thesis (SS4 of 02-technical-differentiation.md)
```

**Total: ~7 minutes core**, with cross-session left verbal-only in the base run so the whole
journey survives even if the multi-session prepared capture is not staged that day.

## 4. Presentation slide-level evidence plan (brief §25)

**Smallest persuasive structure identified: 9 slides, not 15.** Sections the brief lists that do
not need a dedicated slide, and why: "why existing approaches are insufficient" folds into the
Problem slide as one bullet (a separate slide invites unnecessary competitor comparison in front
of judges, which the project's own novelty discipline advises against overclaiming on); "Impact /
deployment" folds into Closing; "cryptographic intelligence" and "AI/ML role" are one slide each
matching Scene B and Scene C, not two per topic.

| # | Slide | Claim | Evidence | Visual | Demo support | Likely judge question | Answer source |
|---|---|---|---|---|---|---|---|
| 1 | Problem | email transport security fails silently and existing tools guess or stay silent | doc 01D competitor audit (3/4 hypothesised differentiators already exist elsewhere; only cross-session does not) | one-sentence problem statement, no logos | none needed | "why not just use Zeek/Suricata?" | `11-judge-question-bank.md` |
| 2 | Architecture | passive PCAP -> evidence -> deterministic rules -> cross-session -> ML (secondary) -> posture -> reports/dashboard | this repo's own architecture, `00-release-state-audit.md` §3 | the pipeline diagram from that section | none needed | "why tshark, not a custom parser?" | judge bank |
| 3 | Passive forensic pipeline | zero-dependency core, offline, no active probing | measured: zero third-party imports in the core path | terminal output of the import check | opening beat | "can this run air-gapped?" | judge bank, `10-demo-environment.md` |
| 4 | Cryptographic intelligence (D-09–D-17) | key exchange, certificates, forward secrecy, insecure config — closed where passively observable | 19 rules, 97 Phase-11 tests, 3 generated TLS 1.2 fixtures | Findings screen screenshot showing a CRITICAL finding with citation | Scene B + cert deep-dive | "why is D-11 partial?" | judge bank |
| 5 | Cross-session reasoning | the one verified-absent-from-competitors capability | doc 01D §4 | side-by-side benign-decline vs. genuine-strip finding | Scene A | "is this novel?" | `12-novelty-audit.md` |
| 6 | AI/ML role | secondary prioritisation signal, proven not decorative, honestly evaluated as non-detecting | ADR-0015/0024, `--no-ai` test | side-by-side score with AI on/off | Scene C | "why is A-02 partial? why not a better model?" | judge bank |
| 7 | Evidence & provenance | every conclusion traces to a frame, a rule, a standard | `EvidenceRef` schema, report excerpt | JSON snippet with frame number highlighted | Evidence screen | "can you prove this isn't fabricated?" | judge bank |
| 8 | Real-PCAP validation & honest limitations | 10 real captures + 3 generated fixtures; D-11 and A-02 named with reasons | `01-final-requirements-audit.md` | the requirement summary table | Scene B closing line | "what doesn't work?" | this document |
| 9 | Closing / impact | one-sentence differentiation thesis; deployable today, offline, for SOC/DFIR/incident-response use | doc 01D §12 thesis | none needed | — | "what's next?" | `13-final-engineering-decision.md` |

No slide claims novelty in absolute terms ("first," "only," "unique") — every claim above is
traceable to a specific evidence artifact in this repository, which is the standard this document
holds itself to throughout.
