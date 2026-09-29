# FINAL PITCH-DECK HANDOFF

**Read this first.** Single entry point for anyone building the SIH26159 deck who has not followed
the engineering history. Everything here is verified against the repository on 2026-09-23.

Detailed documents remain authoritative for their own topic; this is the map.

---

## A. Project one-liner

> **SecureMailScope reads a passive email packet capture and produces a standards-cited
> cryptographic security posture — by reasoning across comparable prior sessions at the same
> endpoint rather than judging each connection alone, which is what makes it possible to tell a
> stripped STARTTLS from a client that simply declined.**

## B. SIH six-slide structure (official, fixed — verified from the template file)

| # | Official heading | Sub-pointers (must not be changed) |
|---|---|---|
| 1 | `TITLE PAGE` | PS ID · PS Title · Theme · PS Category · Team ID · Team Name |
| 2 | `IDEA TITLE` | Proposed solution · How it addresses the problem · Innovation and uniqueness |
| 3 | `TECHNICAL APPROACH` | Technologies · Methodology (flow charts/images/working prototype) |
| 4 | `FEASIBILITY AND VIABILITY` | Feasibility · Challenges and risks · Strategies |
| 5 | `IMPACT AND BENEFITS` | Impact on target audience · Benefits |
| 6 | `RESEARCH AND REFERENCES` | Reference and research work |

**Max 6 slides including the title page. No paragraphs. Export as PDF only.**
Source: `00-official-sih-format-research.md`.

## C. Slide-by-slide canonical content (summary — full text in `FINAL-SLIDE-CONTENT.md`)

| Slide | One job | Headline |
|---|---|---|
| 1 | administrative compliance | *(template default)* |
| 2 | **the differentiator** | Reasoning across sessions, not just parsing packets |
| 3 | prove a real engineered system | A deterministic evidence pipeline — with AI kept in its place |
| 4 | measured results **+ honest limits** | A working prototype — and we can name exactly what it cannot prove |
| 5 | who benefits, operationally | Evidence an analyst can defend |
| 6 | standards grounding | *(heading fixed)* |

## D. Five most important technical facts

1. **Cross-session reasoning** compares a session against **comparable prior sessions at the same
   endpoint, protocol and TLS mode**; a baseline needs **≥5** prior comparable sessions
   (`DEFAULT_MIN_HISTORY = 5`), below which the engine **abstains**.
2. **Six evidence states** (`EvidenceState`) are never collapsed — missing evidence never becomes
   a verdict in either direction, and **cannot improve a score** (enforced in code).
3. **19 rules total** (16 deterministic + 3 cross-session), every finding citing one of
   **11 published standards** (8 RFCs + 3 NIST SPs).
4. **The ML lane is structurally bounded**: capped at **4.0** against a **30-point severity-tier
   gap**, so it can re-rank within a tier and can **never** create a finding or cross a tier.
5. **Provenance is complete**: PCAP SHA-256 → frame → TCP stream → evidence state → finding →
   cited standard → report; artifacts are content-addressed and re-verified on access.

## E. Five most important limitations (these must stay visible)

1. **TLS 1.3 encrypts the certificate** (RFC 8446 §2) — **0 of 10** real captures expose one.
2. **Certificate trust and revocation are not observable** from passive capture alone (RFC 5280 §6
   needs a trust anchor a PCAP lacks; RFC 6960 OCSP/CRL are network transactions). **D-11 PARTIAL.**
3. **The ML lane showed zero unique true detections** on every held-out split. **A-02 PARTIAL.**
4. **Certificate analysis is validated on generated TLS 1.2 fixtures**, not real-world traffic,
   because the real corpus is entirely TLS 1.3.
5. **Scale is untested** — no capture beyond a few hundred KB; no load testing exists.

Plus, for completeness: with **no comparable control endpoint**, consistent stripping and a
legitimately plaintext-configured server remain **passively indistinguishable** — and the engine
says so itself rather than guessing.

## F. Exact approved terminology

| Concept | Approved wording |
|---|---|
| The six states | `OBSERVED · INFERRED · UNKNOWN · AMBIGUOUS · INCOMPLETE · NOT_OBSERVABLE` |
| Cross-session scope | "comparable prior sessions at the same endpoint, protocol and TLS mode" |
| Cross-session output | "reports a **deviation**" |
| Certificates | "assesses observable certificate properties and chain **structure** where the handshake exposes them" |
| Trust/revocation | "not observable from passive PCAP alone" |
| Dependencies | "**0 third-party Python runtime packages** in the analysis core; **TShark is the required external dissection binary**" |
| Deployment | "**runs without network access**" |
| AI | "bounded secondary prioritisation signal"; "provably identical with the AI lane disabled" |
| Novelty | "our source-code audit of five competing SIH26159 implementations found none performing cross-session reasoning" |
| Generated data | "**GENERATED TLS 1.2 FIXTURE**" / "generated scenario corpus" |

## G. Exact forbidden terminology

"AI detects attacks" · "AI identifies attackers" · "ML accuracy/precision/recall/F1" ·
"we validate certificates" (unqualified) · "certificate trust checked" · "revocation checked" ·
"detects every STARTTLS stripping attack" · "zero false positives" · "100% detection" ·
"reduces false positives by X%" · "first" / "unique" / "only" / "revolutionary" · "real-time" ·
"enterprise scale" · ROI / TAM / mailbox counts · "chain of custody" · "court admissible" ·
"we decrypt email" · "zero dependencies" · "air-gapped" · `NOT_APPLICABLE` as an evidence state.

Full table with correct alternatives: `DO-NOT-CLAIM.md`.

## H. Real vs generated evidence map

| Evidence | Category | Use it for | Never call it |
|---|---|---|---|
| 10 Postfix + Dovecot captures (`oq33r`) | **REAL validated** | feasibility, protocol coverage, TLS 1.3 observability | — |
| 25 scenario captures (`oq28`), incl. `G_control_endpoint` / `H_no_control` | **GENERATED scenario corpus** | cross-session demonstration | "real-world" / "production traffic" |
| 3 TLS 1.2 captures (`p11cert`) | **GENERATED fixtures** | certificate-analysis validation | "real-world certificate validation" |

## I. Verified metrics (exact values — do not round or embellish)

| Metric | Value |
|---|---|
| Automated tests | **1234**, 0 failures, 0 skips (3 independent runs) |
| Real validated captures | **10** (Postfix + Dovecot) |
| Protocols / TLS modes | **3** / **4** |
| Deterministic rules | **16** · Cross-session rules: **3** |
| Published standards | **11** (8 RFCs + 3 NIST SPs) |
| Evidence states | **6** |
| Analysis latency | **115–320 ms** per validated capture |
| Repeat-run stability | **20/20** identical |
| ML adjustment cap / tier gap | **4.0** / **30** |
| ML detection value (held-out) | **0** unique true detections |
| Certificates visible under TLS 1.3 | **0 of 10** |
| Cross-session baseline threshold | **≥5** prior comparable sessions |
| Competing implementations audited | **5**; cross-session found in **0** |
| Third-party Python runtime packages (core) | **0** (TShark required externally) |

## J. Architecture diagram specification

**Primary (Slide 3):**
`PCAP → dissect (TShark) → session reconstruction → 16 deterministic rules → 3 cross-session rules
→ evidence fusion → coverage-gated posture → JSON/HTML/PDF + analyst dashboard`

**ML lane:** a visually subordinate branch, feeding **ranking only**, with the arrow into findings
**visibly blocked**. Label: `ML lane — ranking only (capped 4.0 / 30-pt tier gap)`.

**Secondary (Slide 3):** six-state strip, exact spelling per §F.
**Footer strip (Slide 3):** the provenance chain.
**Primary (Slide 2):** the ✗/✓ same-endpoint contrast.

## K. Screenshot / asset checklist

See `FINAL-ASSET-CHECKLIST.md`. **Blocking item: no dashboard screenshot exists yet**
(`demo/screenshots/` is empty). Produce with `bash demo/commands/start_demo.sh`, upload a capture
from `demo/captures/`, screenshot the Overview screen.

## L. Judge Q&A — top 15

Full answers: `19-judge-attack-map.md` and `docs/finalization/10-final-judge-cheatsheet.md`.
Answer pattern throughout: **Concede → Scope → Evidence → Boundary.**

1. *Isn't this just TShark?* — TShark dissects; it produces no security verdict, no cross-session
   reasoning, no evidence states. It's our dependency, not our competitor.
2. *Zeek already correlates across connections.* — **Concede immediately.** Our claim is scoped to
   five audited SIH implementations, not the NSM field.
3. *What's novel?* — Integration-grade differentiation for this mail-forensics workflow; not a
   research breakthrough. We never claim otherwise.
4. *What if STARTTLS is stripped every time?* — Then it's passively indistinguishable from a server
   that never offered it, and the engine states that limitation itself.
5. *How do you know it isn't legitimate configuration?* — We don't, and we say so. The finding
   reports a *deviation*, never an attack.
6. *Why five sessions?* — `DEFAULT_MIN_HISTORY = 5`; below it the engine abstains rather than
   inferring from thin history.
7. *Why keep AI if it found nothing?* — The PS requires AI/ML; we shipped a real, properly
   evaluated model and report the negative result instead of inflating it.
8. *What does the AI actually change?* — Ranking within a severity tier. Nothing else. Proven by
   `--no-ai` equivalence.
9. *Why can't you see certificates?* — TLS 1.3 encrypts them (RFC 8446 §2). 0 of 10 real captures.
10. *Can you validate certificate trust?* — No. A PCAP contains no trust anchor. D-11 is PARTIAL.
11. *Can you check revocation?* — No. OCSP/CRL are separate network transactions.
12. *Is this real-time?* — No. Batch analysis over captures, 115–320 ms each.
13. *How does it scale?* — Untested. Designed for analyst-workstation use.
14. *How many real captures?* — 10, across 3 protocols and 4 TLS modes, two vendors.
15. *Why are certificate tests generated?* — Because the real corpus is 100% TLS 1.3 and
    structurally cannot expose a certificate. We label the fixtures as generated.

## M. Source hierarchy

```
Production source / executed experiment   ← highest authority
        ↓
Verified project evidence (tests, measured runs)
        ↓
Research documents
        ↓
Pitch-deck content
        ↓
Visual/design instructions                ← lowest authority
```

**A presentation document never overrides the implementation.** If a conflict is found, resolve it
against the repository and update the deck — not the other way round.

## N. Final export checklist

- [ ] Exactly **6 slides** (delete the template's instruction slide)
- [ ] Official headings and sub-pointers **unchanged**
- [ ] Team ID and Team Name filled in
- [ ] Six evidence states spelled exactly per §F
- [ ] Every generated capture labelled **generated**
- [ ] Dependency wording includes **TShark**
- [ ] No forbidden term from §G anywhere
- [ ] TLS 1.3 "0 of 10" styled as a boundary, **not** red/failure
- [ ] ML lane visually subordinate, arrow to findings blocked
- [ ] Dashboard screenshot captured and captioned with its source capture
- [ ] Cross-checked against `FINAL-CLAIM-AUDIT.md`
- [ ] Exported as **PDF**
