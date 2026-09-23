# FINAL ASSET CHECKLIST

Every visual asset the deck needs. **Nothing here is fabricated** — assets that do not yet exist
are marked `NOT CREATED`, not described as if they were ready.

---

## Status summary

| Status | Count |
|---|---|
| ✅ Ready (content fully specified, diagram trivial to draw) | 0 |
| 🟡 Specified, needs drawing | 5 |
| 🔴 Blocking — requires a running system | 1 (dashboard screenshot) |
| ⚪ Optional | 2 |

---

## 1. Cross-session contrast diagram — 🟡 NOT CREATED

| | |
|---|---|
| **Slide** | 2 (primary visual) |
| **Source** | `docs/finalization/06-cross-session-demo.md` — real engine output from `G_control_endpoint.pcap` |
| **Real or generated** | **GENERATED scenario corpus** — do not caption as real-world traffic |
| **Owner** | ⟨design⟩ |
| **Required content** | Two rows under "Same endpoint, same capture": `Client A: ✗ ✗ ✗ ✗ ✗ (never upgrades)` and `Other clients: ✓ ✓ ✓ ✓ ✓ ✓ (always upgrade)`. Arrow down to the quoted finding: *"This endpoint consistently lacks the upgrade capability while comparable endpoints at the same server consistently have it."* Label the second row **Control endpoint**. |
| **Must not** | imply an attack was detected; use the word "deviation", never "attack" |

## 2. Pipeline flow diagram — 🟡 NOT CREATED

| | |
|---|---|
| **Slide** | 3 (primary visual) |
| **Source** | `docs/phase12/00-release-state-audit.md` §3; verified against `ALL_RULES` |
| **Real or generated** | n/a (architecture) |
| **Owner** | ⟨design⟩ |
| **Required content** | `PCAP → Dissect (TShark) → Session reconstruction → 16 deterministic rules → 3 cross-session rules → Evidence fusion → Coverage-gated posture → Reports (JSON/HTML/PDF) → Analyst dashboard`, plus a **visually subordinate** ML branch labelled `ML lane — ranking only (capped 4.0 / 30-pt tier gap)` with its arrow into findings **visibly blocked** |
| **Must not** | give the ML lane equal visual weight; use brain/robot/neural imagery |

## 3. Six evidence-state strip — 🟡 NOT CREATED

| | |
|---|---|
| **Slide** | 3 (secondary visual) |
| **Source** | `evidence/states.py`, verified 2026-09-23 |
| **Owner** | ⟨design⟩ |
| **Required content** | Exactly, in this spelling: `OBSERVED · INFERRED · UNKNOWN · AMBIGUOUS · INCOMPLETE · NOT_OBSERVABLE`, with the caption *"Missing evidence can never improve a score."* |
| **Must not** | include `NOT_APPLICABLE` or `INSUFFICIENT_EVIDENCE` — those belong to different enums (`DO-NOT-CLAIM.md` §A) |

## 4. Results number strip — 🟡 NOT CREATED

| | |
|---|---|
| **Slide** | 4 (primary visual) |
| **Source** | `docs/finalization/14-final-release-gate.md`; measurements re-verified 2026-09-23 |
| **Owner** | ⟨design⟩ |
| **Required content** | `1219` automated tests, 0 failures · `10` real Postfix/Dovecot captures · `11` published standards · `<1 s` (115–320 ms) per capture · `20/20` identical repeat runs |
| **Must not** | round, embellish, or add a coverage percentage |

## 5. Provenance strip — 🟡 NOT CREATED

| | |
|---|---|
| **Slide** | 3 (footer, single line) |
| **Source** | `EvidenceRef`; traced across 13 executions |
| **Owner** | ⟨design⟩ |
| **Required content** | `PCAP SHA-256 → frame → TCP stream → evidence state → finding → cited standard → report` |
| **Must not** | be captioned "chain of custody" or "court admissible" |

## 6. Dashboard screenshot — 🔴 BLOCKING, NOT CAPTURED

| | |
|---|---|
| **Slide** | 5 (primary visual) |
| **Source** | live system — `demo/screenshots/` is **currently empty** |
| **Real or generated** | **must caption with the source capture and whether it is real or generated** |
| **Owner** | ⟨team⟩ |
| **How to produce** | `bash demo/commands/start_demo.sh` → open `http://127.0.0.1:8000/dashboard/` → **drag a capture from `demo/captures/` onto the drop zone** → `Analyze capture` → screenshot the **Overview** screen. The console submits captures itself as of the dashboard redesign; no terminal step is involved. |
| **Viewport** | 1440 × 900 (the validated primary target — `UI-IMPLEMENTATION-NOTES.md` §8) |
| **Required content** | the hero block, in which posture band, score, evidence coverage, finding count and abstention count are visible together by construction |
| **Recommended capture** | `scene_b_certificate_honesty.pcap` (**real** — Dovecot IMAPS) so the screenshot can be honestly captioned as real-vendor traffic |
| **Must not** | screenshot a generated-fixture result and caption it as real-world |

## 7. Findings-screen screenshot — ⚪ OPTIONAL

| | |
|---|---|
| **Slide** | 5 (alternative to #6) |
| **Required content** | a prioritised finding with its severity and cited standard visible |
| **Caption requirement** | same provenance rule as #6 |

## 8. Evidence-screen screenshot — ⚪ OPTIONAL

| | |
|---|---|
| **Slide** | 3 |
| **Required content** | an abstention with its "what would resolve this" text |
| **Note** | strongest single image for the forensic-honesty story if Slide 3 has room |

## 9. Generated-fixture labelling — ⚠️ PROCESS CHECK, not an asset

Any visual derived from `research/experiments/p11cert/` (the RSA-1024 / SHA-1 / self-signed
results) **must carry the label "GENERATED TLS 1.2 FIXTURE"** on the slide itself, not only in
speaker notes. The real corpus is 100% TLS 1.3 and cannot produce these results.

## 10. Final PDF export — 🟡 PENDING

| | |
|---|---|
| **Requirement** | exactly 6 slides; official headings and sub-pointers unchanged; PDF format only |
| **Gate** | `FINAL-PITCH-DECK-HANDOFF.md` §N checklist must pass first |

---

## The one genuine blocker

**Asset #6 (dashboard screenshot).** Everything else is diagram work that can proceed immediately
from the specifications above. The screenshot requires a running system and cannot be fabricated —
and Slide 5 is materially weaker without it.

**Status update (2026-09-24):** the capture-and-screenshot step is now a pure UI action. The
dashboard redesign added in-console capture submission, so producing this asset no longer requires
a `curl` command or any terminal work beyond starting the server. The screenshot itself still has
to be taken from a live run and still must be captioned with its source capture and whether that
capture is real or generated. Assets #7 (Findings) and #8 (Evidence) are produced the same way and
are now materially stronger: the Evidence screen renders the full six-state vocabulary, and the
Overview renders the abstentions with their "what would settle this" text.
