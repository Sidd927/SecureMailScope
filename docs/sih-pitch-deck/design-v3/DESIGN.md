# SecureMailScope — Design System (V3 Exploration)

Status: **exploration, not implemented.** This document defines the shared design language extracted from three Stitch-generated directions (see `design-direction-a/`, `design-direction-b/`, `design-direction-c/`). Nothing here has been built. `src/` and `tests/` are untouched.

Grounding: every enum name, constant, and vocabulary term below is copied verbatim from the production source (file:line references given) or from the docs under `docs/sih-pitch-deck/`. Where a screen needed illustrative content (a filename, a hash, a finding count) to be legible as a mockup, that content is invented for demonstration only and is flagged in `IMPLEMENTATION-HANDOFF.md` — it is never a claim about what the product measured.

---

## 1. Why V2 had to be rethought

V1/V2's composition is `centered hero → "Assess an email capture" → giant upload rectangle → four explanatory columns → analyses/history`. That shape reads as a generic API-viewer/demo regardless of type or color polish, because the *information architecture* — not the styling — is what signals "generic AI tool." The three directions here change composition, navigation, density, and evidence/cross-session presentation, not just theme.

All three share one constraint the user set: **light theme only**, Apple-level restraint, forensic credibility, no dark-hacker/glow/gradient/gauge/donut/radar clichés, no fabricated metrics.

---

## 2. Shared semantic vocabulary (identical across all three directions)

Meaning must not drift between skins. These tokens are fixed system-wide; only their typographic/spacing expression changes per direction.

### 2.1 EvidenceState (six values — exact, from `src/securemailscope/evidence/states.py:22-30`)

| Value | Definition (from source docstring) |
|---|---|
| `OBSERVED` | Directly present in captured bytes |
| `INFERRED` | Deduced from observed facts (a `basis` is required) |
| `UNKNOWN` | Insufficient evidence to decide |
| `AMBIGUOUS` | Evidence supports more than one reading |
| `INCOMPLETE` | Capture truncated at the relevant point |
| `NOT_OBSERVABLE` | Structurally impossible to observe passively |

**Never** substitute, rename, or reorder these. Never add a seventh state (`NOT_APPLICABLE` belongs to `BaselineStatus`, not here — see `DO-NOT-CLAIM.md` Part II, which documents a wrong conflated vocabulary that once circulated).

Visual language: **icon + fill-pattern, never hue.** All six states share one neutral chip family (graphite/ink on the direction's neutral surface). This is what keeps evidence-state visually distinct from severity, which *is* hue-coded.

- `OBSERVED` — solid filled chip
- `INFERRED` — outlined chip + connective-dot icon
- `AMBIGUOUS` — half-filled / split-fill chip
- `INCOMPLETE` — dashed partial-fill chip
- `UNKNOWN` — dotted hollow chip
- `NOT_OBSERVABLE` — diagonal-strike chip (communicates a structural limitation, not a failure)

Editorial grouping used on the Evidence screen (matches the real V2 dashboard's own grouping, `UI-DESIGN-SPEC-V2.md`): **"What was established"** (OBSERVED, INFERRED) vs. **"What could not be established"** (AMBIGUOUS, INCOMPLETE, UNKNOWN, NOT_OBSERVABLE). Grouping only — not a new vocabulary, not a merge of the six states into two.

### 2.2 Severity (from `src/securemailscope/analysis/model.py`)

`INFO, LOW, MEDIUM, HIGH, CRITICAL` — impact *if the condition holds*, not a confidence statement. Orthogonal to evidence state by design.

| Severity | Color | Hex |
|---|---|---|
| Critical | Garnet | `#A32C2C` |
| High | Rust | `#B5541C` |
| Medium | Ochre | `#96731A` |
| Low | Steel | `#4A5B78` |
| Informational | Graphite | `#6B7280` |

Always paired with a text label and a shape/icon — never color alone (accessibility: non-color-only status).

### 2.3 Evidence certainty (derived, shown on Findings rows — `posture/model.py:180-185`)

`CONFIRMED / PROBABLE / UNCERTAIN / UNDETERMINED` — derived from the evidence states behind a finding (OBSERVED → CONFIRMED, INFERRED → PROBABLE, AMBIGUOUS/INCOMPLETE → UNCERTAIN). Shown as a badge distinct from both severity and the raw EvidenceState chip.

### 2.4 Posture bands (`posture/model.py:581-591`)

`STRONG, ADEQUATE, WEAK, CRITICAL, INSUFFICIENT_EVIDENCE` — the last is a band, not a score of zero. This is the exact word set for the one large typographic moment on the Overview screen. Never invent alternate band names.

### 2.5 Cross-session vocabulary

- `DEFAULT_MIN_HISTORY = 5` (`crosssession/baseline.py:32`) — configuration, not a hard constant. State the number, don't hide it.
- Comparability scope: **same client → same server endpoint, port, protocol, and TLS mode** (explicit vs. implicit TLS never pooled). Canonical membership phrase (`SessionRef.membership_reason`): *"prior comparable session at the same endpoint, protocol and TLS mode."* Use this phrase verbatim in UI copy.
- `BaselineStatus`: `ESTABLISHED, INSUFFICIENT_HISTORY, NOT_APPLICABLE` — a different enum from EvidenceState; don't blend them.
- `Deviation`: `NONE, DEVIATION, SUSPICIOUS_DEVIATION, NOT_ASSESSED`.
- Only *prior* sessions count toward a baseline (never capture-wide pooling — this was a fixed false-positive source, OQ-25).

### 2.6 Provenance chain (dashboard's on-screen labels, `UI-DESIGN-SPEC-V2.md`)

**Capture → Frame / Stream → Evidence → Finding → Posture → Report** — six static, presentation-only labels. Call it a "forensic trace," never "chain of custody" (that implies a legal standard this tool doesn't claim).

### 2.7 AI's role

Bounded secondary prioritisation signal only. `MAX_ML_ADJUSTMENT = 4.0` against a 30-point severity-tier gap (MEDIUM→HIGH). Zero unique true detections on any held-out split (ADR-0015). Provably identical output with the AI lane disabled (`ai_enabled=False` ⇒ ML adjustment is always `0.0`). Never say "AI detects attackers" or show an "AI threat score." AI must never be the dominant visual element on any screen.

### 2.8 Observability limitation (TLS 1.3 / certificates)

RFC 8446 §2 encrypts the Certificate message under TLS 1.3; a resumed session never sends it. The product reports **NOT_OBSERVABLE**, not "untrusted" or blank. Never imply trust/revocation was checked when it structurally could not be (0 of 10 real captures exposed a certificate under TLS 1.3, per ADR-0023).

---

## 3. Typography

| Direction | Headline | Body | Data / mono |
|---|---|---|---|
| A — Editorial Forensic | Newsreader (editorial serif, headers only) | Geist | JetBrains Mono |
| B — Premium Security Product | Geist (no serif) | Geist | Google Sans Mono |
| C — Technical Investigation | IBM Plex Sans | IBM Plex Sans | JetBrains Mono (all numerics, system-wide — density override) |

Shared rules across all three:
- **Inter is banned** (generic, no character for a premium security tool).
- Generic serifs (Times, Georgia, Garamond) are banned outright; Direction A's serif use is deliberately a *distinctive* editorial face (Newsreader), restricted to section titles/report headers, never body copy or UI chrome.
- Type scale communicates hierarchy through weight and size, not color — color is reserved for severity/evidence meaning (this mirrors the real V2 spec's own rule: "colour is reserved for meaning").
- One typographic headline per screen: on Overview, the posture-band word is the only large element (34px-scale equivalent). No second headline competes with it.
- Max ~65 characters per line for prose (methodology, finding rationale).

## 4. Color discipline

All three directions are **light mode only**. Canvas is always an off-white/near-white, never pure `#FFFFFF`-flat or pure `#000000` text.

| Direction | Canvas | Ink | Secondary ink | Single accent |
|---|---|---|---|---|
| A | `#FAF9F6` (paper) | `#20242B` | `#5B6472` | `#3A4A5C` (slate ink-blue) |
| B | `#F7F8F9` | `#1E2328` | `#5C6670` | `#285E73` (desaturated teal-blue) |
| C | `#F5F6F5` | `#1C1F21` | `#5A5F63` | `#8A5A2B` (muted amber-rust, used like a highlighter) |

Each direction's accent is saturation-capped (<80%), used *only* for primary actions, active nav, links, and focus rings — never decoratively. Severity and evidence-state colors (§2.1–2.2) are identical across all three directions; only the neutral/accent skin changes. Hairline borders (1px, ~10–14% opacity of ink) are the primary structural device — not shadows, not card elevation.

## 5. Layout & navigation (this is where the three directions actually diverge)

| | A — Editorial Forensic | B — Premium Security Product | C — Technical Investigation |
|---|---|---|---|
| Shell | Persistent left nav (icon+label) + wide analytical canvas | Refined top nav + secondary contextual tab/segment rail | Three-pane: left rail (nav+session context), central canvas, right contextual inspector |
| Density | 6/10 | 5/10 | 8/10 (cockpit-dense) |
| Variance | 6/10, asymmetric grid, unequal-width columns | 4/10, orderly, systematic | 5/10 |
| Motion | 2/10 — near-static, functional only | 3/10 — refined hover/focus/expand only | 2/10 — static/functional |
| Findings | Horizontal record rows, hairline border-top dividers | Compact table-like rows | Dense mono-numbered rows |
| Evidence/provenance | Horizontal rail, editorial two-cluster grouping | Structured stepper/rail, hover-reveal | Signature component: schematic rail with hex/byte node references |
| Cross-session | Two-column Current vs. Comparable History | Segmented comparison module | Side-by-side panels, first-class persistent concept (not buried) |
| Roundness | 4px | 8px | 4px |

No direction uses a centered marketing hero, a dashed dropzone as the primary intake metaphor, a 3-equal-card feature row, or a circular/donut/radar chart anywhere.

## 6. Components

- **Buttons** — flat fill primary (direction accent), hairline-outline secondary, ‑1px tactile press on active, zero outer glow, zero neon.
- **Finding rows** — never cards. Severity chip + title + one-line explanation + protocol tag + evidence-certainty badge (visually separated from severity) + standard citation tag (e.g. "RFC 8446 §2"). Inline disclosure expansion (not a modal) reveals full explanation, evidence link, remediation, limitations.
- **Evidence chips** — the six-state icon+fill-pattern family from §2.1, identical across directions.
- **Provenance rail** — six clickable nodes (§2.6), hairline connectors, per-node count badge, inline (not modal) detail on selection.
- **Cross-session module** — Current Session vs. Comparable History; when `len(prior) < DEFAULT_MIN_HISTORY`, replace the comparison with a **dignified abstention state** stating the exact count found vs. required (e.g. "2 of 5 required comparable sessions found — no baseline established yet") — framed as expected behavior, never an error.
- **Intake/upload** — never a giant dashed dropzone. A compact bordered "Start an investigation" panel: file-select control, supported-protocol line, and (once a file is chosen) a capture-inspection panel showing filename, size, truncated SHA-256, pre-scan protocol hints, and stream count — before a single explicit "Analyze capture" action. An honesty note states that posture/findings are not pre-judged at staging.
- **Loading** — skeletal placeholders matching exact layout geometry. No circular spinners.
- **Empty/abstention states** — composed, dignified, specific about *why* (never a generic "no data").
- **Error states** — same calm editorial tone as the rest of the product; neutral graphite, not alarm red; states what went wrong, a technical detail line in mono, one clear recovery action ("Choose a different capture"), never implies partial success.

## 7. Responsive behavior

Validated target 1440×900 (matches the real V2 spec's own target); designed to also hold at 1280×800 and 1600×1000 with no horizontal overflow. Three-pane layouts (Direction C) collapse the right inspector panel first below ~1280px; two-column comparisons (cross-session) stack vertically below that. Touch targets ≥44px where relevant; this is a desktop-first analyst tool, not a mobile product, per the brief.

## 8. Accessibility

- Non-color-only status: every severity and evidence-state indicator pairs color/pattern with a text label and/or icon.
- High-contrast ink-on-canvas ratios (WCAG AA target, matching the real V2 dashboard's own pinned contrast tokens).
- Visible focus rings in the direction's single accent color, 1px offset outline — never removed.
- Semantic heading hierarchy per screen; one H1-equivalent per screen (the posture band on Overview, the panel title on Home, etc.).
- Reduced-motion: nothing here depends on animation to convey state — motion is capped at 2–3/10 across all directions and used only for functional transitions (expand/collapse, hover reveal), never decoratively.

---

See `design-direction-a/`, `design-direction-b/`, `design-direction-c/` for direction-specific screens and screenshots, `DESIGN-REVIEW.md` for the self-critique against the brief's standard, and `IMPLEMENTATION-HANDOFF.md` for what's real vs. illustrative and how this maps to the actual API/data model.
