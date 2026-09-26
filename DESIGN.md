# SecureMailScope — Design System
**Document Version:** 1.0 (Phase 1 Design Direction)
**Branch:** `frontend/final-user-experience`
**Status:** Draft — awaiting approval before token consolidation (Phase 1D)

---

## 0. Who this is for

SecureMailScope is not a mail client and not a SaaS dashboard. It is a **passive PCAP forensic instrument** used by NTRO security analysts to determine the cryptographic posture of captured email-protocol sessions, then defend that determination with frame-level evidence and standards citations. The audience reads dense technical output for a living, works long sessions, and needs to trust every color and label as a truth-claim, not a decoration. A wrong color here is a wrong statement about evidence.

This document blends three references, each for a specific reason:
- **Linear** — the four-step dark surface ladder, hairline borders instead of shadows, one scarce chromatic accent, negative-tracked display type. This is where the app's *restraint* comes from.
- **Stripe** — tabular-figure (`tnum`) discipline for every number that means something (scores, penalties, byte counts, frame numbers). This is where the app's *numeric honesty* comes from.
- **Vercel** — stacked micro-shadows over single heavy drops, monospace reserved strictly for the technical layer (code, hashes, frame IDs), sentence-case headlines. This is where the app's *instrument-grade calm* comes from.

None of the three are followed literally — SecureMailScope is not a marketing site, has no hero gradient, and is not selling anything. What's borrowed is the *discipline*, not the surface.

---

## 1. Color System

### 1.1 Base palette (6 hex values)

| Token | Hex | Role |
|---|---|---|
| `--sms-canvas` | `#0a0e14` | Page background. Near-black with a cool slate-navy tint — never pure `#000000`. |
| `--sms-surface-1` | `#10151d` | Card / panel background — one step up from canvas. |
| `--sms-surface-2` | `#161d27` | Elevated / hovered surface — dropdowns, active rows. |
| `--sms-ink` | `#e8ecf1` | Primary text — off-white, never pure `#ffffff`. |
| `--sms-accent` | `#4c8edb` | Primary accent — a precise steel-blue. Deliberately not Linear's lavender (`#5e6ad2`), Stripe's indigo (`#533afd`), or Vercel's link-blue (`#0070f3`) — those all read as "SaaS brand." This reads as an oscilloscope trace. |
| `--sms-crimson` | `#e5484d` | The one semantic red — CRITICAL posture, HIGH/CRITICAL severity, OBSERVED_ISSUE. |

### 1.2 Full surface ladder

| Token | Hex | Use |
|---|---|---|
| `--sms-canvas` | `#0a0e14` | Page background |
| `--sms-surface-1` | `#10151d` | Cards, panels |
| `--sms-surface-2` | `#161d27` | Elevated: dropdowns, hovered rows, active tab |
| `--sms-surface-3` | `#1b232f` | Modals, command palette, popovers |
| `--sms-border-subtle` | `#1c2430` | Hairline dividers within a panel (table rows) |
| `--sms-border-default` | `#2a3441` | Default card/input border |
| `--sms-border-strong` | `#3a4656` | Emphasized border — focused state resting border, active tab underline |

### 1.3 Text hierarchy (4 levels)

| Token | Hex | Use |
|---|---|---|
| `--sms-ink-primary` | `#e8ecf1` | Headlines, primary findings, body copy that carries the argument |
| `--sms-ink-secondary` | `#a8b3c2` | Supporting copy, field labels, secondary determinations |
| `--sms-ink-muted` | `#74808f` | Metadata, timestamps, helper text |
| `--sms-ink-disabled` | `#48505c` | Disabled controls, placeholder text |

### 1.4 Primary accent

`--sms-accent: #4c8edb` — used **only** for: interactive elements (links, active tab underline, primary button fill, focus rings), the brand mark, and the selected state in the command palette. Never used as a status color and never as a card fill. A lighter tint `--sms-accent-tint: #8fbceb` is used where accent-colored *text* must sit directly on `--sms-canvas` (button fill uses the base accent with white text instead).

### 1.5 Secondary accent

`--sms-amber: #d9a441` — a restrained gold, used for: highlighted/pinned rows, the "recommended action" callout in remediation cards, and doubles as the WEAK/AMBIGUOUS semantic tone (see §1.7). Never used decoratively.

### 1.6 Secure/encryption indicator

`--sms-teal: #3fc7b8` — a distinct cyan-teal, used *only* to indicate TLS/encryption state (implicit-TLS badges, "Encrypted" ML-lane-disabled-safe indicators, cipher suite chips). Deliberately not the same hue as the primary accent or the success green, so "this is encrypted" and "this is good" never get visually conflated — TLS presence is not the same claim as posture strength (a capture can be encrypted *and* CRITICAL, per the weak-cert scenario).

### 1.7 Semantic colors (severity family)

| Token | Hex | Use |
|---|---|---|
| `--sms-success` | `#4cb782` | LOW severity, COMPLIANT status, STRONG posture |
| `--sms-warning` | `#d9a441` | MEDIUM severity, WEAK posture (shares the amber secondary accent) |
| `--sms-error` | `#e5484d` | HIGH/CRITICAL severity, CRITICAL posture, OBSERVED_ISSUE |
| `--sms-info` | `#4c8edb` | INFO severity (shares the primary accent — informational is inherently "neutral-interactive," not alarming) |

Each of these ships in three strengths: `-ink` (text), `-bg` (a ~10%-opacity tint of the same hue over `--sms-surface-1`), `-border` (a ~30%-opacity tint) — mirroring the existing `--sev-*-ink/-bg/-border` pattern already in `theme.css`, just remapped to dark-theme-appropriate values.

### 1.8 The four status families — never visually collapsed

The backend exposes **four structurally different kinds of state**, and the existing `theme.css` already keeps them in separate token namespaces (`--sev-*`, `--posture-*`, `--epistemic-*`). This design system keeps that separation and makes the *visual logic* for each explicit:

**A. Evidence state** (`EvidenceState`: `OBSERVED, INFERRED, UNKNOWN, AMBIGUOUS, INCOMPLETE, NOT_OBSERVABLE`) — gets a **neutral ink + border-style** family, not hue. This is the epistemic layer; it should never compete visually with severity's hue-coded urgency, because "how sure are we" and "how bad is it" are different questions asked at the same time on the same row.

| State | Border style | Ink | Meaning |
|---|---|---|---|
| `OBSERVED` | solid | `--sms-ink-primary` | Directly present in captured bytes — the calmest, most certain treatment |
| `INFERRED` | dashed | `--sms-accent-tint` | Deduced from observed facts |
| `AMBIGUOUS` | dotted | `--sms-amber` | Evidence supports more than one reading |
| `UNKNOWN` | dotted | `--sms-ink-muted` | Insufficient evidence to decide |
| `INCOMPLETE` | dashed | `--sms-ink-secondary` with an orange tick | Capture truncated at the relevant point |
| `NOT_OBSERVABLE` | solid, reduced opacity (0.6) | `--sms-ink-muted` | Structurally impossible to observe — deliberately looks *absent*, not alarming |

**B. Severity** (`Severity`: `INFO, LOW, MEDIUM, HIGH, CRITICAL`) — gets **hue**, per §1.7. This is the only family allowed to use saturated color for alarm.

**C. Posture band** (`PostureBand`: `STRONG, ADEQUATE, WEAK, CRITICAL, INSUFFICIENT_EVIDENCE`) — gets its own **large-composition treatment**, not just a colored pill: the big score number, the waterfall, the banner. It reuses severity's hue logic where the words overlap (CRITICAL posture *is* visually red, deliberately, because forcing a different hue for the same concept would be confusing) but is distinguished by scale and layout, never by a conflicting color grammar. `INSUFFICIENT_EVIDENCE` is the one exception: it renders in the *evidence-state neutral family* (`--sms-ink-muted`, dotted treatment), never in a "failure" color — refusing to grade is not the same as grading zero.

**D. Job/run lifecycle** (`JobState`: `CREATED, VALIDATING, QUEUED, RUNNING, FINALIZING, COMPLETED, FAILED, CANCELLED, RECOVERY_REQUIRED`) — gets a **third, minimal treatment**: a small status dot + ink color, no border-style variation, no large composition. In-progress states (`VALIDATING, QUEUED, RUNNING, FINALIZING`) use `--sms-accent`; terminal states resolve to the obvious semantic (`COMPLETED`→success, `FAILED`→error, `CANCELLED`→muted, `RECOVERY_REQUIRED`→warning, `CREATED`→muted).

---

## 2. Typography

### 2.1 Family

**IBM Plex Sans** (UI, body, headlines) + **IBM Plex Mono** (evidence values, frame references, hashes, timestamps, cipher suite strings). One family pair, committed fully — not Inter, not Roboto, not Space Grotesk, not Geist (Geist would echo the Vercel reference too literally; IBM Plex reads as regulatory/enterprise-instrument, which fits an NTRO-facing tool better than a startup-devtool face).

Mono is **first-class**, not an afterthought: every evidence value, every frame/stream reference, every hash, every timestamp, and every cipher/algorithm string renders in `--sms-font-mono`. This is the app's Stripe-derived "numeric honesty" signal — a reader should be able to tell at a glance which strings are the analyst's prose and which are load-bearing forensic data, the same way Stripe's `tnum` marks "this is money."

### 2.2 Scale

| Token | Size | Use |
|---|---|---|
| `--sms-text-xs` | 12px | Metadata, timestamps, table micro-labels |
| `--sms-text-sm` | 13px | Secondary body, badge labels |
| `--sms-text-base` | 14px | Default UI body — the working size for a dense instrument |
| `--sms-text-md` | 16px | Lead paragraphs, finding conclusions |
| `--sms-text-lg` | 20px | Section headings |
| `--sms-text-xl` | 24px | Panel titles ("Investigation Summary") |
| `--sms-text-display` | 32px | The one big number — posture score |

No intermediate sizes. Six steps, no 15px/18px/28px stragglers.

### 2.3 Line height & tracking

- Body: `1.4`.
- Long-form evidence prose (finding explanations, remediation text): `1.6` — these need to breathe more than a UI label does.
- Headlines: slight negative tracking (`-0.01em`) — a small nod to the Linear/Vercel display voice, kept subtle because this app has no hero moment to spend it on.
- Body and mono: normal tracking. Never letter-spaced positively except the existing `ANALYSIS` / `TECHNICAL` / `DELIVERABLE` mono-caps group labels in the workbench nav, which already use `+0.06em` — keep that, it is functioning as a real taxonomy label, not decoration.

### 2.4 Numeric discipline (the Stripe borrow)

Every number that is a **score, penalty, byte count, frame number, or port number** renders with `font-feature-settings: "tnum"` in `--sms-font-mono`. This is non-negotiable for the posture score and the score waterfall — those numbers are the entire argument of the Summary screen.

---

## 3. Spacing

- Base unit: 4px (unchanged from the existing `theme.css` scale — it's already correct).
- Working values: `8px, 12px, 16px, 24px` cover nearly everything — tighter than a consumer product's `16/24/32/48`, because density is the correct choice for an analyst's working instrument, not a compromise.
- Section padding: 24px.
- Card padding: 16px (compact — evidence tables, badge rows) / 24px (standard — finding cards, summary panels).
- Table/list row padding: 10px vertical. Density is earned here specifically because rows are homogenous and scannable, not because "dense = professional" as a blanket rule.

| Token | Value |
|---|---|
| `--sms-space-1` | 4px |
| `--sms-space-2` | 8px |
| `--sms-space-3` | 12px |
| `--sms-space-4` | 16px |
| `--sms-space-6` | 24px |
| `--sms-space-8` | 32px |
| `--sms-space-row` | 10px |

---

## 4. Component tokens

### 4.1 Radius

| Token | Value | Use |
|---|---|---|
| `--sms-radius-input` | 4px | Inputs, cards |
| `--sms-radius-badge` | 2px | Badges, pills, status chips — tighter than cards, reads as "data," not "UI chrome" |
| `--sms-radius-table` | 0px | Data tables — forensic data should feel like a printed report, not a rounded widget |
| `--sms-radius-modal` | 8px | Modals, command palette, dropdowns |

### 4.2 Shadows

Minimal, on purpose — per Linear's near-total absence of shadow on dark surfaces, and per the app's own instrument framing: elevation is carried by the surface ladder (§1.2) and hairline borders, not by drop shadow. Two levels only, both subtle stacked shadows in the Vercel style (small offsets, low opacity — never one heavy blur):

| Token | Value | Use |
|---|---|---|
| `--sms-shadow-card` | `0 1px 2px rgba(0,0,0,0.24)` | Barely-there — default card lift off canvas |
| `--sms-shadow-modal` | `0 8px 24px rgba(0,0,0,0.36), 0 2px 6px rgba(0,0,0,0.24)` | Command palette, modals, the one place real elevation is earned |

### 4.3 Motion

Unchanged from the existing `theme.css` timing tokens — they're already correct: `150ms` (`--duration-micro`) for hover/focus micro-interactions, `250ms` (`--duration-normal`) for page-level transitions, `cubic-bezier(0.16, 1, 0.3, 1)` ease-out throughout. `prefers-reduced-motion` is already respected globally in `theme.css` and stays as-is.

---

## 5. What this document does NOT change yet

This is the Phase 1 design *direction* — it defines values, not where every current pixel comes from. Phase 1D (token consolidation, pending your approval) will:
- Resolve the `theme.css` vs `DirectionS.css` duplicate `:root` conflict using **these values** as the tiebreaker.
- Migrate the existing light-theme tokens (`--bg-app: #f8fafc` etc.) to this dark palette.
- Leave `--color-*` / `--evidence-*` compatibility aliases (added in Phase 0B) pointing at the new canonical names, so nothing silently breaks.

No component code changes in this step. No visual regression check applies to *this* document — it applies to Phase 1D's execution of it.

---

## 6. Anti-slop checklist (self-audit against `frontend-design` + `design-taste-frontend` skills)

- [x] Not Inter/Roboto/Arial/Space Grotesk/Geist-by-default — IBM Plex chosen deliberately for the regulatory-instrument fit.
- [x] Not the beige/cream + serif + terracotta AI-tell, not the near-black + neon-accent AI-tell (accent is a desaturated steel-blue, not acid/neon).
- [x] Not the SaaS-card-kit — one radius per component *category* (input/badge/table/modal), not one radius for everything; shadows are barely-there, not the generic `rgba(0,0,0,.1)` soft-shadow-under-everything default.
- [x] No decorative eyebrows, no middot-joined meta strings, no em-dash-as-design-element anywhere in this document.
- [x] Every color has a stated reason tied to a real backend concept (evidence state / severity / posture / lifecycle) — none are decorative.
- [x] Accent is scarce (interactive-only), matching the Linear discipline this system borrows.
