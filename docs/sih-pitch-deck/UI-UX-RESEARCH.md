# UI/UX research — analyst console redesign

Design research conducted 2026-09-23 for the SecureMailScope dashboard redesign. **This research
informs design principles only.** No proprietary UI asset is copied, and no claim is made that
SecureMailScope compares to any product named here.

---

## 1. Products and sources inspected

**Product categories studied** (public documentation, screenshots, published design systems):
posture-management consoles (Vanta, Wiz), developer-security tools (Snyk, GitHub security tab),
SOC/EDR consoles (Microsoft Defender, CrowdStrike Falcon, Elastic Security), observability
(Grafana, Datadog), and infrastructure security (Cloudflare).

**Published design-system sources:** IBM Carbon (empty-state pattern), Nielsen Norman Group
(empty states in complex applications), Smart Interface Design Patterns (drag-and-drop),
practitioner guidance on cybersecurity dashboard hierarchy and trust.

## 2. Patterns worth adopting

| Pattern | Source of the idea | Why it fits SecureMailScope |
|---|---|---|
| **Hierarchy follows operational priority, not data availability** | cybersecurity dashboard practice | our projection returns 16 sections; the UI must rank them by what an analyst acts on, not render all equally |
| **The finding disclosure chain**: what → severity → impact → affected asset → evidence → action → status | posture-tool practice | maps almost exactly onto our finding model (`severity` → `conclusion` → `protocol`/`stream_key` → `frames` → `remediation` → `status`) |
| **Colour is a signal system, not decoration** — red only where action is required | cybersecurity UX guidance | critical for us: `NOT_OBSERVABLE` must **never** be red, because it is not a failure |
| **Severity encoded redundantly** (colour + icon + text) | accessibility guidance | we already have `severity_marker` and `severity_label` in the projection — currently underused |
| **Empty state as onboarding**, with the primary action front and centre | Carbon, NN/g, UserOnboard | directly fixes the current "here is a curl command" dead end |
| **Positive empty-state copy** ("Start by analysing a capture", not "You have no analyses") | Carbon | the current copy is written as an absence |
| **Drop zone: always pair drag with click**, generous target, explicit drag-over state, dashed boundary | Smart Interface Design Patterns, SaaSUI | we have no upload UI at all today |
| **Confirm what was received** after drop (name, size, type) | Dropbox pattern via research | reduces "did that work?" during a live demo |
| **Progressive disclosure on findings** — scan first, expand for evidence | posture tools | a judge must scan; an analyst must drill |
| **Distinguish empty-because-first-use from empty-because-filtered from empty-because-error** | NN/g | we have six distinct failure modes already; the UI should keep them distinct |
| **Alert fatigue is a design failure** — group, rank, and damp | SOC practice | our engine already groups by `issue_class` and ranks by priority; the UI should show the grouping, not a flat list |
| **App chrome (persistent shell) rather than document flow** | all inspected consoles | the current console reads like a paper, not an application |

## 3. Patterns explicitly rejected

| Rejected | Why |
|---|---|
| Dark "SOC war-room" theme, neon accents, glow | the brief forbids it, and it signals "student project" rather than "forensic tool" |
| Large donut/gauge charts for posture | a gauge implies a continuous measurement; our score is a damped penalty with a **coverage gate** — a gauge would hide the gate |
| Threat-map / globe visualisations | we have no geographic data and never will; pure decoration |
| "AI insights" panel with prominent placement | contradicts our own architecture and `DO-NOT-CLAIM.md` — the ML lane has no demonstrated detection value |
| Risk trend lines over time | we have no longitudinal data; a trend line would be fabricated |
| Density-maximising SOC table grids (Splunk-style) | our value is *interpretation*, not log volume; a dense grid buries the reasoning |
| Skeleton loaders everywhere | analysis completes in ~140 ms; a skeleton would flash and look broken |
| Multi-level sidebar navigation | we have exactly four screens; a sidebar tree would be cognitive overhead for no gain |
| Toast notifications for everything | the result *is* the confirmation; toasts add noise |

## 4. Resulting design principles for SecureMailScope

1. **The primary action is always visible.** On an empty console that means the drop zone; on a
   completed analysis it means posture first, then report export.
2. **Uncertainty is a first-class visual citizen, not an error.** `NOT_OBSERVABLE` gets a neutral,
   deliberate treatment — never red, never a warning icon. This is the product's differentiator and
   the UI must look like it believes that.
3. **Colour only where action is implied.** Severity colours for `OBSERVED_ISSUE` findings only.
   Evidence states use neutral tones with textual labels.
4. **Redundant encoding, always.** Every severity and state carries a word; colour is never the
   only signal. (The projection already supplies `*_label` and `severity_marker`.)
5. **Scan, then drill.** Findings list is scannable in seconds; evidence, frames, citations and
   limitations live behind disclosure.
6. **Never render API text as markup.** All PCAP-derived strings stay `textContent`. This is
   existing discipline and is preserved without exception.
7. **Honest progress.** Analysis is synchronous (~140 ms measured); show a determinate-feeling
   working state and the *real* stage list on completion — never a fake percentage.
8. **Offline-only assets.** No web fonts, no CDN, no icon service. Inline SVG and system font stack.
9. **Light, quiet, precise.** Off-white surfaces, one accent, restrained borders, generous
   whitespace, strong typographic hierarchy.
10. **Fewer, better components.** Ten useful components beat fifty decorative ones.

## 5. The one product-specific pattern research did *not* supply

None of the inspected products has our core problem: **presenting a conclusion alongside an
explicit statement of what could not be concluded.** Posture tools show pass/fail; SOC tools show
alert/no-alert. We must show a third thing — *"this is genuinely unknowable from the evidence, and
here is why"* — without it reading as a failure or a gap.

**Our answer** (developed for this redesign, not borrowed): evidence states get a dedicated,
neutral visual language — a bordered chip with a word, never a coloured severity pill — and
abstentions are presented as *findings about the evidence*, each paired with its
`resolved_by` text ("what would settle this"). That turns a limitation into a piece of analysis,
which is exactly what it is.
