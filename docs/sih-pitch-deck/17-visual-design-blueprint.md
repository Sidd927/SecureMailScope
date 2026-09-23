# 17 — Visual design blueprint

Layout per slide. The official instruction is explicit: *"avoid paragraphs… post your idea in
points / diagrams / infographics / pictures."* Text is the fallback, not the default.

**Global rules:** max ~40 words of body text per slide · max 5 bullets · no paragraph longer than
two lines · every number large enough to read at a glance · consistent colour meaning throughout
(one colour for "observed/verified", one for "not observable/limitation" — never red-for-bad on
limitations, they are *features*).

---

## SLIDE 1 — TITLE PAGE

| Zone | Content |
|---|---|
| TOP | SIH 2026 branding (template default) |
| CENTER | **SecureMailScope** + one-line descriptor |
| BODY | the six required fields, as a clean two-column block |
| BOTTOM | team name |

**Read first:** project name. **Read second:** PS ID. **Omit:** everything else.

---

## SLIDE 2 — IDEA TITLE (the differentiator slide)

```
┌──────────────────────────────────────────────────────────┐
│ HEADLINE: Reasoning across sessions, not just parsing    │
│           packets                                         │
├────────────────────────────┬─────────────────────────────┤
│ LEFT (40%)                 │ RIGHT (60%) — THE VISUAL    │
│ • what it is (2 lines)     │                             │
│ • the problem (2 lines)    │  Session A ✗ ✗ ✗ ✗ ✗        │
│ • uniqueness (2 lines)     │  Others   ✓ ✓ ✓ ✓ ✓ ✓       │
│                            │       ↓ same server          │
│                            │  "deviates from comparable   │
│                            │   endpoints" (evidenced)     │
└────────────────────────────┴─────────────────────────────┘
│ FOOTER: source audit — 0 of 5 competing implementations   │
│         perform cross-session reasoning                   │
└──────────────────────────────────────────────────────────┘
```

**Read first:** the headline. **Read second:** the ✗/✓ contrast — it communicates the entire idea
pre-verbally. **Omit:** pipeline, metrics, AI.

---

## SLIDE 3 — TECHNICAL APPROACH

```
┌──────────────────────────────────────────────────────────┐
│ TOP: pipeline flow (full width, single row, 9 boxes)     │
│  PCAP → dissect → sessions → 16 rules → cross-session     │
│       → fusion → posture → reports → dashboard            │
│                         ↑                                 │
│              ML lane ──┘ (ranking only, capped 4.0)      │
├───────────────────┬──────────────────────────────────────┤
│ LEFT: technologies│ RIGHT: six evidence states (strip)   │
│ Python 3.9+       │ OBSERVED · INFERRED · UNKNOWN        │
│ TShark (required) │ AMBIGUOUS · INCOMPLETE ·             │
│                   │ NOT_OBSERVABLE                       │
│ FastAPI · SQLite  │ ─────────────────────────────────    │
│ 0 3p Py packages  │ "Missing evidence can never          │
│                   │  improve a score."                   │
├───────────────────┴──────────────────────────────────────┤
│ FOOTER STRIP: PCAP SHA-256 → frame → stream → finding    │
│               → cited standard → report                   │
└──────────────────────────────────────────────────────────┘
```

**Read first:** the pipeline. **Read second:** the blocked ML arrow. **Read third:** the evidence
strip. **Omit:** formula names, ADR numbers, code.

---

## SLIDE 4 — FEASIBILITY AND VIABILITY

```
┌──────────────────────────────────────────────────────────┐
│ TOP: results strip — five large numbers, evenly spaced    │
│  1219        10          11          <1s        0 of 10  │
│  tests    real captures standards   analysis  certs under │
│                                                TLS 1.3   │
├──────────────────────────────────────────────────────────┤
│ CENTER: risks & strategies — 3-row table                 │
│  RISK                    │ STRATEGY                       │
│  TLS 1.3 hides certs     │ report NOT_OBSERVABLE + reason │
│  Trust needs an anchor   │ validate structure; state limit│
│  ML: no detection value  │ bounded prioritisation only    │
├──────────────────────────────────────────────────────────┤
│ BOTTOM: runs without network access · passive ·           │
│         0 third-party Python packages (TShark required)   │
└──────────────────────────────────────────────────────────┘
```

**Read first:** the five numbers. **Read second:** the risk table. **Omit:** apologies, hedging
language, scalability.

**Design note:** style the risk table neutrally (not red/warning). These are *engineering
statements*, and the visual tone should say "we measured this", not "we're sorry".

---

## SLIDE 5 — IMPACT AND BENEFITS

```
┌──────────────────────────────────────────────────────────┐
│ TOP: WHO — 4 user icons + labels                          │
│  SOC analyst · DFIR investigator · IR team · mail admin   │
├───────────────────────┬──────────────────────────────────┤
│ LEFT: before/after    │ RIGHT: report or dashboard        │
│  Before: read PCAP by │ SCREENSHOT                        │
│  hand, or trust an    │ (posture + coverage + a finding   │
│  unexplained verdict  │  with its cited standard visible) │
│  After: cited posture │                                   │
│  in under a second    │                                   │
├───────────────────────┴──────────────────────────────────┤
│ BOTTOM: no server access · no keys · no internet ·        │
│         no message content read                           │
└──────────────────────────────────────────────────────────┘
```

**Read first:** the four user types. **Read second:** the screenshot. **Omit:** market figures,
ROI, anything quantitative about adoption.

---

## SLIDE 6 — RESEARCH AND REFERENCES

```
┌──────────────────────────────────────────────────────────┐
│ LEFT COLUMN: Standards          RIGHT COLUMN: Research    │
│ RFC 8446 · 8996 · 3207 · 2595   Authoritative PS record   │
│ RFC 8314 · 5280 · 6960 · 9155   TLS passive-visibility    │
│ NIST SP 800-52r2                STARTTLS prior-art review │
│ NIST SP 800-57 Pt.1 Rev.5       Competing-implementation  │
│ NIST SP 800-131A Rev.2            source audit            │
│                                 ML evaluation (held-out)  │
└──────────────────────────────────────────────────────────┘
```

**Read first:** that there *are* real standards. **Omit:** URLs long enough to wrap, blogs,
vendor pages.

---

## Assets that must be produced

| Asset | Status | Needed for |
|---|---|---|
| Pipeline flow diagram | **to create** | Slide 3 (primary) |
| Cross-session ✗/✓ visual | **to create** | Slide 2 (primary) |
| Six-evidence-state strip | **to create** | Slide 3 |
| Dashboard screenshot | **to capture** — none exists yet (`demo/screenshots/` is empty) | Slide 5 |
| Results number strip | **to create** | Slide 4 |

The dashboard screenshot is the only asset requiring a running system; everything else is
diagram work. See `PPT-TEAM-CONTENT-BANK.md` for exact labels.
