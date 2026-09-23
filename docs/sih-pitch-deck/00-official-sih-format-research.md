# 00 — Official SIH 2026 format research

**Method:** the official template was downloaded directly from the SIH portal and its slide XML
extracted programmatically. This is not a summary of a blog post about the format — it is the
format file itself, read.

---

## 1. Primary source

| | |
|---|---|
| **SOURCE** | Official Smart India Hackathon portal, Guidelines section → "Idea PPT" |
| **URL** | `https://sih.gov.in/letters/2026/SIH2026-IDEA-Presentation-Format.pptx` |
| **DATE ACCESSED** | 2026-09-23 |
| **METHOD** | downloaded (924,505 bytes), unzipped, slide XML parsed with `xml.etree` — all text extracted verbatim |
| **AUTHORITY** | **Tier 1** — the official government/AICTE template itself |
| **FILE CONTAINS** | 7 slides (6 content + 1 "Important Instructions" slide marked for deletion) |

## 2. The official structure, verbatim

Extracted text, exactly as it appears in the template:

| # | Official heading | Official "idea details pointers" (must not be changed) |
|---|---|---|
| **1** | `TITLE PAGE` | Problem Statement ID – · Problem Statement Title – · Theme – · PS Category – Software/Hardware · Team ID – · Team Name (Registered on portal) |
| **2** | `IDEA TITLE` | **Proposed Solution** (Describe your Idea/Solution/Prototype): Detailed explanation of the proposed solution · How it addresses the problem · Innovation and uniqueness of the solution |
| **3** | `TECHNICAL APPROACH` | Technologies to be used (e.g. programming languages, frameworks, hardware) · Methodology and process for implementation (Flow Charts/Images/working prototype) |
| **4** | `FEASIBILITY AND VIABILITY` | Analysis of the feasibility of the idea · Potential challenges and risks · Strategies for overcoming these challenges |
| **5** | `IMPACT AND BENEFITS` | Potential impact on the target audience · Benefits of the solution (social, economic, environmental, etc.) |
| **6** | `RESEARCH AND REFERENCES` | Details / Links of the reference and research work |
| ~~7~~ | ~~`IMPORTANT INSTRUCTIONS`~~ | *"You can delete this slide when you upload the details of your idea on SIH portal."* |

## 3. The official rules, verbatim

Quoted exactly from slide 7 of the official template:

> - *"Kindly keep the maximum slides limit up to six (6). (Including the title slide)"*
> - *"Try to avoid paragraphs and post your idea in points /diagrams / Infographics /pictures"*
> - *"Keep your explanation precise and easy to understand"*
> - *"Idea should be unique and novel."*
> - *"You can only use provided template for making the PPT **without changing the idea details pointers** (mentioned in previous slides)."*
> - *"You need to save the file in PDF and upload the same on portal. No PPT, Word Doc or any other format will be supported."*

## 4. IMPLICATIONS FOR OUR DECK — these change the design fundamentally

| Official requirement | Implication |
|---|---|
| Max 6 slides **including the title page** | We effectively have **five content slides**, not six. The title page is consumed by administrative metadata (PS ID, title, theme, category, team ID, team name) and carries no argument. |
| Headings are **fixed** (`IDEA TITLE`, `TECHNICAL APPROACH`, `FEASIBILITY AND VIABILITY`, `IMPACT AND BENEFITS`, `RESEARCH AND REFERENCES`) | **We cannot invent our own slide titles.** Any plan built around custom titles like "The Problem" or "Why We're Different" is invalid. Our content must be mapped *underneath* the official headings. |
| The **"idea details pointers" must not be changed** | The sub-bullets on each slide are prescribed. Our content must *answer* those specific pointers, not replace them. E.g. Slide 2 must explicitly address "Innovation and uniqueness of the solution" — that is a required field, not an optional flourish. |
| "Avoid paragraphs… points/diagrams/infographics/pictures" | Visual-first. Our densest assets (evidence-state model, cross-session flow, provenance chain) are **advantages** here — they are diagrams, not prose. |
| "Idea should be unique and novel" | This is an explicit official criterion, which makes our competitor source-audit evidence directly relevant — but it must stay evidence-backed (see `DO-NOT-CLAIM.md`). |
| PDF upload only | Final artifact is a PDF export. No animations, no transitions, no video embedded in the deck itself. |
| **There is no "Problem" slide** | Critically: the official template has **no dedicated problem-statement slide**. The problem context must be compressed into Slide 2's "How it addresses the problem" pointer. This is the single most common mistake teams make — burning a slide on a problem statement the template does not ask for. |

## 5. What is NOT officially published

| Item | Status |
|---|---|
| Jury scoring rubric / weightings | **NOT FOUND on sih.gov.in.** A weighting breakdown (problem understanding 20%, technical approach 25%, prototype 25%, impact 20%, presentation 10%) circulates on *institutional* portals, but it is **not an official AICTE/SIH publication** and is **not treated as authoritative here.** Recorded as unverified. |
| Font/size/colour requirements | Not specified in the template beyond using the provided template. |
| Whether diagrams may exceed the template's placeholder boxes | Not specified. |

**Conflict resolution:** no conflict was found between sources on the six-slide cap or the slide
headings — the secondary sources found via web search agree with the official template, and the
official template is used as authority for every statement in §2–§3 above.

## 6. Verification note

The 7-slide count in the downloaded file (6 + instructions) is consistent with the instruction
"maximum slides limit up to six (6), including the title slide" once the deletable instruction
slide is removed. No ambiguity remains about the intended final slide count: **six.**
