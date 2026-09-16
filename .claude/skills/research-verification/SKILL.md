---
name: research-verification
description: Verify factual/source claims with primary-source discipline. Trigger when adding any claim to docs/, citing a standard/tool/competitor, or when a statement asserts what a source "requires" or "does".
---
# research-verification

Every non-trivial claim carries a label: **FACT** (primary source in SOURCES.md), **INFERENCE**
(named FACTs it derives from), **ASSUMPTION** (falsifiable, tracked in RESEARCH_STATUS.md),
**OPEN QUESTION** (owner: research/team/SPOC). An unlabelled claim is a defect.

Rules:
- Prefer primary sources: RFC/NIST/official portal > agency > peer-reviewed > vendor docs > analysis.
- Competitor repos are *interpretations*, never requirements. READMEs are marketing; only source counts.
- Never silently promote ASSUMPTION → FACT. Promotion needs a SOURCES.md entry + changelog line.
- Distinguish "I found no public evidence" from "I verified X does not exist." The second is rarely supportable.
- Quote exact wording for standards/PS text. Never fabricate a citation, statistic, or novelty claim.
