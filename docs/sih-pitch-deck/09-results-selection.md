# 09 — Results selection

Every candidate metric, tested against: does this help a judge understand **effectiveness,
feasibility, robustness, differentiation, or scale**? Metrics that fail all five are omitted even
though they are true.

---

## SELECTED — these go on slides

| METRIC | VALUE | CORPUS | METHOD | WHY IT MATTERS | SLIDE | SAFE WORDING | LIMITATION |
|---|---|---|---|---|---|---|---|
| Automated tests | **1219**, 0 failures, 0 skips | whole system | `pytest`, run 3× independently | feasibility — separates a built system from a concept | 4 | "1219 automated tests, zero failures" | not a coverage percentage — coverage was never measured |
| Real-vendor captures validated | **10** | Postfix + Dovecot, SMTP/IMAP/POP3, 4 TLS modes | full pipeline per capture | robustness — real traffic, not toy data | 4 | "validated on 10 real Postfix and Dovecot captures" | loopback-generated, two vendors only |
| Standards cited | **11** (8 RFCs + 3 NIST SPs) | rule registry | enumerated from `ALL_RULES` | effectiveness — findings are grounded, not invented | 3, 6 | "every finding cites one of 11 published standards" | citation ≠ certification |
| Analysis latency | **115–320 ms** per capture | demo corpus | measured end-to-end, cold start included | feasibility — no waiting, works live | 4 | "sub-second analysis per capture" | small captures only; **never say "real-time"** |
| Repeat-run stability | **20/20** identical | 4 core scenes × 5 runs | repeated execution | robustness — deterministic, demo-safe | 4 | "20 of 20 repeated runs produced identical results" | same machine, same corpus |
| Rules | **16 + 3** cross-session | source | enumeration | effectiveness, scope | 3 | "16 standards-bound rules plus 3 cross-session rules" | several are compliance/abstention rules, not detections |
| ML bound | **4.0** vs **30**-point tier gap | source | arithmetic | differentiation — the AI boundary is structural, not a promise | 3 | "the ML signal is capped at 4.0 against a 30-point severity gap — it cannot cross a tier" | none; this is arithmetic |
| TLS 1.3 certificate visibility | **0 of 10** | real corpus | field extraction per capture | robustness/honesty — frames the hardest limitation as measured fact | 4 | "TLS 1.3 encrypts the certificate — 0 of our 10 real captures expose one" | none |
| Regression after certificate work | **10/10 identical** | real corpus | diff vs `v0.5.0-phase10` | robustness — new capability broke nothing | 4 (optional) | "adding certificate analysis changed no existing verdict" | none |

## SELECTED WITH MANDATORY LABEL

| METRIC | VALUE | REQUIRED LABEL |
|---|---|---|
| Weak-certificate detection | RSA-1024 + SHA-1 → 2× HIGH → posture **CRITICAL (44.0)** | must say **"generated TLS 1.2 fixture"** — the real corpus cannot exercise this |
| X.509 fields extracted | **38** distinct fields | same label |

## REJECTED — true but not slide-worthy

| METRIC | Why omitted |
|---|---|
| 16,107 lines of source / 84 modules | LOC is not a quality signal; invites "so what?" |
| 24 ADRs, 12 phases | engineering process, not evidence of outcome |
| 25-capture golden corpus | folds into the corpus story; extra number dilutes the 10-real-capture headline |
| 46 captures across ML corpora | only meaningful inside the ML discussion, which we deliberately keep small |
| 98.6% generator separability | crucial for *explaining* the ML result in Q&A, but on a slide it reads as a failure metric without its context |
| Dashboard endpoint latencies (0.89–30.95 ms) | too granular; the 115–320 ms end-to-end number already covers feasibility |
| 33 dashboard security-matrix tests, 15-payload hostile matrix | excellent engineering, invisible to a judge in six slides |
| Report byte-determinism / `report_sha256` | supports provenance in Q&A; too subtle for slide space |

## REJECTED — would be fabrication

| Claim | Status |
|---|---|
| "Reduces false positives by X%" | **never measured.** OQ-25 was never closed with a quantitative experiment. |
| ML accuracy / precision / recall / F1 | the measured result is **zero unique true detections**; any favourable figure would be invented |
| Throughput, captures/hour, max PCAP size | untested |
| Market size, ROI, cost savings, user counts | no verified source exists |
| "Detects N% of STARTTLS stripping attacks" | no such measurement; the capability is *disambiguation*, not detection-rate |

## The five numbers that actually matter

If space forces a cut to five: **1219 tests · 10 real captures · 11 standards · sub-second
analysis · 0 of 10 certificates visible under TLS 1.3.**

The last one is deliberately included as a *result*: it is the fact that most efficiently proves
we measured our own limits rather than assuming them.
