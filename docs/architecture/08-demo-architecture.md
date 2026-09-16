# 08 — Demo Architecture

**Status:** Draft for demo-reviewer. **Date:** 2026-09-16 · **Skill:** sih-readiness.

The demo must tell a defensible story to a technical NTRO evaluator, run fully offline from a
deterministic corpus, and show honesty (abstention, NOT_OBSERVABLE) as a feature — not hide it.

---

## 1. Narrative (Phase-11 §34)

```
Load PCAP (deterministic demo corpus, hash shown)
  → sessions reconstructed (SMTP + IMAP + POP3, incl. implicit TLS)
  → evidence extracted, each field with its state
  → deterministic security posture established (coverage-aware)
  → cross-session reasoning adds infrastructure context
  → ML flags anomalous session(s) as an independent signal
  → findings prioritised
  → evidence shown (down to frames)
  → remediation explained (standards-cited)
  → forensic report exported (JSON / PDF / HTML)
```

## 2. The three scenes that win or lose it

1. **The inversion scene.** Show a legitimate STARTTLS decline and a real stripping side by side. The
   naive per-session rule (what competitors ship) flags the benign one CRITICAL and misses the attack;
   our cross-session engine gets both right. *This is the differentiator, demonstrated, with numbers
   from 02A/02B.* Highest-value 90 seconds in the demo.
2. **The honesty scene.** Feed a TLS 1.3 / resumed / truncated capture. Show the tool output
   `NOT_OBSERVABLE` / `INCOMPLETE` and a coverage-aware posture ("assessed 13/18") instead of a
   confident wrong answer. An NTRO evaluator who probes "what about TLS 1.3?" gets a designed answer.
3. **The `--no-ai` scene.** Run the same capture with AI on and off; findings are identical; the AI
   only adds the query/explanation surface. Proves the AI is honest, not decorative (10B).

## 3. Live vs precomputed

- **Live:** ingest → analysis → report on a small demo capture (fast, reliable).
- **Precomputed fallback:** a saved analysis run (SQLite + rendered reports) for every demo capture, in
  case tshark/env misbehaves on the day. The demo can switch to the saved run without changing the story.
- **Never live internet traffic** (Phase-11 §34).

## 4. Catastrophic failure points & fallbacks

| Failure | Fallback |
|---|---|
| tshark missing/version-mismatch on demo machine | pinned bundled tshark; startup check; else precomputed run |
| Large-capture slowness | demo corpus is small & fixed; precomputed run ready |
| ML model load error | `--no-ai` path still produces the full security story |
| PDF renderer fails offline | JSON + HTML shown; PDF pre-rendered in the corpus |
| Dashboard JS error | reports (HTML/JSON) viewable directly |

## 5. Demo corpus

A frozen subset of the golden corpus (07 §3) chosen to exercise all three scenes: `A_legit_decline` +
`B_strip_advert` + `G_control_endpoint` (inversion), a TLS 1.3 + `E_incomplete` capture (honesty),
`C_normal_tls` (baseline), and one multi-session infrastructure capture (cross-session view). All
hashed, all offline, all with expected outputs in the manifest.

## 6. What the demo must NOT claim

Stripping universally detected · attacker attribution · anomaly score = attack proof · novelty in
detection. It **may** claim (with on-screen numbers): ~70% FP reduction vs per-session, control-endpoint
detection competitors miss, honest abstention, evidence-anchored forensic findings, all three mail
protocols incl. implicit TLS.
