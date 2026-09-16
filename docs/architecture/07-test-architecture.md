# 07 — Test Architecture

**Status:** Draft. **Date:** 2026-09-16 · **Skill:** testing-validation · **Agent:** test-engineer.

---

## 1. Layers

| Layer | Scope | Examples |
|---|---|---|
| **Unit** | pure logic | STARTTLS state transitions; evidence-state assignment; each rule; feature extraction; ML feature construction; report object serialisation |
| **Integration** | full pipeline | `PCAP → dissection → normalization → sessions → analysis → cross-session → ML → findings → report` on a fixed capture |
| **Regression** | never re-break validated results | **every OQ-25 / OQ-28 / OQ-33 scenario** (A_legit_decline, B_strip_advert, C_normal_tls, D_failed_upgrade, E_incomplete, F_shared_identity, G_control_endpoint, H_no_control, I_no_support, J_strip_command, K_network_cond, P_{imap,pop3}_*, S_striptls_real, X_prompt_injection) |
| **Adversarial** | try to break it | malformed/truncated/reordered/retransmit/missing-packet; ambiguous & contradictory evidence; injection text; oversized capture |
| **ML** | methodology guards | leakage (generator-held-out), seed reproducibility (≥5 seeds identical), feature stability, model persistence round-trip, inference reproducibility |

## 2. Invariants asserted by tests (the correctness contract)

- No forbidden evidence-state conversion ever occurs (04 §2) — assert on wrapper access patterns.
- Truncated/incomplete captures never produce a SUSPECT/insecure finding (02B §5).
- ML output never changes a finding: **`--no-ai` run and full run produce identical findings** (10B
  §5 invariant 4) — a diff test, and a demo asset.
- Same PCAP + same versions ⇒ identical output hash (04 §4; already true in 02B).
- Every finding references ≥1 frame and carries an evidence state.

## 3. Golden corpus (Phase-11 §26)

Manifest (`tests/golden/manifest.json`) — one row per PCAP:
`{ pcap, sha256, scenario_id, protocol, expected_evidence, expected_states, expected_findings,
expected_anomaly_behaviour, provenance }`. The OQ-28 `ground_truth.json` is the seed manifest.

**Rule:** never silently modify a golden PCAP. A change requires a **new hash + version + documented
reason**. A test asserts stored hashes match on load.

## 4. Test-run discipline (token-efficiency)

Targeted unit test → relevant integration test → **full regression only at milestones or before a
demo**, not after every edit. ML bake-off is a separate, explicitly-invoked suite (expensive).

## 5. Coverage targets (pragmatic, not vanity)

Cover every rule, every evidence-state branch, every STARTTLS deviation (§7.2 of 01B), and every
regression scenario. No line-coverage percentage target — behaviour coverage over line coverage.
