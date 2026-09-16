# 02A — OQ-25 Experiment: Does Cross-Session Baselining Reduce False Positives?

**Hypothesis under test:** *Cross-session reasoning can distinguish malicious STARTTLS
stripping/downgrade from legitimate behaviour that produces the same per-session observable state.*
**Status:** Executed · **Date:** 2026-09-16
**Code:** `research/experiments/oq25/` — deterministic, seeded, no ML.

---

## 1. Verdict

> ## 🟡 **RESULT B — PARTIALLY VERIFIED**
>
> Cross-session reasoning produces a **large, real, measurable improvement** — but it is **two
> separate mechanisms that trade against each other**, and it **fails completely** against the most
> important adversary.

| Detector | False positives | False negatives |
|---|---|---|
| **D1 per-session** (competitor-style) | **120** | **70** |
| **D2 consistency rule only** | **35** (**−71%**) | 70 (unchanged) |
| **D2 + server-contrast rule** | 75 (−38%) | **35** (**−50%**) |

Aggregate over 9 scenarios, 260 sessions. **You can cut false positives by 71% at no recall cost, or
halve false negatives at a smaller FP gain — not both.** No configuration achieved both.

**The thesis survives, but must be restated.** It cannot be "cross-session reasoning distinguishes
attacks from configuration." It can be: *"cross-session reasoning eliminates the dominant false-positive
class, abstains honestly when history is thin, and — when a control endpoint exists — detects a
stripping attack that per-session analysis cannot see at all."*

---

## 2. Method

### 2.1 Scope limitation, stated up front

This is a **session-model experiment, not a packet-level one.** The corpus generator emits the
*observable feature vector* a passive PCAP parser would recover from the cleartext phase, rather
than synthesising real PCAPs. That is appropriate because OQ-25 is a question about **reasoning over
session observations**, not about parsing — but it means:

- ❌ It does **not** validate any parser.
- ❌ It cannot surface packet-level effects (segmentation, pipelining, retransmission, multiple
  STARTTLS attempts in one stream).
- ❌ Absolute rates depend on scenario composition, which I chose. **Ratios between D1 and D2 on the
  *same* corpus are the meaningful output; the absolute numbers are not population estimates.**

Packet-level validation remains the separate 01B §10 experiment using `striptls`.

### 2.2 Ground truth separation

Seven hidden ground-truth classes map to observables. Ground truth is stored in a separate dict,
never exposed to a detector, and used only for scoring. No key logs. No labels as features.

| Ground truth | advertised | cmd | response | TLS | plaintext |
|---|---|---|---|---|---|
| `LEGIT_TLS` | ✅ | ✅ | 220/+OK/OK | ✅ | — |
| `LEGIT_DECLINE` | ✅ | ❌ | — | ❌ | ✅ |
| `LEGIT_PLAINTEXT_CFG` | ❌ | ❌ | — | ❌ | ✅ |
| `ATTACK_STRIP_ADVERT` | ❌ | ❌ | — | ❌ | ✅ |
| `ATTACK_STRIP_COMMAND` | ✅ | ✅ | 454/-ERR/NO | ❌ | ✅ |
| `FAILED_UPGRADE` | ✅ | ✅ | 220/+OK/OK | ❌ | — |
| `INCOMPLETE_CAPTURE` | ✅ | — | — | ❌ | — |

🔴 **The crux, visible in this table:** `ATTACK_STRIP_ADVERT` and `LEGIT_PLAINTEXT_CFG` are
**observationally identical at the single-session level.** No per-session detector can separate
them — not ours, not any competitor's. This is an epistemic limit, not an engineering gap.

### 2.3 Detectors

**D1 — per-session.** Faithful to CipherPost's shipped rule, deliberately *not* weakened:

```python
if o.starttls_advertised and not o.tls_handshake_observed:
    return SUSPECT
```

**D2 — cross-session.** Deterministic aggregation over a key, with documented transitions:

| Rule | Condition | Verdict |
|---|---|---|
| R1 | truncated | `UNKNOWN` |
| R2 | TLS observed | `BENIGN` |
| R3 | usable sessions < `min_history` | `INSUFFICIENT_HISTORY` — *explicitly not an accusation* |
| R4 | **consistency:** key never upgrades in any session | `BENIGN` — configuration |
| R5 | **deviation:** key sometimes upgrades, this session does not | `SUSPECT` |
| R6 | **server-contrast:** server upgrades for *other* clients but never this one | `SUSPECT` |

No scores. No ML (Part 17 respected).

---

## 3. Results by scenario

| Scenario | D1 FP/FN | D2 consistency | D2 + contrast |
|---|---|---|---|
| **A** legitimate decline ×25 | **25 / 0** | **0 / 0** ✅ | 0 / 0 ✅ |
| **B** intentional plaintext config | 0 / 0 | 0 / 0 | 0 / 0 |
| **C** 25 healthy + 5 stripped-command | 0 / 0 | 0 / 0 | 0 / 0 |
| **D** realistic mix | 15 / 5 | 15 / 5 | 15 / **0** ✅ |
| **E** two legitimate client types | **20 / 0** | **0 / 0** ✅ | **20 / 0** ❌ |
| **11J** 100% stripping, no control | 0 / **30** | 0 / **30** ❌ | 0 / **30** ❌ |
| **11J′** 100% stripping + control client | 0 / **30** | 0 / **30** | **30 TP / 0 FN** ✅ |
| **11D** five legitimate client types | **20 / 0** | **0 / 0** ✅ | **20 / 0** ❌ |
| **11H** NAT shared identity | **20 / 0** | **20 / 0** ❌ | **20 / 0** ❌ |
| **11I** attack hidden in plaintext baseline | 20 / 5 | **0 / 5** ✅ | **0 / 5** ✅ |
| **TOTAL** | **120 / 70** | **35 / 70** | **75 / 35** |

### 3.1 🔴 The headline finding: the per-session detector is *inverted*

Two rows tell the whole story:

- **Scenario A:** D1 raises a **CRITICAL finding on 25 of 25 benign sessions.** 100% false positive.
- **11J:** D1 **misses 30 of 30 genuine attack sessions.** 100% false negative.

**The competitor-style rule fires on the legitimate case and is blind to the actual
capability-stripping attack.** The reason is structural: `ATTACK_STRIP_ADVERT` removes the
advertisement, so `saw_starttls_offer` is false and the rule never triggers — while
`LEGIT_DECLINE` keeps the advertisement and triggers it every time.

This is not a tuning problem. It is what that rule *does*, and it applies to CipherPost's shipped
`rule_starttls_strip` as written.

---

## 4. Part 5 — which baseline key works?

On Scenario D, all keys performed **identically** (`global`, `server`, `client`, `pair`,
`pair+proto`, `server+proto`): P=0.40, R=1.00 with contrast; P=0.25, R=0.50 without.

**The key choice did not matter. The *rule set* did.** With contrast enabled, `client`, `pair` and
`pair+proto` jumped from R=0.50 to R=1.00; without it they stayed at 0.50. `global`, `server` and
`server+proto` reached R=1.00 either way, because a server-scoped key already contains the
cross-client contrast implicitly.

**Conclusion:** the useful dimension is **whether the key spans multiple clients of the same
server**. `pair+proto` + explicit contrast, and `server+proto` alone, are equivalent. ⚠️ This
finding is corpus-dependent and should not be over-read — my scenarios may simply not discriminate
between keys.

---

## 5. Part 10 — how much history is needed?

| Sessions | D1 FP | D2 FP | D2 abstentions |
|---|---|---|---|
| 1 | 1 | 0 | 1 — abstains |
| 2 | 2 | 0 | 2 — abstains |
| 3 | 3 | 0 | 3 — abstains |
| **5** | 5 | **0** | **0 — baseline usable** |
| 10 | 10 | 0 | 0 |
| 25 | 25 | 0 | 0 |
| 50 | 50 | 0 | 0 |

**Clean result: the threshold is ~5 sessions per key.** Below it the detector abstains with
`INSUFFICIENT_HISTORY` rather than guessing — which is itself a correctness win over D1, whose
false-positive count grows linearly with capture size.

⚠️ `min_history=5` was a chosen parameter, not a derived one. The sweep shows behaviour is a step
function at the threshold, so the *value* is a tunable, not a discovery.

---

## 6. Part 14 — time-aware baselines

| Case | D1 | D2 capture-wide | D3 time-aware |
|---|---|---|---|
| Client always used TLS → **stops on day 2 (attack)** → resumes day 3 | FN=10 ❌ | **TP=10, FP=0** ✅ | **TP=10, FP=0** ✅ |
| Client was plaintext (day 1) → **legitimately upgrades** (day 2). 0 attacks | FP=20 ❌ | **FP=20** ❌ | **FP=0** ✅ (abstains on day 1) |

**Time-aware baselining is strictly better than capture-wide in these tests.** It matches
capture-wide on attack detection and eliminates the false positives from legitimate configuration
change (adversarial case 11A) by comparing only against *prior* history instead of pooling the whole
capture.

**Recommendation: prefer prior-history baselines over capture-wide pooling.** ⚠️ Two tests only;
needs broader validation.

---

## 7. Part 12 — does the "infrastructure" framing survive?

**Yes.** On Scenario D the two framings produce qualitatively different output:

```
SESSION-LEVEL  : "STARTTLS advertised, no TLS handshake observed."   ×20 identical lines

INFRASTRUCTURE :
    c1 -> s1 smtp   40/50 sessions upgraded  (80%)
    c2 -> s1 smtp   10/20 sessions upgraded  (50%)
    c3 -> s1 smtp    0/5  sessions upgraded  (0%)     <-- the outlier, immediately visible
    c4 -> s1 smtp   10/10 sessions upgraded  (100%)
```

The session view produces twenty indistinguishable findings an analyst must triage by hand. The
infrastructure view localises the problem to one endpoint on sight. **This is genuinely different
information, not a reformatting.** The terminology is justified.

---

## 8. Part 13 — per-protocol

SMTP, IMAP and POP3 produced **identical** results (D1 FP=20, D2 FP=0 each), and `pair` vs
`pair+proto` made no difference on a mixed-protocol attack corpus (both P=1.00, R=1.00).

⚠️ **This is a non-result, not a finding.** The logic is protocol-independent by construction and my
generator models no protocol-specific behavioural differences. **The experiment cannot show
differences it did not model.** Real protocol differences — IMAP's persistent polling connections,
POP3's short sessions, SMTP's MTA-to-MTA vs submission split — would change session counts per key
and therefore how quickly `min_history` is reached. **Untested. Requires the packet-level corpus.**

---

## 9. Falsification attempts

| # | Attack on the hypothesis | Result |
|---|---|---|
| 1 | **Stripping happens on 100% of sessions** | 🔴 **METHOD FAILS COMPLETELY.** FN=30/30 for both D1 and D2. With no session ever upgrading, "consistent plaintext" is indistinguishable from "consistently attacked". **Unresolved and unresolvable from capture alone.** |
| 2 | **Same, but a control client exists** | ✅ **Method wins decisively.** FN 30 → 0, TP 0 → 30. The contrast rule detects an attack D1 cannot see at all. **The single strongest result in this experiment.** |
| 3 | **Legitimate behaviour changes mid-capture** (11A) | ❌ Capture-wide FP=20. ✅ **Fixed by time-aware baselining** (§6). |
| 4 | **Too few sessions** | ✅ Handled — abstains below 5 (§5). |
| 5 | **Client identity unreliable / NAT** (11H) | 🔴 **METHOD FAILS.** FP=20, no improvement over D1. Two populations collapsed into one identity produce a permanently `MIXED` baseline. **Unresolved.** |
| 6 | **Multiple legitimate client types** (11D, E) | 🔴 **The contrast rule actively hurts:** FP 0 → 20. Heterogeneous-but-legitimate client populations are flagged as attacks. **This is the precision/recall tradeoff made concrete.** |
| 7 | **Incomplete PCAP** (11F) | ✅ Correctly abstains (20 `UNKNOWN`). |
| 8 | **Baseline poisoning / attacker hides inside an existing plaintext baseline** (11I) | 🟡 **Split.** FP 20 → 0 ✅, but FN=5 for both ❌. The attack is *concealed* by the very baseline that removes the false positives. **Inherent to the approach.** |
| 9 | **Attacker deliberately mimics the baseline** | Same as #8 — succeeds against the method. |
| 10 | **Does cross-session create more FPs than it removes?** | ✅ No for the consistency rule (120 → 35). 🔴 **Yes, locally, for the contrast rule** — it adds 40 FPs across cases E and 11D while removing 35 FNs. |

**Two unresolved failure modes: total stripping with no control (#1), and identity collapse (#5).**
Both must be stated as limitations in any submission, not hidden.

---

## 10. Answers to the 12 required questions

1. **Does it reduce false positives?** ✅ Yes — substantially, via the consistency rule.
2. **By how much?** **−71%** (120 → 35) with no recall loss. The contrast variant gives −38% FP with
   −50% FN.
3. **In which scenarios?** Legitimate decline (25→0), heterogeneous client types (20→0), attack
   hidden in a plaintext baseline (20→0), and all three protocols identically.
4. **Where does it fail?** 100% stripping with no control endpoint; NAT/shared identity; and the
   contrast rule on legitimately heterogeneous client populations.
5. **Best key?** Any key that spans multiple clients of one server — `server+proto`, or
   `pair+proto` with an explicit contrast rule. **Key choice mattered far less than rule choice.**
6. **History needed?** ~**5 sessions** per key; below that, abstain.
7. **Infrastructure framing?** ✅ **Survives** — demonstrably different information (§7).
8. **Protocol differences?** **Untested** — not modelled. Non-result.
9. **Strongest counterexample?** Attacker strips every session with no unaffected control endpoint.
   Total failure, and it is the realistic scenario for a targeted single-client attack.
10. **Verdict?** 🟡 **PARTIALLY VERIFIED (RESULT B).**
11. **Thesis changes required?** §11.
12. **Next?** §12.

---

## 11. Required changes to the product thesis

The 01D §12 thesis claimed cross-session reasoning *"distinguishes an attack from a configuration
choice."* **The experiment does not support that as stated** — in the total-stripping case it
cannot, and the mechanism that best suppresses false positives (consistency) is precisely the one an
attacker exploits to hide (#8).

**Revised, defensible thesis:**

> **SecureMailScope reasons across every session in a capture rather than judging each in isolation.
> This eliminates the dominant false-positive class in STARTTLS analysis, abstains explicitly when
> there is too little history to judge, and — where an unaffected control endpoint exists — surfaces
> downgrade attacks that per-session analysis cannot detect at all. Where the evidence cannot
> decide, it says so.**

Every clause is now backed by a number in §3. The last clause is not a hedge — `INSUFFICIENT_HISTORY`
and `UNKNOWN` are measured outputs, and abstention is what keeps D2's false-positive count from
growing with capture size.

**Two claims we must never make:** that this detects stripping in general (it does not — #1), and
that it identifies attackers (it identifies *deviation*, which is not the same thing).

---

## 12. Next research actions

| # | Action | Why |
|---|---|---|
| 1 | **Run the packet-level version** (01B §10 corpus via `striptls`) | §2.1 — this experiment validates reasoning, not parsing. The reasoning result must be confirmed on real captures |
| 2 | **Adopt time-aware baselines**, not capture-wide pooling | §6 — strictly better in both tests |
| 3 | **Decide the contrast-rule default** | §9 #6 — it is a precision/recall policy choice. Provisional: **default OFF, enable when a control endpoint is present**, and report which mode produced each finding |
| 4 | **Design an identity model robust to NAT** (ports, TLS fingerprints, banners as client identity) | §9 #5 — the unresolved failure |
| 5 | **Test protocol-specific session dynamics** | §8 — currently a non-result |
| 6 | Re-test OQ-27 (does unsupervised outlier detection add anything *on top of* this?) | 10A — only now meaningful, since the deterministic baseline is established |

⚠️ **Do not run OQ-27 or any ML work before action 1.** The deterministic result is the foundation;
adding ML before validating it at packet level would repeat exactly the mistake found in every
competitor (01D §6).
