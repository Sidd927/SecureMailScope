# Phase 11 — 04. A-02 re-assessment

**Requirement (verbatim PS):** *"AI-assisted anomaly detection for suspicious TLS sessions."*
**Prior status:** PARTIAL — ADR-0015, Outcome D
**Measurement:** `research/experiments/p11ai/measure_features.py` →
`results/feature_variance.json` · 46 captures · tshark 4.6.8
**Decision rule:** fixed in `03-scope-lock.md` §E-i **before** this evaluation ran.

---

## 1. The question

ADR-0015 closed OQ-37 **negative**: zero unique true detections on all three held-out splits.
It left OQ-45 open — *would different data change the answer?*

Phase 11 creates a genuinely new opportunity: for the first time, key-exchange mechanism,
forward secrecy, certificate validity, public-key algorithm/length and signature algorithm
become available as features. The honest question is whether **these specific new features**
carry detection value the deterministic rules do not already have.

This is asked properly, and the answer may be no.

---

## 2. The pre-committed decision rule

> A-02 moves from PARTIAL only if new features produce **unique true detections on a held-out
> split that the deterministic rules do not already produce**. Anything less — improved
> scores, better separation, nicer clustering — leaves A-02 **PARTIAL**.

Recorded before measurement so that the result could not be rationalised afterwards.

---

## 3. Measurement — do the new features carry any information at all?

A feature that takes the **same value in every session** carries zero information. It cannot
change a ranking, a score, or a detection, regardless of which model consumes it. That is
checkable without training anything, so it was checked first.

All 46 captures available to this project were measured: the 10 real OQ-33r captures, the 17
genB and 18 genC ML-corpus captures, and the 1 synthetic TLS 1.2 capture from doc 02.

### 3.1 Forward secrecy (D-17) — constant

| Value | Captures |
|---|---:|
| `True` (forward secret) | **31** |
| `None` (no TLS session at all — cleartext capture) | 15 |
| `False` (**not** forward secret) | **0** |

**FACT:** across every capture this project possesses, there is **not one** non-forward-secret
session. The feature is constant wherever it is defined.

**INFERENCE:** a constant feature has zero variance and therefore zero discriminative
information. `robust-z` of a constant is undefined-or-zero by construction. D-17 cannot
contribute to anomaly detection on any corpus that exists.

### 3.2 Certificate features (D-10, D-12, D-13, D-14) — undefined almost everywhere

| Corpus | Captures | With X.509 data |
|---|---:|---:|
| real (OQ-33r) | 10 | **0** — all TLS 1.3, certificate encrypted (RFC 8446 §2) |
| genB | 17 | **0** — generator writes no `Certificate` message |
| genC | 18 | **0** — same |
| synthetic TLS 1.2 (doc 02) | 1 | **1** |
| **total** | **46** | **1** |

**FACT:** certificate evidence exists in **1 of 46** captures — the single capture synthesised
this phase specifically to prove extraction works.

**INFERENCE:** a feature present in one sample cannot be evaluated. Training or thresholding
on it would be fitting to a single point that I authored myself.

### 3.3 Key exchange (D-09) — present, but it encodes generator identity

| Corpus | Selected suites observed |
|---|---|
| genB | `0x1302` (×11), `0xc030` (×1) |
| genC | `0x1301` (×1), `0xc02f` (×12) |
| real | `0x1302` (×5) |
| synthetic TLS 1.2 | `0xc030` (×1) |

**FACT:** genB and genC use **disjoint** suite sets. Source confirms this is structural, not
incidental — `genb.py:67` selects `0x1302`/`0xc030` and `genc.py:59` selects `0x1301`/`0xc02f`,
each as a hard-coded function of the TLS version.

**This is the decisive result.** ADR-0015 identified the project's central ML failure mode:
the feature space leaks generator identity at **98.6 %** accuracy, and the best-scoring
candidate flagged **86.8 %** of an independently authored corpus. A suite-derived
key-exchange feature separates genB from genC **perfectly** on every TLS-bearing capture.

**INFERENCE:** adding it would not add detection value — it would **worsen the known failure
mode**, and any apparent gain in a bake-off would be the model learning which generator wrote
the file. That is the exact artefact ADR-0015 exists to prevent.

---

## 4. Why no bake-off was run

Running a bake-off requires features with variance. §3 measured that the three new feature
families are, respectively: constant (D-17), absent from 45 of 46 captures (D-10/12/13/14),
and a generator fingerprint (D-09).

**DESIGN DECISION.** Training on this would have produced a number, and the number would have
been meaningless — or worse, favourable for the wrong reason. Fabricating a positive result by
feeding a model its own generator's signature is precisely the failure the Phase-11 brief
forbids. The measurement in §3 is the stronger and more honest evidence, and it is
reproducible in seconds.

**LIMITATION — stated plainly:** this is an *absence-of-evidence* argument about the corpora
that exist. It does **not** prove that certificate-derived anomaly detection is impossible on
real-world TLS ≤1.2 mail traffic. It proves this project cannot currently demonstrate it.

---

## 5. Verdict

**A-02 remains PARTIAL.** The decision rule was not met — not narrowly, but by a wide margin:
the new features cannot produce detections because two of the three carry no usable
information at all, and the third carries the wrong information.

Nothing about the ML lane changes in Phase 11:
- `robust-z-sum` stays a **secondary prioritisation signal**, never a finding
- `MAX_ML_ADJUSTMENT = 4.0` against a narrowest severity-tier gap of 30 — untouched
- the lane still emits a score, a band and a feature attribution, and no security conclusion
- the `--no-ai` equivalence property remains tested

**The new D-09…D-17 evidence flows into the deterministic rule engine, not into the ML lane.**
That is where it has demonstrable value, and it is where a forensic claim belongs.

### Why this is the right outcome, not a failure

The PS asks for AI-assisted anomaly detection. SecureMailScope ships a real, evaluated,
unsupervised technique with reproducible artifacts, explanations and abstention — and reports
honestly that its demonstrated detection value is zero on the available data. A tool that
claimed otherwise would be making exactly the kind of overclaim this project was built to
avoid.

> A technically honest PARTIAL is worth more than a fabricated COMPLETE.

---

## 6. Open questions

| ID | Status |
|---|---|
| **OQ-45** (does real multi-vendor traffic change the ML answer?) | **Still open, and now better characterised.** The real corpus is 100 % TLS 1.3 and 100 % forward secret, so it cannot discriminate. Answering it needs real traffic containing genuinely weak configurations — which, encouragingly, modern mail infrastructure does not produce. |
| **OQ-61** (new) | Would a TLS ≤1.2 corpus with *varied* certificate quality (expired, weak key, SHA-1 signature, self-signed) give the ML lane real variance? Deferred: building that corpus myself would re-create the generator-identity leak at a new level, since I would author both the anomalies and the baseline. |
