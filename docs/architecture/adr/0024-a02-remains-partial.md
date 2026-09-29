# ADR-0024 — A-02 remains PARTIAL after the Phase-11 feature re-assessment
**Status:** Accepted 2026-09-22 · **Confirms:** ADR-0015 · **Refines:** OQ-45

**Context** ADR-0015 closed OQ-37 negative: zero unique true detections on all three
held-out splits. It left OQ-45 open — would different data change the answer? Phase 11
creates genuinely new features for the first time (key exchange, forward secrecy,
certificate validity, public-key algorithm and length, signature algorithm), so the
question was re-opened honestly.

**Problem** Do the new Phase-11 features give the ML lane detection value the
deterministic rules do not already have?

**Decision rule, fixed before the evaluation ran** (`docs/phase11/03-scope-lock.md` §E-i)
A-02 moves from PARTIAL only if new features produce unique true detections on a held-out
split that the deterministic rules do not already produce. Improved scores, better
separation or nicer clustering do not qualify.

**Evidence** (`research/experiments/p11ai/measure_features.py`, all 46 captures the
project possesses: 10 real OQ-33r, 17 genB, 18 genC, 1 synthetic TLS 1.2)
- **Forward secrecy is constant.** `True` in 31 sessions, `None` in 15 (no TLS at all),
  **`False` in zero**. A feature with no variance carries no information and cannot
  change a ranking, whatever model consumes it.
- **Certificate evidence exists in 1 of 46 captures** — the one synthesised this phase to
  prove extraction works. A feature present in a single sample cannot be evaluated; a
  threshold on it would fit a point we authored ourselves.
- **Key exchange fingerprints the generator.** genB uses suites {`0x1302`, `0xc030`} and
  genC uses {`0x1301`, `0xc02f`} — **disjoint sets**, and structurally so: `genb.py:67`
  and `genc.py:59` each select the suite as a hard-coded function of TLS version. A
  suite-derived feature separates the two generators perfectly.

**Decision** **A-02 remains PARTIAL.** The new evidence is routed to the deterministic
rule engine, where it has demonstrable value, and **not** to the ML lane. Nothing about
the ML lane changes: `robust-z-sum` stays a secondary prioritisation signal,
`MAX_ML_ADJUSTMENT = 4.0` is untouched, the lane still emits a score, a band and a feature
attribution and never a finding, and the `--no-ai` equivalence property stays tested.

**Rejected**
- *Run the bake-off anyway.* It would produce a number, and the number would be
  meaningless — or favourable for the wrong reason. ADR-0015 measured 98.6 % generator
  separability as the project's central ML failure mode; adding a feature that separates
  the generators perfectly would worsen exactly that, and any gain would be the model
  learning which script wrote the file.
- *Synthesise a TLS 1.2 corpus with varied certificate quality to create variance.* We
  would author both the anomalies and the baseline, re-creating the generator-identity
  leak one level up. Recorded as OQ-61 instead.
- *Report A-02 as COMPLETE because the capability exists and is evaluated.* The
  capability existing is not detection value, and the PS asks for detection.

**Consequences** + the negative result is reproducible in seconds and is itself
defensible evidence; + the new certificate evidence strengthens the deterministic lane,
which is where forensic claims belong; − A-02 stays PARTIAL through to the SIH
submission, and the traceability entry states why in plain words.

**Risks** A reviewer may read PARTIAL as incomplete engineering rather than an honest
measurement → the traceability entry and the report state the decision rule, the
measurement and the reason, so the negative result reads as a finding rather than a gap.

**Open questions** **OQ-45 still open, better characterised**: the real corpus is 100 %
TLS 1.3 and 100 % forward secret, so it cannot discriminate; answering it needs real
traffic containing genuinely weak configurations, which modern mail infrastructure
encouragingly does not produce. New: **OQ-61** — would a TLS ≤1.2 corpus with varied
certificate quality give the ML lane real variance without re-introducing authorship leak?
