# research/experiments

**Research infrastructure. NOT product code. NOT a prototype.**

Scripts here exist solely to execute and reproduce experiments documented in `docs/research/`.
They must never be imported by, depended on, or promoted into an application. When implementation
begins, this directory stays where it is.

| Dir | Experiment | Document |
|---|---|---|
| `oq25/` | Does cross-session baselining reduce false positives? | [02A](../../docs/research/02A-cross-session-baseline-experiment.md) |
| `oq28/` | Does the OQ-25 result replicate on real packets? | [02B](../../docs/research/02B-packet-level-validation.md) |
| `oq36/` | Does any ML model add value beyond the deterministic lanes? | [17](../../docs/architecture/17-ml-model-evaluation.md) |
| `oq48/` | Which posture scoring formulation is defensible? | [19](../../docs/architecture/19-evidence-fusion-and-posture.md) |

## Reproducing OQ-25

```bash
python3 research/experiments/oq25/run.py    # scenarios A-F
python3 research/experiments/oq25/run2.py   # keys, history sweep, adversarial cases
python3 research/experiments/oq25/run3.py   # ablation, time-aware, infrastructure framing
```

Deterministic: every corpus is seeded. No network access, no ML, no external dependencies
beyond the Python standard library.

**Design constraint honoured throughout:** ground truth lives in a separate structure
(`Corpus.truth`) and is never visible to a detector. Detectors receive only
`Corpus.observations()` — the passively observable feature vector.


## Reproducing OQ-36 (Phase-6 ML evaluation)

```bash
python3 research/experiments/oq36/genb.py      # generator B corpus (Exim dialect)
python3 research/experiments/oq36/genc.py      # generator C corpus (Zimbra/Dovecot dialect)
python3 research/experiments/oq36/dataset.py   # inventory + split integrity
python3 research/experiments/oq36/bakeoff.py   # 9 candidates, held-out evaluation
python3 research/experiments/oq36/probes.py    # ablation, generator artifact, circularity
```

Needs `scapy` (corpus generation) and `scikit-learn` (four of the nine candidates; the
stdlib candidates run without it). Results land in `oq36/results/*.json`.

Generators B and C are seeded and byte-reproducible — `tests/test_ml_dataset.py` asserts
regeneration matches the committed captures exactly. The committed corpus is ~3.2 MB;
it is kept in the repository because the evaluation in doc 17 is not independently
checkable without it.

**Design constraint honoured throughout:** labels are used for evaluation only. No fit
receives them, and the threshold is chosen from normal-session scores on a generator that
never contributed a training row.


## Reproducing OQ-48 (Phase-7 posture scoring review)

```bash
python3 research/experiments/oq48/score_review.py
```

Scores all 60 captures (OQ-28 generator A, Phase-6 generators B and C) under all three
candidate formulations and runs the property probes -- monotonicity, duplicate
resistance, recurrence behaviour, severe-finding sensitivity, long-tail behaviour and
the missing-evidence case. Results land in `oq48/results/score-review.json` and the
verdict is ADR-0016.

Needs `tshark`; no ML dependency (the review scores deterministic and cross-session
findings only, since the ML lane cannot penalise a posture score by design).
