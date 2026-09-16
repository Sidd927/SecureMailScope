# research/experiments

**Research infrastructure. NOT product code. NOT a prototype.**

Scripts here exist solely to execute and reproduce experiments documented in `docs/research/`.
They must never be imported by, depended on, or promoted into an application. When implementation
begins, this directory stays where it is.

| Dir | Experiment | Document |
|---|---|---|
| `oq25/` | Does cross-session baselining reduce false positives? | [02A](../../docs/research/02A-cross-session-baseline-experiment.md) |

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
