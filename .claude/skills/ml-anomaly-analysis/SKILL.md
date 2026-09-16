---
name: ml-anomaly-analysis
description: ML methodology for the anomaly component — leakage prevention, experiment design, honest evaluation. Trigger for any model selection, feature design, training, or metric reporting.
---
# ml-anomaly-analysis

Non-negotiables:
- **Unsupervised only** for the anomaly signal. Do NOT train a classifier on labels produced by our own
  rules engine (the competitor circular-training trap — 01D §6, saravana/CipherPost).
- **Features are cross-session DEVIATION features**, not raw per-session values. Naive per-session
  Isolation Forest failed (10B §9: 2/32 attacks, more FP than deterministic). Signal lives in
  infrastructure-relative space.
- **Separate by generator/scenario/session** in train/test. Never train and test on near-identical
  synthetic sessions — that measures the generator (01 §6.3 trap 2).
- Report TP/FP/FN/TN, precision, recall, F1, FPR, PR-AUC (not accuracy on imbalanced data), seed
  stability, sensitivity to history size / protocol / truncation. Never fabricate metrics.
- ML output is `anomaly_score` / `anomaly_band` / `feature_contributions` / `model_version` — an
  independent signal. It NEVER writes a finding or overrides a deterministic fact.
- Report zero honestly. If ML adds nothing over the deterministic baseline on real data, say so.
