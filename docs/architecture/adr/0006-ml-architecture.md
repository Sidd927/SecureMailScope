# ADR-0006 — ML anomaly component: unsupervised, deviation-feature, empirically selected
**Status:** Proposed (model NOT selected) 2026-09-16
**Context** PS explicitly requires AI/ML anomaly detection (A-02). Naive per-session Isolation Forest
failed (10B §9). Must ship a real component without forcing a bad one.
**Problem** What ML, on what features, selected how?
**Evidence** 05; 10B §9 (per-session ML: 2/32 attacks, more FP); 01D §6 (competitor circular training).
**Decision** Unsupervised anomaly detection over **cross-session deviation features**, model chosen by
a generator-held-out bake-off (05 §5) among robust-statistical (prior favourite), Isolation Forest,
LOF, One-Class SVM; autoencoder deprioritised (data). Separate lane; output is score only.
**Rejected** supervised classifier on rule labels (circular, 01D); per-session features (10B §9 failed);
autoencoder (insufficient data); no-ML (violates A-02 / Phase-11 §3).
**Consequences** + real A-02 component, non-circular, evaluated honestly. − adds ML surface + a corpus dependency (OQ-33r).
**Risks** may only qualify as a secondary prioritisation signal (accepted fallback, 05 §5); generator leakage → held-out eval.
**Open questions** OQ-36 model choice, OQ-37 complementary value, depends OQ-33r.
