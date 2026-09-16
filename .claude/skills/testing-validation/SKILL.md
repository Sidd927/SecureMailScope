---
name: testing-validation
description: Layered test strategy — unit, integration, regression, adversarial, ML. Trigger when adding features, changing detectors/models, or before a milestone.
---
# testing-validation

Layers: unit (state transitions, evidence states, rules, feature extraction) → integration
(PCAP→dissection→session→analysis→ML→findings→report) → regression (every OQ-25/28/33 scenario) →
adversarial (malformed/truncated/reordered/retransmit/missing/ambiguous/contradictory/injection) →
ML (leakage, seed reproducibility, held-out-by-generator, feature stability, inference reproducibility).

Golden corpus: each PCAP has SHA-256, scenario ID, expected evidence + states + findings + anomaly
behaviour. Never silently modify a golden PCAP — change = new hash + version + reason.
Run targeted → relevant integration → full regression only when justified. Same PCAP + same version =
reproducible output.
