---
name: architecture-review
description: Architecture tradeoffs and ADR review. Trigger before any significant technology/structure decision, or when reviewing an ADR.
---
# architecture-review

- No major decision without an options comparison + evidence. Record as an ADR (Context, Problem,
  Options, Evidence, Decision, Rejected alternatives, Consequences, Risks, Open questions).
- Reuse mature tooling (tshark) over rebuilding (TCP/TLS). Custom only if tooling provably can't meet a need.
- Prefer modular monolith + SQLite + filesystem artifacts for the SIH prototype. Reject Kafka/k8s/
  microservices/redis/message brokers/cloud unless a real requirement forces them.
- Offline-capable by default (I-01 is our inference, not PS text, but forensic context favours it).
- Optimize for correctness, evidence traceability, explainability, demo reliability — not LOC or buzzwords.
