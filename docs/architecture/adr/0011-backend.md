# ADR-0011 — Modular monolith, Python + FastAPI
**Status:** Accepted 2026-09-16
**Context** SIH prototype, one workstation, offline; team velocity and demo reliability matter.
**Decision** Modular monolith: Python + FastAPI; components (01 §3) as internal modules with clean
interfaces; synchronous analysis for small captures, in-process background job + progress polling for
large ones. Python chosen for tshark subprocess, scapy/pandas/sklearn ecosystem, and continuity with
the validated experiment code.
**Rejected** microservices, Kafka, Kubernetes, Redis, message brokers, cloud — none justified (Phase-11 §22).
**Consequences** + simple deploy, easy to reason about/test, offline. − monolith scaling limits (irrelevant at prototype scale).
**Risks** long analysis blocking the API → background job; CPU-bound ML → runs in worker thread/process.
**Open questions** none blocking.
