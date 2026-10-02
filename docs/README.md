# SecureMailScope documentation

The repository root [README](../README.md) is the gateway. This index tells you where the deeper material lives and **how current each part is** — most of the numbered documents are phase-by-phase design and audit records that are deliberately kept exactly as written.

## Start here

| If you want to… | Read |
|---|---|
| Understand the system's structure | [architecture/ARCHITECTURE.md](architecture/ARCHITECTURE.md) |
| See how every SIH26159 requirement is met (and where it is only partly met) | [phase12/01-final-requirements-audit.md](phase12/01-final-requirements-audit.md) · [architecture/requirements-traceability.md](architecture/requirements-traceability.md) |
| See cross-session reasoning in action with real engine output | [finalization/06-cross-session-demo.md](finalization/06-cross-session-demo.md) |
| Prepare for tough questions | [phase12/11-judge-question-bank.md](phase12/11-judge-question-bank.md) · [finalization/10-final-judge-cheatsheet.md](finalization/10-final-judge-cheatsheet.md) |
| Run the live demo | [../demo/RUNBOOK.md](../demo/RUNBOOK.md) · [phase12/03-demo-journey.md](phase12/03-demo-journey.md) |
| Deploy it | [deployment/DEPLOYMENT-RUNBOOK.md](deployment/DEPLOYMENT-RUNBOOK.md) |

## Architecture — [`architecture/`](architecture/)

Design records numbered `00`–`23` (data model, evidence & provenance, session reconstruction, rule catalogues, cross-session reasoning, ML architecture and evaluation, posture, backend/API, reporting, dashboard), 24 decision records in [`adr/`](architecture/adr/), and [ARCHITECTURE_STATUS](architecture/ARCHITECTURE_STATUS.md) (a historical map for Phases 1–10; it points to the current status documents).

Key contracts: [04 evidence states & provenance](architecture/04-evidence-provenance.md) · [13 single-session rules](architecture/13-rule-catalog.md) · [14](architecture/14-cross-session-reasoning.md) / [15](architecture/15-cross-session-rule-catalog.md) cross-session · [19 posture](architecture/19-evidence-fusion-and-posture.md) · [21 backend & API](architecture/21-backend-persistence-api.md) · [22 reporting](architecture/22-forensic-reporting.md).

## Research & validation — [`research/`](research/00-research-index.md)

[Research index](research/00-research-index.md) (every claim is labelled FACT / INFERENCE / ASSUMPTION / OPEN QUESTION). Highlights:

| Topic | Document |
|---|---|
| Official problem-statement verification | [19-authoritative-ps-verification](research/19-authoritative-ps-verification.md) |
| What passive TLS evidence can and cannot show | [01A](research/01A-tls-visibility-validation.md) · [02B packet-level validation](research/02B-packet-level-validation.md) |
| STARTTLS stripping prior art | [01B](research/01B-starttls-prior-art.md) |
| Cross-session baseline experiment | [02A](research/02A-cross-session-baseline-experiment.md) |
| Existing tools and other SIH submissions | [01C](research/01C-existing-tool-stack-reconstruction.md) · [01D](research/01D-sih-competitor-source-audit.md) |
| AI opportunity and architecture decision | [10A](research/10A-ai-opportunity-validation.md) · [10B](research/10B-ai-architecture-decision.md) |
| Real-world corpus validation | [22](research/22-oq46-oq47-validation.md) · [23](research/23-oq33r-real-world-validation.md) |
| ML evaluation (negative result, reported honestly) | [architecture/17](architecture/17-ml-model-evaluation.md) · [ADR-0015](architecture/adr/0015-ml-model-selection.md) |

Experiment code and captures: [`../research/experiments/`](../research/experiments/README.md).

## Deployment — [`deployment/`](deployment/)

[Architecture](deployment/DEPLOYMENT-ARCHITECTURE.md) (Vercel frontend + Render Docker backend, ephemeral storage on the Free plan) · [Runbook](deployment/DEPLOYMENT-RUNBOOK.md) · [Acceptance tests](deployment/DEPLOYMENT-ACCEPTANCE.md) · [Troubleshooting](deployment/DEPLOYMENT-TROUBLESHOOTING.md).

## Releases & validation — [`releases/`](releases/)

[Final engineering freeze](releases/SECUREMAILSCOPE-FINAL-ENGINEERING-FREEZE.md) (`v0.7.1-sih-final`) · [final system validation](releases/SECUREMAILSCOPE-FINAL-SYSTEM-VALIDATION.md) · [frontend handoff](releases/SECUREMAILSCOPE-FRONTEND-HANDOFF.md) · [release manifest](releases/SECUREMAILSCOPE-FRONTEND-RELEASE-MANIFEST.md). Finalization audits (security, AI-claim, demo, release gate): [`finalization/`](finalization/).

## Demo bundle — [`../demo/`](../demo/README.md)

Captures, machine-generated expected results, pre-rendered JSON/HTML/PDF reports and SHA-256 sums.

## How to read the historical documents

| Area | Status |
|---|---|
| `architecture/00`–`23`, `adr/` | Design records; implemented parts are marked in each header. Superseded decisions are labelled as such. |
| `phase11/`, `phase12/`, `finalization/` | Phase audits — **historical snapshots**. Test counts, tags and branch names inside them describe the state at that time (e.g. `1219` tests at `v0.6.0-phase11`; **`1234` is the current verified count**). |
| `releases/` | Release records, kept as written. |
| `sih-pitch-deck/`, `presentation-layer-content.md`, `ANTIGRAVITY-*`, `CLAUDE_CONTINUATION_CONTEXT.md`, `SECUREMAILSCOPE_COMPLETE_TEAM_HANDOVER.md`, `engineering/` | Internal working material for the pitch and team handover; not part of the product description. |
| `assets/screenshots/` | Real screenshots of the deployed prototype used by the README. |
