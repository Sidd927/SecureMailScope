# SecureMailScope

Passive PCAP cryptographic security posture assessment for email — **SIH26159** (NTRO).

Reads captured SMTP / IMAP / POP3 traffic and reports the **transport** security posture:
TLS versions, STARTTLS/STLS upgrade integrity, plaintext exposure, and what the capture
genuinely could not establish. It is passive and offline — it never connects to a mail
server, needs no keys, and reads no message content.

Out of scope by design: SPF, DKIM, DMARC, DNS, DANE, MTA-STS, S/MIME, PGP, phishing.
None appears in the authoritative problem statement
(`docs/research/19-authoritative-ps-verification.md`).

## Principles

- **Evidence over assumptions.** Every conclusion traces to frames, a rule and a standard.
- **UNKNOWN ≠ SECURE.** `AMBIGUOUS` and `NOT_OBSERVABLE` are not compliant states and
  never improve a score. A capture that shows too little gets `INSUFFICIENT_EVIDENCE`,
  not a good grade.
- **`PostureAssessment` is canonical.** The backend, and every later layer, consume it
  and recompute nothing.
- **ML cannot create security facts.** The anomaly lane is a bounded prioritisation
  signal; it has no demonstrated detection value (ADR-0015).

## Requirements

Python ≥ 3.9 and **tshark** (developed against 4.6.8). The core package has **zero**
runtime dependencies.

`pip install -e .` is unreliable on the system pip — use `PYTHONPATH=src`.

## Tests

```bash
PYTHONPATH=src python3 -m pytest -q
```

Tests needing tshark or the research captures skip cleanly when they are absent.

## Backend (Phase 8)

Optional extra; the analysis core stays dependency-free without it.

```bash
python3 -m pip install 'fastapi>=0.110' 'pydantic>=2' 'uvicorn>=0.27' 'python-multipart>=0.0.9'
```

```bash
PYTHONPATH=src python3 -m securemailscope.backend --port 8000
```

Binds to loopback. **There is no authentication** — this is a local single-analyst
prototype (ADR-0011), not a deployable service.

```bash
curl -s -F file=@capture.pcap http://127.0.0.1:8000/api/v1/analyses
```

| Method | Path |
|---|---|
| GET | `/api/v1/health` |
| POST | `/api/v1/analyses` — `?ai=true` enables the ML lane, `?force=true` re-runs |
| GET | `/api/v1/analyses` |
| GET | `/api/v1/analyses/{run_id}` |
| GET | `/api/v1/analyses/{run_id}/assessment` |
| GET | `/api/v1/analyses/{run_id}/artifacts` — `?verify=true` re-hashes |
| GET | `/api/v1/analyses/{run_id}/reports` — available formats + integrity |
| GET | `/api/v1/analyses/{run_id}/reports/{html\|pdf\|json}` |
| GET | `/api/v1/analyses/{run_id}/dashboard` — console view model |

The assessment endpoint returns the canonical document unaltered. Read `coverage`
alongside `overall_posture`: a band without its evidence coverage is a misleading claim,
which is why the band is withheld below 50 % assessed coverage.

Interactive API docs at `/docs` once running.

## Forensic reports (Phase 9)

JSON and HTML need **no dependency**. PDF needs one extra:

```bash
python3 -m pip install 'reportlab>=4'
```

```bash
curl -s http://127.0.0.1:8000/api/v1/analyses/<run_id>/reports/html -o report.html
```

The HTML is a single standalone file — no CDN, no webfont, no script — so it opens from
disk and prints cleanly. The PDF is composed from the same report model, not from the
HTML, and both are byte-deterministic: the report is a pure function of its assessment,
so the same assessment always renders to the same bytes and can be cited by
`report_sha256`.

The timestamp shown in a report is the **analysis** time, not a print time.

## Analyst console (Phase 10)

Open **http://127.0.0.1:8000/dashboard/** once the backend is running. No build step, no
npm packages — it is static ES modules served by the same FastAPI app.

Four screens: **History** (every run and its lifecycle state), **Overview** (posture and
coverage together, protocol posture, distributions, top findings, the ML panel, report
links), **Findings** (prioritised in canonical order, filterable on eight canonical
facets), and **Evidence & provenance** (abstentions with how to resolve them,
limitations, standards including unmapped citations, rule ids, artifact integrity).

The console renders the canonical assessment and computes no security conclusion of its
own. It shows what the assessment could not determine as readily as what it could, and
states plainly what the contract does not carry — there is no packet-level drill-down,
because the assessment does not contain one.

There is **no authentication**: bind to loopback only.

## Where to look

| Document | Why |
|---|---|
| `docs/CLAUDE_CONTINUATION_CONTEXT.md` | orientation for a fresh session |
| `docs/architecture/ARCHITECTURE_STATUS.md` | current status and open questions |
| `docs/architecture/requirements-traceability.md` | requirement status with evidence |
| `docs/architecture/19-evidence-fusion-and-posture.md` | the canonical output |
| `docs/architecture/21-backend-persistence-api.md` | backend, storage and API |
| `docs/architecture/22-forensic-reporting.md` | reporting, HTML/PDF, report identity |
| `docs/architecture/23-dashboard-architecture.md` | analyst console, projection, security boundary |
| `docs/architecture/adr/` | 22 ADRs; every significant decision with its alternatives |

## Status

Phases 1–10 implemented on their own branches; `main` deliberately still points at
Phase 3.
Known limitations are recorded per phase rather than summarised away — start with
`ARCHITECTURE_STATUS.md`.
