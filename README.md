# SecureMailScope

Passive PCAP cryptographic security posture assessment for email — **SIH26159** (NTRO).

> **Checkout the release, not the default branch.** `main` is deliberately frozen at an early
> phase (see [Status](#status) below). The released system is the tag **`v0.6.0-phase11`**:
> ```bash
> git checkout v0.6.0-phase11
> ```

Reads captured SMTP / IMAP / POP3 traffic — including implicit-TLS SMTPS/IMAPS/POP3S — and
reports the **transport** security posture: TLS version, cipher suite, key exchange, X.509
certificate properties where a cleartext handshake exposes them, forward secrecy, STARTTLS/STLS
upgrade integrity, plaintext exposure, insecure configuration, and what the capture genuinely
could not establish. It is passive and offline — it never connects to a mail server, needs no
keys, and reads no message content.

**Certificate visibility is bounded by the protocol, not by this tool.** TLS 1.3 encrypts the
Certificate message (RFC 8446 §2), so a TLS 1.3 session correctly reports the certificate as
`NOT_OBSERVABLE` — that is never rendered as "certificate invalid" or "certificate absent."
Chain **structure** is validated where a certificate is visible; chain **trust** and
**revocation** are not, because a passive capture carries no trust anchor and no OCSP/CRL
access — this project does not claim otherwise (see [Status](#status)).

Out of scope by design: SPF, DKIM, DMARC, DNS, DANE, MTA-STS, S/MIME, PGP, phishing, attacker
attribution. None appears in the authoritative problem statement
(`docs/research/19-authoritative-ps-verification.md`), and passive packet evidence cannot
establish attribution regardless.

## Principles

- **Evidence over assumptions.** Every conclusion traces to frames, a rule and a standard.
- **UNKNOWN ≠ SECURE.** `AMBIGUOUS` and `NOT_OBSERVABLE` are not compliant states and
  never improve a score. A capture that shows too little gets `INSUFFICIENT_EVIDENCE`,
  not a good grade.
- **`PostureAssessment` is canonical.** The backend, and every later layer, consume it
  and recompute nothing.
- **ML cannot create security facts.** The anomaly lane is a bounded, unsupervised
  prioritisation signal — it can re-order findings within one severity tier and can never
  create, upgrade, or downgrade a finding. Evaluated honestly across every held-out split and
  every capture this project holds, it currently demonstrates **no independent detection
  value**, and the tool reports that rather than hiding it (ADR-0015, ADR-0024). Every
  assessment is identical with the AI lane on or off — `--no-ai` is a proof, not a toggle for
  looking less capable.

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
| `docs/phase11/05-architecture.md` | key exchange, X.509, forward secrecy, insecure config (`crypto/` package) |
| `docs/phase11/06-final-audit.md` | why D-11 and A-02 are PARTIAL, with the measured reasons |
| `docs/phase12/01-final-requirements-audit.md` | the authoritative requirement-by-requirement status table |
| `docs/phase12/11-judge-question-bank.md` | short/technical answers to the questions this project is most likely to be asked |
| `docs/architecture/adr/` | 24 ADRs; every significant decision with its alternatives |

## Status

**Released: `v0.6.0-phase11`** — the tag to check out, not `main` (below). Nineteen
standards-bound rules (16 single-session + 3 cross-session) cover TLS version, cipher,
key exchange, X.509 extraction/expiry/key-strength/signature, forward secrecy, insecure
configuration, STARTTLS/STLS integrity, and plaintext exposure — each finding cited to an
RFC or NIST publication, never an invented weight. 1219 tests pass, zero known flakes.

Two requirements are honestly **PARTIAL**, not incomplete-for-lack-of-time:

- **D-11** (certificate chain validation) — chain *structure* is fully validated; chain
  *trust* and *revocation* are not, because a passive capture contains no trust anchor and
  no OCSP/CRL access (RFC 5280 §6; RFC 6960). A bundled public root store was evaluated and
  rejected — it would flag legitimate private-CA enterprise deployments as untrusted.
- **A-02** (AI-assisted anomaly detection) — a real, evaluated, unsupervised model ships and
  is proven not to change any security conclusion when disabled; it currently demonstrates
  zero unique true detections on any held-out split or corpus this project holds.

Full reasoning for both: `docs/phase12/01-final-requirements-audit.md`.

`main` deliberately still points at Phase 3 — every phase from 4 onward lives on its own
branch, tagged at release. This is a **process choice** (keep `main` as a stable early
anchor while phases are developed and reviewed on their own branches), not a sign of
incomplete work; check out `v0.6.0-phase11` for the released system. Known limitations are
recorded per phase rather than summarised away — start with `ARCHITECTURE_STATUS.md`.
