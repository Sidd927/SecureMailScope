# SecureMailScope — Frontend Rebuild Audit
**Document Version:** 1.0 (Phase 1 Audit)  
**Branch:** `frontend/final-user-experience`  
**Problem Statement:** SIH26159 — AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications  
**Organization:** National Telecom Regulatory Organization (NTRO)

---

## 1. Executive Summary

This audit establishes the ground truth for rebuilding the SecureMailScope frontend from first principles. The backend/security engine is completely frozen and operates as mission-grade infrastructure. The objective of this frontend reinvention is not to create another skin or card redesign, but to construct a guided forensic investigation workflow answering:
1. **WHAT HAPPENED?**
2. **WHY DOES IT MATTER?**
3. **WHAT PROVES IT?**
4. **WHAT CAN WE KNOW? (Observed vs. Inferred)**
5. **WHAT CAN WE NOT KNOW? (Epistemic boundaries: Not Observable)**
6. **WHAT SHOULD I INVESTIGATE NEXT?**

---

## 2. Real Backend Environment & Startup Architecture

### 2.1 Backend Process & Port
- **Host & Port:** `http://127.0.0.1:8001` (loopback only, no external exposure without authentication per ADR-0011).
- **Backend Invocation:**
  ```bash
  PYTHONPATH=src python3 -m securemailscope.backend --port 8001 --data-dir ./securemailscope-data
  ```
- **Startup Script:** `./demo/commands/start_demo.sh 8001` (or integrated one-command launcher).
- **TShark Integration:** Fully operational (`TShark 4.6.8` verified live via `GET /api/v1/health`).
- **Live Health Status:**
  ```json
  {
    "status": "ok",
    "version": "0.1.0",
    "backend_schema_version": "1.0",
    "posture_schema_version": "1.0",
    "posture_engine_version": "0.8.0",
    "database": "ok",
    "artifact_count": 17,
    "artifact_bytes": 150662,
    "limits": {
      "max_upload_bytes": 268435456,
      "max_concurrent_analyses": 1,
      "max_queued_jobs": 8,
      "max_analysis_seconds": 600,
      "max_page_size": 100,
      "default_page_size": 20,
      "max_json_bytes": 65536
    },
    "tshark": "available"
  }
  ```

### 2.2 Frontend Communication & Proxy
- **Vite Dev Server:** `http://127.0.0.1:5173`
- **Proxy Configuration (`frontend/vite.config.ts`):**
  Proxies all `/api/v1/*` requests directly to `http://127.0.0.1:8001`.
- **Offline / Standalone Resilience:**
  If the backend daemon is temporarily halted, the frontend incorporates verified fixtures (`frontend/src/fixtures/real_fixtures.json`) matching exact engine runs for the 3 core demonstration captures.

---

## 3. Exhaustive Backend API Contract Audit

The API surface is strictly bounded by `/api/v1` (no unauthorized extensions allowed):

| HTTP Method | Path | Status | Response Model | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | 200 | `HealthResponse` | System, database, storage, and TShark availability |
| `POST` | `/api/v1/analyses` | 201 | `RunResponse` | Ingest PCAP (multipart/form-data or octet-stream) |
| `GET` | `/api/v1/analyses` | 200 | `RunListResponse` | Historical capture executions with pagination |
| `GET` | `/api/v1/analyses/{run_id}` | 200 | `RunResponse` | Status, timestamps, error states, and timing |
| `GET` | `/api/v1/analyses/{run_id}/dashboard` | 200 | `DashboardViewModel` | Canonical projection (identity, posture, findings, epistemic limits, standards) |
| `GET` | `/api/v1/analyses/{run_id}/assessment` | 200 | `AssessmentResponse` | Canonical raw security evaluation document |
| `GET` | `/api/v1/analyses/{run_id}/sessions` | 200 | `SessionListResponse` | Reconstructed TCP/TLS sessions and frame indices |
| `GET` | `/api/v1/analyses/{run_id}/reports` | 200 | `ReportListResponse` | Available reports with hash integrity |
| `GET` | `/api/v1/analyses/{run_id}/reports/{fmt}` | 200 | Binary / Stream | Export assessment as `html`, `pdf`, or `json` |

---

## 4. Real Data Truth & Ground Truth Scenarios

The frontend must represent the following verified scenarios with 100% fidelity:

### Scenario 1: `backup_weak_certificate.pcap`
- **Overall Posture:** `44.0 / 100` — **CRITICAL** (`F2-group-damped` calculus).
- **Starting Score:** `100.0`.
- **Deduction 1:** `−28.0 pts` — RSA 1024-bit public key modulus (`NIST SP 800-57 Part 1 Rev. 5 §5.6.1`).
- **Deduction 2:** `−28.0 pts` — `sha1WithRSAEncryption` deprecated signature hash (`RFC 9155 / NIST SP 800-131A`).
- **Proof:** Frame `#6`, Stream `#0`, SMTPS port `465`.
- **Epistemic Boundaries:** Client Trust Store and OCSP/CRL are `NOT_OBSERVABLE`.

### Scenario 2: `deepdive_cross_session_control_endpoint.pcap`
- **Overall Posture:** `22.15 / 100` — **CRITICAL**.
- **Subject Client (`10.0.0.6`, Streams 0–5):** 6 sessions with `STARTTLS` capability omitted; cleartext authentication exposed.
- **Control Client (`10.0.0.7`, Streams 6–11):** 6 sessions advertising `STARTTLS` and establishing `TLS 1.3`.
- **Governing Rule:** `CS-STARTTLS-001` / `RFC 3207 §6` (Downgrade behavioral anomaly).

### Scenario 3: `scene_b_certificate_honesty.pcap`
- **Overall Posture:** `100.0 / 100` — **STRONG**.
- **Handshake:** Negotiated `TLS 1.3` (RFC 8446).
- **Epistemic Boundary:** Leaf certificate is encrypted in TLS 1.3 handshake; certificate extraction is honestly reported as `NOT_OBSERVABLE`.

---

## 5. What Data is AVAILABLE vs. NOT AVAILABLE

### Available Data (Must Be Used):
1. **Canonical Posture:** Score value, band (`CRITICAL`, `WEAK`, `ADEQUATE`, `STRONG`), formula ID, deductions breakdown.
2. **Deterministic Findings:** Issue class, severity, rank, title, plain-language conclusion, technical explanation, proof frame numbers, standards citations.
3. **Epistemic Abstentions:** Explicit reasons why facts could not be concluded (`NOT_OBSERVABLE`, `INSUFFICIENT_CAPTURE`, `AMBIGUOUS`).
4. **Session Evidence:** Client/Server IP:port, TLS version, cipher suite, key exchange, certificate fields, timing.
5. **Multi-Session Baselines:** Subject vs. Control matrix, stream comparisons.
6. **Regulatory Citations:** NIST SP 800-57, NIST SP 800-52r2, RFC 9155, RFC 8314, RFC 8996, RFC 3207.

### Unavailable Data (Must NEVER Be Fabricated):
1. **Live Analysis Progress Percentage:** Backend is synchronous; progress percentages (`37%`, `61%`, `82%`) do not exist.
2. **Packet-Level Hex / Raw Bytes:** No raw packet payload endpoint exists.
3. **Attacker Attribution / Intent:** Passive capture cannot assert malicious intent.
4. **Trust Anchor & Revocation:** Offline captures do not contain client trust stores or live OCSP/CRL queries.
5. **AI Confidence Scores:** ML lane only re-ranks presentation order; it produces no confidence percentage.

---

## 6. What Can Be Reused vs. What Must Be Removed

### What Must Be REMOVED:
- **7-Tab Equal-Weight Top Navigation:** Too much cognitive load on first landing.
- **Generic Dashboard Widgets / Tiles:** Equal-weight card grids that bury the primary determination.
- **Duplicate Navigation Elements:** Competing buttons and tabs on every screen.
- **Verbose Monospace Overload:** Non-technical copy rendered in monospace.
- **All `/design-lab` exploratory traces:** Product must feel like a shipping, authoritative forensic instrument.

### What Must Be REUSED & REORGANIZED:
- **Clean API Client (`client.ts`):** Robust async handling, headers, error wrapping.
- **Exact Domain Types (`types.ts`):** Unaltered strict enums (`EvidenceState`, `PostureBand`, etc.).
- **Topological Provenance SVG:** Highly intuitive when focused on "How did we reach this conclusion?".
- **Protocol Sequence Model:** Valuable directional narrative when Frame #6 is visually emphasized.
- **Authoritative Report Preview:** Verifiable deliverable structure.

---

## 7. Conclusions & Next Steps
With the audit complete and live backend verified:
- Proceed to Phase 2: Create `FRONTEND-REBUILD-IA.md`.
- Structure the experience into 3 primary modes:
  - **Mode A (Home / Intake):** Clean launchpad answering "What is this tool and what do I upload?".
  - **Mode B (Analysis / Results):** Verdict-first determination answering "What happened, why does it matter, and what proves it?".
  - **Mode C (Forensic Detail):** Progressive drill-down into Protocol, Certificate, Cross-Session, Provenance, and Report.
