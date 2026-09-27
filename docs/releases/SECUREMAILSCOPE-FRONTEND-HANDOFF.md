# SecureMailScope Frontend — Team Handoff

## 1. Executive Summary

SecureMailScope is a specialized forensic investigation workstation for passive cryptographic assessment of secure email traffic (SMTP, IMAP, POP3, and implicit TLS variants). 

Unlike conventional dark cybersecurity dashboards or generic SaaS monitoring templates, this interface is engineered specifically as a **forensic analyst workstation**. It translates raw wire evidence (PCAPs, TCP streams, protocol frames, and handshake attributes) into normative compliance findings (NIST SP 800-52r2, NIST SP 800-57, RFC 3207, RFC 8314) and deterministic security posture scores (0–100 scale).

### Current Maturity
- **Status:** Production-Ready & Feature-Complete (`frontend-v1.0.0` / `frontend-v1.0.1`).
- **Backend Coupling:** Acts strictly as a projection layer over the real FastAPI + TShark backend.
- **Freeze Boundary:** The Python backend, SQLite database schema, deterministic rule engine, scoring formulas, ML models, and API contracts are strictly frozen.
- **What Can Be Changed:** Frontend presentation, CSS utility polish, additional client-side filtering, keyboard shortcut extensions, and responsive layout enhancements without altering backend contracts.

---

## 2. Current Release

- **Branch:** `frontend/final-polish`
- **Baseline Implementation Commit:** `b2cbbae` (`feat(frontend): finalize forensic workstation frontend`)
- **Release Documentation Commit:** `HEAD` (`docs(release): add frontend v1 team handoff and release documentation`)
- **Tags:** 
  - `frontend-v1.0.0` (Immutable implementation baseline at `b2cbbae`)
  - `frontend-v1.0.1` (Immutable release documentation & team handoff)
- **Safety Checkpoint Branch:** `frontend/pre-final-polish` (Commit `60fe4ae`)
- **Release Date:** September 28, 2026
- **Repository:** `git@github.com:Sidd927/SecureMailScope.git`
- **Frontend Stack:** React 19, TypeScript 5.9, Vite 8.3, Vanilla CSS (Design Tokens, zero Tailwind)
- **Backend Dependency:** FastAPI (Python 3.9+) on `127.0.0.1:8001`, TShark 4.6.8
- **Build Tool:** `tsc -b && vite build` (Production bundle generated in <200ms)
- **Linter:** `oxlint` (0 errors, 9 non-blocking warnings)

---

## 3. Architecture

The frontend follows a disciplined component architecture with no ad-hoc CSS frameworks:

```
frontend/
├── dist/                          # Production bundle (Vite output)
├── scripts/                       # Verification & headless screenshot capture scripts
│   ├── capture_phase1d_screenshots.mjs
│   ├── verify_real_backend_cdp.mjs
│   └── capture_current.mjs
├── src/
│   ├── App.tsx                    # Root shell & view switcher (Home vs Workbench)
│   ├── api/                       # API clients & backend contract mapping
│   │   ├── client.ts              # Fetch client communicating with /api/v1
│   │   └── types.ts               # Complete TypeScript types matching backend models
│   ├── context/
│   │   └── InvestigationContext.tsx # Central store for active runs, dashboard data, sessions
│   ├── components/
│   │   ├── home/                  # Entry landing page
│   │   │   ├── HomeView.tsx       # Hero, feature highlights, PCAP upload drop bay
│   │   │   ├── ForensicProcessPipeline.tsx # 6-stage methodology interactive roadmap
│   │   │   └── RecentAnalyses.tsx # 4-column case ledger (Score, Case, Scope, Time)
│   │   ├── shell/                 # Global UI chrome
│   │   │   ├── Header.tsx         # 2-tier responsive header, case selector, engine pill
│   │   │   ├── CommandPalette.tsx # Contextual ⌘K spotlight
│   │   │   └── IntakeModal.tsx    # Native PCAP upload modal
│   │   └── workbench/             # Analyst investigation workspace
│   │       ├── WorkbenchView.tsx  # 215px quiet navigation rail & tab switcher
│   │       ├── overview/          # Executive Brief, Score Waterfall, Wire Evidence
│   │       │   ├── InvestigationOverview.tsx
│   │       │   ├── ExecutiveDetermination.tsx
│   │       │   ├── ScoreWaterfall.tsx
│   │       │   ├── ProofCard.tsx
│   │       │   └── ObservabilityBoundary.tsx
│   │       ├── flow/              # Evidentiary reasoning graph
│   │       │   └── InvestigationFlow.tsx
│   │       ├── evidence/          # Findings queue & analyst notes
│   │       │   ├── FindingsTable.tsx
│   │       │   ├── FindingEvidenceDetail.tsx
│   │       │   └── CertificateForensics.tsx
│   │       ├── timeline/          # Protocol state reconstruction
│   │       │   ├── ProtocolJourney.tsx
│   │       │   └── ProtocolStateMachineStory.tsx
│   │       ├── crosssession/      # Subject vs Control endpoint comparison
│   │       │   └── CrossSessionWorkspace.tsx
│   │       ├── provenance/        # 8-stage byte-to-posture interactive trace
│   │       │   ├── EvidenceChain.tsx
│   │       │   └── ProvenanceGraph.tsx
│   │       └── report/            # Flagship deliverable presentation & exports
│   │           └── ReportExperience.tsx
│   └── styles/
│       ├── tokens.css             # Semantic CSS tokens (--ds-*, --sms-*)
│       ├── components.css         # Component styling, layouts, buttons, cards
│       └── overview.css           # Workspace grid, waterfall tree, timeline rules
└── package.json
```

---

## 4. Backend Contract

The frontend communicates with the FastAPI service locally via Vite's configured proxy (`/api/v1` $\rightarrow$ `http://127.0.0.1:8001/api/v1`):

- **Health:** `GET /api/v1/health` $\rightarrow$ Checks engine status, TShark version (`4.6.8`), and schema version (`1.0`).
- **Analyses List:** `GET /api/v1/analyses` $\rightarrow$ Returns ledger of recorded runs.
- **Upload Analysis:** `POST /api/v1/analyses` (`multipart/form-data`) $\rightarrow$ Uploads PCAP and triggers dissection pipeline.
- **Dashboard Summary:** `GET /api/v1/analyses/{id}/dashboard` $\rightarrow$ Aggregated findings, posture band, score, and factor deductions.
- **Session Dissection:** `GET /api/v1/analyses/{id}/sessions` $\rightarrow$ Per-stream TCP metadata, handshake parameters, and frame logs.
- **Assessment Payload:** `GET /api/v1/analyses/{id}/assessment` $\rightarrow$ Complete canonical JSON assessment artifact.
- **Report Manifest:** `GET /api/v1/analyses/{id}/reports` $\rightarrow$ Stored report metadata.
- **Report Downloads:** 
  - `GET /api/v1/analyses/{id}/reports/html` $\rightarrow$ Standalone printable HTML report.
  - `GET /api/v1/analyses/{id}/reports/pdf` $\rightarrow$ High-resolution binary PDF deliverable.
  - `GET /api/v1/analyses/{id}/reports/json` $\rightarrow$ Machine-readable assessment JSON.

---

## 5. Forensic Data Model

The frontend strictly enforces backend evidentiary vocabulary across all components:

| Category | Permitted Values | Meaning in SecureMailScope |
|---|---|---|
| **EvidenceState** | `OBSERVED`<br>`INFERRED`<br>`UNKNOWN`<br>`AMBIGUOUS`<br>`INCOMPLETE`<br>`NOT_OBSERVABLE` | Direct packet proof vs deduced properties vs bounded visibility (e.g. TLS 1.3 encrypted handshake). |
| **FindingStatus** | `OBSERVED_ISSUE`<br>`COMPLIANT`<br>`INFORMATIONAL`<br>`AMBIGUOUS`<br>`INSUFFICIENT_EVIDENCE`<br>`NOT_OBSERVABLE` | Analytical evaluation status of a security property. |
| **BaselineStatus** | `ESTABLISHED`<br>`INSUFFICIENT_HISTORY`<br>`NOT_APPLICABLE` | Endpoint baseline status for cross-session comparative reasoning. |
| **Deviation** | `NONE`<br>`DEVIATION`<br>`SUSPICIOUS_DEVIATION`<br>`NOT_ASSESSED` | Discrepancy between subject traffic and comparable control traffic. |
| **PostureBand** | `STRONG`<br>`ADEQUATE`<br>`WEAK`<br>`CRITICAL`<br>`INSUFFICIENT_EVIDENCE` | Overall composite cryptographic posture classification. |

---

## 6. Core Screens

### 1. Home / Case Desk (`HomeView.tsx`)
- **Purpose:** Entrance to the forensic system.
- **Key Elements:** SecureMailScope mark, 6-stage forensic methodology pipeline, drag-and-drop PCAP upload bay, and 4-column recent case ledger with direct pivot buttons (`Open ↗`).
- **Data Consumed:** `GET /api/v1/analyses`, `GET /api/v1/health`.

### 2. Overview (`InvestigationOverview.tsx`)
- **Purpose:** Executive forensic brief providing immediate clarity in the first viewport.
- **Key Elements:** Executive Determination (`CRITICAL 22.15 / 100`, plain-English headline), "Why This Score?" deduction tree, Wire Evidence table (`AUTH_ACTIVITY: TRUE · OBSERVED`), and Evidentiary Reasoning Path.
- **Data Consumed:** `GET /api/v1/analyses/{id}/dashboard`, `assessment.scoring_explanation`.

### 3. Findings Queue (`FindingsTable.tsx`, `FindingEvidenceDetail.tsx`)
- **Purpose:** Analyst work queue prioritizing issues by severity and certainty.
- **Key Elements:** High-density queue rows on the left; Analyst Note with What Was Observed, Why It Matters, Normative Standard, and Wire Facts on the right.
- **Data Consumed:** `dashboard.findings[]`, `dashboard.evidence[]`.

### 4. Protocol Journey (`ProtocolJourney.tsx`, `ProtocolStateMachineStory.tsx`)
- **Purpose:** Chronological packet dialogue reconstruction.
- **Key Elements:** Vertical timeline anchored by frame numbers (`#1 Connected` $\rightarrow$ `#4 220 Greeting` $\rightarrow$ `#5 EHLO` $\rightarrow$ `#6 Capabilities` $\rightarrow$ `#7 Plaintext AUTH` $\rightarrow$ `#8 Continuation` $\rightarrow$ `#10 Closed`). Packet dissection hex and field viewer for focused frames.
- **Data Consumed:** `GET /api/v1/analyses/{id}/sessions`.

### 5. Certificates (`CertificateForensics.tsx`)
- **Purpose:** Cryptographic credential and handshake analysis.
- **Key Elements:** Case A leads with Cryptographic Weakness banner (`RSA 1024`, `SHA-1`, Frame #6); Case C leads with `NOT_OBSERVABLE` encrypted handshake explanation under TLS 1.3.
- **Data Consumed:** `session.tls`, `session.certificates[]`.

### 6. Cross-Session Workspace (`CrossSessionWorkspace.tsx`)
- **Purpose:** Signature comparative analysis between subject and control streams.
- **Key Elements:** Side-by-side Subject `10.0.0.6` vs Control `10.0.0.7`, divergence matrix table, Supported Deviation banner (`CS-STARTTLS-001`), and epistemic forensic boundary caveats.
- **Data Consumed:** `dashboard.cross_session`, `dashboard.sessions[]`.

### 7. Provenance (`EvidenceChain.tsx`, `ProvenanceGraph.tsx`)
- **Purpose:** Interactive 8-stage trace linking wire bytes to score deductions.
- **Key Elements:** Vertical clickable nodes: Capture $\rightarrow$ Stream $\rightarrow$ Frame $\rightarrow$ Wire Facts $\rightarrow$ Rule $\rightarrow$ Standard $\rightarrow$ Finding $\rightarrow$ Score Deduction.
- **Data Consumed:** `finding.evidence_refs`, `finding.provenance`.

### 8. Report Deliverable (`ReportExperience.tsx`)
- **Purpose:** Final analyst artifact for client or supervisory delivery.
- **Key Elements:** Formal assessment verdict banner, direct download triggers (PDF, HTML, JSON), and in-situ formal document preview.
- **Data Consumed:** `GET /api/v1/analyses/{id}/reports`, `GET /api/v1/analyses/{id}/reports/{fmt}`.

---

## 7. Investigation Flow

SecureMailScope enables seamless click-to-pivot investigation across the complete evidence chain:

```
CAPTURE (PCAP Ingest)
   │
   ▼
SESSION (TCP Stream #0)
   │
   ▼
WIRE EVENT (Frame #7 AUTH Command)
   │
   ▼
EVIDENCE (auth_activity = True · OBSERVED)
   │
   ▼
RULE (SEC-PLAIN-001)
   │
   ▼
STANDARD (NIST SP 800-52r2 §3.1)
   │
   ▼
FINDING (HIGH · CONFIRMED · OBSERVED ISSUE)
   │
   ▼
POSTURE (CRITICAL · 22.15 / 100)
   │
   ▼
REPORT (Forensic Assessment Artifact)
```

Clicking any element (e.g. `Frame #7`, `SEC-PLAIN-001`, or Subject IP) immediately navigates to and focuses the corresponding evidence.

---

## 8. Golden Test Cases

| Case | Capture File | Posture Band | Score | Key Expected Forensic Facts |
|---|---|---|---|---|
| **Case A** | `backup_weak_certificate.pcap` | **CRITICAL** | **44.0 / 100** | RSA 1024 bits modulus, SHA-1 signature algorithm, Frame #6, Stream #0, NIST SP 800-57 Part 1 Rev. 5 §5.6.1 disallowed key length. |
| **Case B** | `deepdive_cross_session_control_endpoint.pcap` | **CRITICAL** | **22.15 / 100** | 12 sessions evaluated, Subject `10.0.0.6` (STARTTLS absent, Plaintext auth) vs Control `10.0.0.7` (STARTTLS observed, TLS established), Frame #7, Frame #56 (`CS-STARTTLS-001`). |
| **Case C** | `scene_b_certificate_honesty.pcap` | **STRONG** | **100.0 / 100** | TLS 1.3 negotiated, Certificate extraction correctly reported as `NOT_OBSERVABLE` due to RFC 8446 encrypted handshake. |

---

## 9. Real Backend Validation

The frontend was validated end-to-end against the live backend (`127.0.0.1:8001`) with TShark 4.6.8:
- Direct PCAP upload successfully created analysis runs.
- All endpoints (`/health`, `/analyses`, `/dashboard`, `/sessions`, `/assessment`, `/reports`) responded with valid data.
- Live Engine status pill accurately reflected `● ENGINE LIVE` with no fallback substitution.
- Report downloads for HTML, PDF, and JSON resolved with valid file payloads.

---

## 10. Responsive Validation

The UI was verified using headless Chrome CDP across multiple viewports:
- **1600 × 1000 & 1440 × 900 (Desktop):** Full workstation layout with quiet 215px navigation rail and dual-column inspection panels.
- **1280 × 800 (Laptop):** Proportional scaling with preserved readability.
- **768 × 1024 (Tablet):** Two-tier compact header (status row + full-width case selector), horizontal scrollable rail, zero button clipping.
- **375 × 812 (Mobile):** Single-column priority reading flow (Posture $\rightarrow$ Determination $\rightarrow$ Actions $\rightarrow$ Waterfall $\rightarrow$ Wire Data). Zero horizontal overflow.

---

## 11. Security & Privacy Properties

- **Air-Gapped / Offline Posture:** No external CDNs, tracking pixels, or third-party web fonts. All font files (IBM Plex Sans, IBM Plex Mono) are bundled locally.
- **No Unsafe Code Execution:** Zero instances of `dangerouslySetInnerHTML`, `eval()`, or dynamic script injection.
- **Strict Read-Only Projection:** The frontend never modifies backend assessment databases or alters PCAP truth.

---

## 12. Git & Release Strategy

- **Release Branch:** `frontend/final-polish`
- **Release Baseline Tag:** `frontend-v1.0.0` (Points to implementation commit `b2cbbae`)
- **Handoff Documentation Tag:** `frontend-v1.0.1`
- **Safety Checkpoint:** `frontend/pre-final-polish` (`60fe4ae`)

### How to Branch for Future Work
To begin a new iteration, branch cleanly from the tagged release:
```bash
git checkout -b frontend/feature-name frontend-v1.0.1
```

---

## 13. How to Run Locally

### Prerequisites
1. Python 3.9+ with `venv`
2. Wireshark / TShark 4.6.8 installed and in system `$PATH`
3. Node.js 20+ and `npm`

### Step 1: Start the Backend Engine
From the repository root:
```bash
# Launch FastAPI server on port 8001
PYTHONPATH=src python3 -m securemailscope.backend --host 127.0.0.1 --port 8001
```

### Step 2: Start the Frontend Dev Server
From `frontend/`:
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

### Step 3: Run Validation Checks
```bash
# In frontend/
npm run build    # TypeScript compilation & Vite bundle
npm run lint     # Oxlint static analysis
```

---

## 14. How to Continue Development Safely

1. **Maintain Backend Freeze:** Do not modify `securemailscope/`, `tests/`, or `research/` unless an official backend release phase is initiated.
2. **Preserve Epistemic Honesty:** Never rename `NOT_OBSERVABLE` to "UNKNOWN", and never present `SUSPICIOUS_DEVIATION` as "ATTACK DETECTED".
3. **Use Design Tokens:** All styles must reference tokens in `src/styles/tokens.css` (`--ds-*`, `--sms-*`). Avoid raw hex codes.
4. **Test Responsive Viewports:** Always test at 768px and 375px before committing any UI changes.

---

## 15. Known Limitations

1. **Timeline Virtualization for Massive Captures:** Extremely large PCAPs (>10,000 packets) render in a single scroll container. DOM virtualization can be added if captures of this scale are expected.
2. **Browser Print Variance:** PDF generation via `/api/v1/analyses/{id}/reports/pdf` uses backend WeasyPrint/reportlab, while in-browser `window.print()` relies on the local browser engine.

---

## 16. Recommended Future Improvements

- **P1 (High Value):** Add windowed virtualization (`@tanstack/react-virtual`) to `ProtocolJourney` for multi-megabyte captures.
- **P1 (High Value):** Add hotkey cheatsheet overlay accessible via `?` key.
- **P2 (Enhancement):** Packet payload search filter in Protocol Journey.

---

## 17. Capabilities NOT Claimed

SecureMailScope explicitly does **NOT** claim:
- Attacker attribution or geographical geolocation.
- Active STARTTLS stripping interception (it observes downgrade/discrepancies passively).
- Real-time mailbox monitoring or IMAP/POP3 content scanning.
- Chain-of-trust or CRL/OCSP revocation verification from passive captures alone.
- AI/ML hallucination of cryptographic keys or certificates.

---

## 18. Final Release Checklist

- [x] Frontend build passes (`npm run build`)
- [x] Frontend linter passes with zero errors (`npm run lint`)
- [x] Live backend integration verified on port 8001
- [x] Case A verified (`44.0 / 100`, RSA 1024, SHA-1)
- [x] Case B verified (`22.15 / 100`, 12 sessions, Subject vs Control)
- [x] Case C verified (`100 / 100`, TLS 1.3 `NOT_OBSERVABLE`)
- [x] Protocol Journey chronological timeline verified
- [x] Cross-session comparative matrix verified
- [x] 8-stage Provenance trace verified
- [x] Responsive layout verified (1440px, 768px, 375px)
- [x] Zero backend changes committed
- [x] Working tree clean
- [x] Branch `frontend/final-polish` and tags pushed to GitHub
