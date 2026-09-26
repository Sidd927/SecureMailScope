# SecureMailScope — Information Architecture (IA) Specification
**Document Version:** 1.0 (Phase 2 IA Specification)  
**Branch:** `frontend/final-user-experience`  
**Problem Statement:** SIH26159 — AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications  
**Organization:** National Telecom Regulatory Organization (NTRO)

---

## 1. Core Architectural Mental Model

SecureMailScope rejects the cognitive overload of traditional SIEM dashboards, table dumps, and fragmented forensic tabs. 

The mental model is **A Guided Forensic Investigation**:
```
OPEN PRODUCT (Understand what this tool does)
   ↓
INTAKE / UPLOAD PCAP (Calm, passive offline ingestion)
   ↓
ANALYSIS STATE (Honest indeterminate activity, no fake progress %)
   ↓
INVESTIGATION SUMMARY (Primary determination, score waterfall, why it matters, what proves it)
   ↓
FINDINGS (Human-first findings with deduction penalties, evidence citation, standards)
   ↓
EVIDENCE INSPECTOR (Exact frame, stream, protocol, raw bytes & epistemic limits)
   ↓
DRILL-DOWN FORENSIC DETAIL (Protocol narrative, Certificate forensics, Cross-Session reasoning, Provenance DAG)
   ↓
REPORT DELIVERABLE (Exportable executive assessment in HTML, PDF, JSON)
```

The system organizes all capabilities into **Three Major User Modes**:
- **Mode A: Home / Intake** — *"What do I do here?"*
- **Mode B: Analysis / Results** — *"What did SecureMailScope find?"*
- **Mode C: Forensic Detail** — *"Show me the technical proof."*

---

## 2. Screen-by-Screen Specifications

### Screen 1: Home (Mode A — Intake)
- **Primary Question:** *"What is this tool, and what do I do here?"*
- **Primary Visual:** A focused, high-contrast hero section with headline, sub-headline, and an prominent central dropzone `[ DROP PCAP HERE / Choose capture ]` highlighting passive offline analysis with zero network traffic.
- **Secondary Information:**
  - 3-step explanation: `01 Capture` (Upload offline email packet capture) → `02 Analyze` (Protocol session reconstruction & cryptographic evaluation) → `03 Explain` (Review findings, standards, evidence, and epistemic boundaries).
  - Clean "Recent Analyses" list/table showing previous capture runs with filename, timestamp, posture score badge, and direct resume links.
  - Quick-start scenario buttons for preloaded benchmark PCAPs (`backup_weak_certificate.pcap`, `deepdive_cross_session_control_endpoint.pcap`, `scene_b_certificate_honesty.pcap`).
- **Primary Action:** `[ Choose capture ]` / Drop PCAP file into the dropzone.
- **Secondary Actions:**
  - Click on a recent investigation in the history list.
  - Click a preloaded scenario badge to load instantly.
  - View engine health badge (`TShark 4.6.8 Available`, `Backend 8001 Connected`).

---

### Screen 2: Upload / Intake Modal (Mode A — Intake)
- **Primary Question:** *"Is this the right capture file and what are its parameters?"*
- **Primary Visual:** Substantial, centered intake dialog with clean drop target, passive offline assurance notice, and file parameter verification card once selected.
- **Secondary Information:**
  - File properties upon selection: File Name, Size (bytes/KB/MB), MIME/extension verification, and SHA-256 integrity hash.
  - Strict privacy/offline notice: *"Passive offline analysis. Zero network connections are made by the analyzer."*
- **Primary Action:** `[ Analyze capture ]` button (enabled once a valid `.pcap` or `.pcapng` file is present).
- **Secondary Actions:**
  - `[ Clear / Choose different file ]`.
  - `[ Cancel / Close ]` (Escape key supported).

---

### Screen 3: Analysis State (Mode B — Results Transition)
- **Primary Question:** *"Is my capture being analyzed, and what is happening?"*
- **Primary Visual:** Calm, elegant progress animation with honest sequential states. Indeterminate pulsing indicator without fake percentages (NO `37%`, `61%`, etc.).
- **Secondary Information:**
  - Capture filename and size.
  - Real status indicators:
    - `01 Capture received` [ ✓ ]
    - `02 Analysis request sent` [ ✓ ]
    - `03 Analyzing capture with TShark engine` [ In Progress … ]
    - `04 Posture assessment ready` [ Pending ○ ]
  - Explanatory copy: *"SecureMailScope is performing passive protocol dissection and evaluating cryptographic posture against NIST and RFC baselines."*
- **Primary Action:** None (system automatically transitions to Screen 4 upon HTTP 201/200 completion).
- **Secondary Actions:** `[ Cancel analysis ]` to return safely to Home.

---

### Screen 4: Investigation Summary (Mode B — Results)
- **Primary Question:** *"What happened and what is the overall cryptographic posture?"*
- **Primary Visual:** Top-tier executive determination layout:
  - Big Posture Badge (e.g. `CRITICAL` or `STRONG`).
  - Score Waterfall: `100.0 Starting Score` → `−28.0 RSA-1024` → `−28.0 SHA-1` = `44.0 Final Posture`.
  - Primary Plain-Language Determination: *"The server presented a 1024-bit RSA certificate using a SHA-1 signature algorithm."*
- **Secondary Information:**
  - **Why This Matters:** Two confirmed cryptographic weaknesses in TLS certificate violating NIST SP 800-57 Part 1 Rev. 5 §5.6.1 and RFC 9155.
  - **What Proves It:** Frame `#6`, Stream `#0`, SMTPS `:465`.
  - **Findings Summary Cards:** Direct links to individual findings with penalty badges.
  - **Observability (Epistemic Boundaries):** 
    - *Known from capture:* Certificate key strength, signature algorithm, TLS version.
    - *Not observable:* Trust anchor (client trust store), OCSP / CRL status.
- **Primary Action:** `[ Inspect evidence ]` (jumps to the focal finding's frame/evidence context).
- **Secondary Actions:**
  - `[ Explore technical evidence ]` (transitions to Mode C forensic views).
  - Navigation between `Summary`, `Findings`, `Evidence`.
  - Header actions: `[ Export Report ]`, `[ New Analysis ]`.

---

### Screen 5: Findings (Mode B — Results)
- **Primary Question:** *"What specifically went wrong?"*
- **Primary Visual:** Structured finding list presented human-first, technical-second. Each finding displays:
  - Severity badge (`HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`).
  - Title and plain-language finding description.
  - Score penalty (e.g. `−28.0 points`).
  - Proof citation (`Frame #6, Stream #0`).
  - Standards violation (`NIST SP 800-57 Part 1 Rev. 5 §5.6.1`).
- **Secondary Information:**
  - Evidence status tag (`OBSERVED_ISSUE`, `COMPLIANT`, `INFORMATIONAL`, `AMBIGUOUS`).
  - Impact explanation detailing cryptographic vulnerability (e.g. factoring risk, collision resistance degradation).
  - Recommended remediation action.
- **Primary Action:** `[ Inspect evidence ]` on any finding to open drawer/focus view with frame data.
- **Secondary Actions:**
  - Filter findings by severity (`All`, `High`, `Medium`, `Low`, `Compliant`).
  - Toggle full technical details (`[ View technical parameters ]`).

---

### Screen 6: Evidence Inspector (Mode B / Mode C Pivot)
- **Primary Question:** *"What exact capture data proves this finding?"*
- **Primary Visual:** Split-view or focused inspector displaying the ground-truth packet frame, stream context, and dissected fields.
- **Secondary Information:**
  - Frame index, timestamp, relative time offset.
  - Protocol ladder (`Ethernet → IPv4 → TCP → TLSv1.2 → Handshake`).
  - Dissected field values (e.g. `tls.handshake.certificate`, `pkcs1.sha1WithRSAEncryption`, `rsa.key_length: 1024`).
  - Epistemic status confirmation (`EvidenceState: OBSERVED`).
  - Exact packet hex dump / payload excerpt.
- **Primary Action:** `[ View in Protocol Journey ]` (cross-links directly into Screen 7).
- **Secondary Actions:**
  - `[ Copy frame citation ]`.
  - `[ Close evidence drawer ]`.

---

### Screen 7: Protocol Journey (Mode C — Technical Forensics)
- **Primary Question:** *"How did the protocol interaction unfold over time?"*
- **Primary Visual:** A chronological narrative timeline depicting the interaction sequence:
  `TCP Connection (3-Way Handshake)` → `TLS Negotiation (ClientHello)` → `Server Certificate Exchange` → `Finding Frame (Highlighted)` → `Encrypted Session Data`.
- **Secondary Information:**
  - Frame-by-frame breakdown with protocol direction (Client → Server / Server → Client).
  - Clear visual accent on finding frame (e.g. Frame `#6` highlighted with red indicator for weak certificate).
  - Frame details on click: port numbers, TCP flags, TLS records, cipher suites.
- **Primary Action:** Click any frame in the narrative to inspect its dissected parameters.
- **Secondary Actions:**
  - Filter timeline events (`All frames`, `TLS Handshake only`, `Findings only`).
  - `[ Jump to Certificate Forensics ]`.

---

### Screen 8: Certificate Forensics (Mode C — Technical Forensics)
- **Primary Question:** *"What are the exact cryptographic properties of the presented certificate?"*
- **Primary Visual:** Clean, human-first certificate security card:
  - Key Algorithm & Size: `RSA 1024-bit` [`DISALLOWED`].
  - Signature Algorithm: `SHA-1 with RSA` [`DEPRECATED`].
  - Validity Window: `21 Sep 2026 → 21 Sep 2027` with validity indicator.
  - Subject: `CN=mail.internal.corp`.
  - Issuer: `CN=mail.internal.corp` (Self-signed).
- **Secondary Information:**
  - Progressive disclosure via `[ View technical certificate details ]`:
    - Serial Number, SKI (Subject Key Identifier), AKI (Authority Key Identifier).
    - Public key modulus hex excerpt.
    - X.509 extensions (Key Usage, Extended Key Usage, SANs).
  - Explicit Epistemic Notice: Client Trust Anchor and OCSP/CRL revocation status marked `NOT_OBSERVABLE` (cannot be evaluated from passive wire capture alone).
- **Primary Action:** `[ View technical certificate details ]` expand/collapse.
- **Secondary Actions:**
  - `[ Copy certificate fingerprint / SHA-256 ]`.
  - `[ View in Provenance ]`.

---

### Screen 9: Cross-Session Analysis (Mode C — Technical Forensics)
- **Primary Question:** *"Was this client's behavior anomalous compared to peer sessions?"*
- **Primary Visual:** Conclusion-first comparative layout:
  - Determination Banner: *"BEHAVIOURAL DEVIATION DETECTED — The subject client repeatedly omitted STARTTLS while the comparable control client negotiated TLS 1.3."*
  - Side-by-Side Endpoint Comparison:
    - **Subject (`10.0.0.6`):** 6 sessions → `CLEAR` → `CLEAR` → `CLEAR` → `CLEAR` → `CLEAR` → `CLEAR`.
    - **Control (`10.0.0.7`):** 6 sessions → `TLS 1.3` → `TLS 1.3` → `TLS 1.3` → `TLS 1.3` → `TLS 1.3` → `TLS 1.3`.
- **Secondary Information:**
  - Governing rule citation: `CS-STARTTLS-001` (`RFC 3207 §6`).
  - Quantitative deduction: `−60.0 points` downgrade penalty driving score to `22.15 / 100` (`CRITICAL`).
  - Detailed session matrix (Streams 0–5 vs Streams 6–11) accessible below the visual narrative.
- **Primary Action:** `[ Inspect subject sessions ]` / `[ Inspect control sessions ]`.
- **Secondary Actions:**
  - Select individual stream row to inspect its cleartext or TLS handshake frames.
  - Filter streams by encryption state.

---

### Screen 10: Provenance (Mode C — Technical Forensics)
- **Primary Question:** *"How does raw packet evidence transform into the final posture score?"*
- **Primary Visual:** An interactive step-by-step Provenance Chain (DAG):
  `PCAP File` → `TCP Stream #0` → `Observed Frame #6` → `Derived Certificate` → `Finding (RSA-1024)` → `Standard (NIST SP 800-57)` → `Penalty (-28 pts)` → `Final Posture (44.0)`.
- **Secondary Information:**
  - Node metadata: timestamps, hashes, frame references, mathematical formulas (`F2-group-damped`).
  - Node relationship explanations explaining epistemic transitions (e.g. `OBSERVED` frame → `DERIVED` certificate → `EVALUATED` finding).
- **Primary Action:** Click any node to highlight related upstream inputs and downstream impacts.
- **Secondary Actions:**
  - Direct deep link from a selected node to its native screen (e.g. clicking Frame `#6` jumps to Protocol Journey).

---

### Screen 11: Report Deliverable (Mode C / Export)
- **Primary Question:** *"How do I export this assessment as an authoritative deliverable?"*
- **Primary Visual:** A clean, formal executive document preview:
  - Document Header: Case Title, Investigation ID, SHA-256 Hash, Capture Date, Analyzer Version.
  - Executive Determination & Posture Gauge (`44.0 / 100 — CRITICAL`).
  - Findings Table with Standards Citations and Penalties.
  - Ground-Truth Evidence Index (Frame `#6`, Stream `#0`).
  - Formal Observability & Epistemic Boundaries Statement.
  - Cryptographic Provenance Chain Summary.
- **Secondary Information:**
  - Export action bar offering server-rendered official formats:
    - `[ Export HTML ]` (Self-contained offline briefing).
    - `[ Export PDF ]` (Printable audit report).
    - `[ Export JSON ]` (Machine-readable SIEM/NDR ingestion model).
  - SHA-256 integrity seal for forensic chain of custody.
- **Primary Action:** `[ Export HTML ]` / `[ Export PDF ]` / `[ Export JSON ]`.
- **Secondary Actions:**
  - `[ Print Document ]`.
  - `[ Return to Investigation ]`.

---

## 3. Global Navigation Hierarchy

The application header provides a calm, quiet, persistent context:

```
[ SECUREMAILSCOPE ]      Case: backup_weak_certificate.pcap   Posture: 44.0 CRITICAL
───────────────────────────────────────────────────────────────────────────────────
Home    |    Investigation:  Summary  •  Findings  •  Evidence
        |    Technical:      Protocol •  Certificate • Cross-Session • Provenance
        |    Deliverable:    Report
                                                         [ New Capture ]  [ Help ]
```

### Navigation Rules:
1. When no active case is loaded, the view defaults to **Home / Intake** (Mode A).
2. Once a capture is analyzed or selected, the top sub-nav activates with clear section grouping.
3. Every screen has a single primary question and one primary action.
4. Breadcrumbs or back-links allow instant return to `Investigation Summary` from any technical drill-down.
5. All interactive elements have descriptive IDs and ARIA labels.

---

## 4. Architectural Readiness Check
- [x] Three major user modes defined (Mode A: Intake, Mode B: Results, Mode C: Forensics).
- [x] All 11 required screens documented with primary questions, visuals, and actions.
- [x] Zero fabricated data; exact production vocabularies preserved.
- [x] Ground-truth scenarios mapped with exact mathematical deductions.
- [x] Ready to proceed to Phase 3: Vertical Slice Implementation.
