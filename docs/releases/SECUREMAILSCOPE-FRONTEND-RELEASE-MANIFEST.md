# SecureMailScope Frontend Release Manifest

| Field | Release Value |
|---|---|
| **Release Identifier** | `SecureMailScope-Frontend-v1.0.1` |
| **Branch** | `frontend/final-polish` |
| **Implementation Commit SHA** | `b2cbbae4010c54798b97d18e70c69149788a0cbb` |
| **Release Documentation Tag** | `frontend-v1.0.1` |
| **Implementation Tag** | `frontend-v1.0.0` |
| **Safety Checkpoint** | `frontend/pre-final-polish` (`60fe4ae`) |
| **Validation Date** | September 28, 2026 |
| **Build Status** | **PASSED** (`vite v8.3.1` built in 176ms, 0 errors) |
| **Lint Status** | **PASSED** (`oxlint` 0 errors, 9 non-blocking warnings on 75 files) |
| **Backend Drift** | **NONE** (0 lines modified in `securemailscope/`, `tests/`, `research/`) |
| **Frontend Files Changed** | 47 files (+5,676 / −967) strictly in `frontend/`, `demo/`, and root `.gitignore` |

---

## Golden Cases Validation Summary

- **Case A (`backup_weak_certificate.pcap`):** `CRITICAL 44.0 / 100`, RSA 1024, SHA-1, Frame #6, Stream #0, NIST SP 800-57 §5.6.1 disallowed key.
- **Case B (`deepdive_cross_session_control_endpoint.pcap`):** `CRITICAL 22.15 / 100`, 12 sessions, Subject `10.0.0.6` vs Control `10.0.0.7`, Frame #7 & #56 (`CS-STARTTLS-001`).
- **Case C (`scene_b_certificate_honesty.pcap`):** `STRONG 100 / 100`, TLS 1.3 negotiated, Certificate extraction `NOT_OBSERVABLE` (RFC 8446).

---

## Validated Screenshots Directory

All 11 screenshots reside in `docs/releases/screenshots/` and `demo/phase1d/`:
1. `01-home.png` (1440 × 900)
2. `02-case-b-overview.png` (1440 × 900)
3. `03-case-b-findings.png` (1440 × 900)
4. `04-case-b-protocol.png` (1440 × 900)
5. `05-case-b-cross-session.png` (1440 × 900)
6. `06-case-b-provenance.png` (1440 × 900)
7. `07-case-b-report.png` (1440 × 900)
8. `08-case-a-certs.png` (1440 × 900)
9. `09-case-c-certs.png` (1440 × 900)
10. `10-responsive-768.png` (768 × 1024)
11. `11-mobile-375.png` (375 × 812)

---

## Known Limitations

1. **Large PCAP Virtualization:** PCAPs exceeding 10,000 frames render in an unvirtualized scroll container.
2. **Browser Print Rendering:** On-screen report print depends on browser `@media print` engine.
