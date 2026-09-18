# context-state

**Purpose:** compact resume point. Read this + ARCHITECTURE_STATUS.md to continue without re-reading
everything. Update when context grows large or a phase completes.

---

**Current phase:** Implementation **Phase 4 (Deterministic Security Engine) — COMPLETE** on branch `phase/04-deterministic-security-engine`. Stopped for review before merge/Phase 5.

**Objective:** design system + engineering operating system; then stop for approval before any product code.

**Completed:**
- Research phases 0–2, validation passes 01A/01B/01C/01D, experiments 02A/02B (executed), 10A/10B (AI),
  requirements gate doc 19 (A-01 confirmed against official portal; deadline 30 Sep 2026).
- Architecture: docs 00–09 + requirements-traceability + ARCHITECTURE_STATUS; ADRs 0001–0011.
- Engineering OS: 11 skills + 5 agents under `.claude/`.

**Locked decisions:** tshark dissection (ADR-0001); EvidenceField + 6 states (ADR-0002/04);
session+STARTTLS engine ours (ADR-0003); versioned standards-bound rules (ADR-0004); cross-session
first-class (ADR-0005); SQLite per-run (ADR-0007); one report→3 renderers (ADR-0009); modular monolith
FastAPI (ADR-0011); AI optional/read-only/grounded, `--no-ai` identical findings (ADR-0008). Two-lane
invariant: ML never writes a fact.

**Key validated facts (do not re-derive):** cross-session −72% FP on real packets (02B); per-session
detector is inverted; TLS 1.3/resumed cert = NOT_OBSERVABLE; only 5/22 deliverables cert-dependent;
tshark recovers all raw facts (reuse it); naive per-session ML failed (10B §9) → ML must be
unsupervised over deviation features, empirically selected (05).

**Open questions (non-blocking, phase-deferred):** OQ-26,29,30,31,32,33r,36,37,38,40,41 (see
ARCHITECTURE_STATUS §4). OQ-35 (does --no-ai satisfy "AI-Assisted") → answered by shipping a real A-02.

**Changed files this phase:** `.claude/skills/*` (11), `.claude/agents/*` (5),
`docs/architecture/*` (10 docs + traceability + status), `docs/architecture/adr/*` (12),
`docs/engineering/context-state.md`, `docs/research/RESEARCH_STATUS.md` (transition marked).

**Tests run this phase:** none (architecture only). Prior experiment code in `research/experiments/`
remains reproducible (oq25, oq28, oq33, oq21_ml_test).

**Approvals received (2026-09-16):** tshark approved (deployment strategy in ADR-0001); real ML lane
required, empirical (ADR-0006); contrast = evidence-driven states, not a flag (ADR-0005); **LLM
deferred from v1** (ADR-0008); SPOC deadline is external PM, not a blocker.

**Phase 1 done:** project config (stdlib-only core), `EvidenceField` contract (frozen, forbidden
conversions structurally blocked), `Capture` metadata (streamed SHA-256), safe `TsharkAdapter`
(arg-array, exit-code map incl. empty=EMPTY, timeout/size guards), `normalize` boundary, golden
manifest (4 captures), **27 tests passing** (tshark 4.6.8). Pre-code review PASS (docs/architecture/10).

**Phase 2 done:** `analyze_capture(path) -> (AnalysisRun, [FrameEvidence])` single entry point;
capture validation boundary (NOT_FOUND / NOT_A_FILE / UNREADABLE / EMPTY_FILE / TOO_LARGE, with
EMPTY_FILE distinct from parsed-EMPTY); `AnalysisRun` contract with 8 statuses + all four versions;
streaming dissection (`-T ek` via Popen, stderr to temp file to avoid pipe deadlock); `fields.py`
isolating every tshark field name; enriched `FrameEvidence` with TLS/mail evidence, protocol stack,
implicit-TLS port evidence, and full provenance (capture_id + frame + stream + ISO timestamp);
stream identity = `capture_id:tcp_stream`. Golden manifest now 7 captures covering SMTP/IMAP/POP3/
TLS/truncation with structural expectations. **51 tests passing.**

**Phase 2 notable finds:** tshark `-T ek` renders `frame.time_epoch` as an ISO-8601 string, not a
float (parser handles both, refuses to fabricate); tshark names the POP3 layer `pop`, not `pop3`;
undrained stderr pipe was a real deadlock risk in the streaming path (fixed).

**Git:** Phase-1 checkpoint = `8e8a288`, tagged `v0.1.0-phase1`, pushed to origin/main.

**Phase 3 done:** `reconstruct_sessions(frames, capture_id) -> [SessionEvidence]`. Per-protocol
state machines (SMTP/IMAP/POP3) behind one contract (ADR-0012); declarative transition table;
endpoint roles from observed greeting, not port order; TLS completion requires hellos + app data;
implicit TLS modelled separately as `IMPLICIT_TLS` with STARTTLS fields `NOT_OBSERVABLE`;
retransmission dedupe on tcp_seq; truncation preserves progressive states without inventing
teardown. **76 tests passing**, 17 golden captures (now incl. SMTPS/IMAPS/POP3S).

**Phase 3 notable finds:** tshark truncates SMTP commands to 4 chars (`STARTTLS`→`STAR`); the SMTP
250 reply is multi-valued so `pick()[0]` silently loses the capability; the POP3 CAPA body is
reported as empty strings so STLS is only in the raw payload (bounded decoder added). Security
review found and fixed one real defect: contradictory accept+reject responses silently preferred
acceptance — now `AMBIGUOUS`.

**Key semantic preserved:** `B_strip_advert` (attack) and `I_no_support` (legitimate) yield
identical state (`AMBIGUOUS/False`) — no manufactured differentiation.

**Phase 4 done:** `SecurityAnalysisEngine` over `SessionEvidence` → `SecurityFinding[]`. 8 rules in
3 families (TLS posture, STARTTLS/STLS, cleartext exposure), registry with stable ordering and
content-derived finding ids. Three orthogonal axes — severity / evidence state / finding status —
with invariants enforced at construction (only OBSERVED_ISSUE may exceed INFO; it must cite a
standard). **114 tests passing.**

**Phase-4 evidence extension (justified, minimal):** `SessionEvidence` gained
`tls_negotiated_version` + `tls_cipher_suite`, derived in Phase 3. Version comes from the
ServerHello `supported_versions` extension first — reading legacy_version would report every TLS
1.3 session as TLS 1.2 (corpus confirms: supported=772 vs handshake=771).

**Phase-4 notable finds:** the golden-hash guard exposed that `craft.py` used a bare `Ether()`,
taking the source MAC from the host NIC — captures were never reproducible off this machine. MACs
are now pinned and generation is verified deterministic; manifest re-baselined to **v2.0** with the
reason recorded. Adversarial review found SEC-TLS-002 claiming COMPLIANT when `tls_state` said
ESTABLISHED but the transition evidence disagreed — now fails closed as AMBIGUOUS.

**Deliberately not implemented:** certificate validation (NOT_OBSERVABLE), EMS/RFC 7627,
renegotiation/RFC 5746, cipher-strength grading, any stripping conclusion.

**Next action:** review Phase 4, approve merge to `main`, then Phase 5 (cross-session reasoning).
**Do not auto-continue.**
