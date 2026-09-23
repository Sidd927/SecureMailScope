# FINAL CLAIM AUDIT

Every substantive claim that appears on a slide, with its evidence source and verification status.
**No claim may appear in `FINAL-SLIDE-CONTENT.md` unless it has a row here.**

Evidence types: **CODE** (production source) · **TEST** (automated test) · **RUN** (executed
measurement) · **REAL** (real-vendor capture) · **GEN** (generated capture/fixture) ·
**STD** (published standard) · **AUDIT** (competitor source audit) · **PS** (problem statement)

---

## Slide 1 — TITLE PAGE

| Claim | Slide | Evidence source | Type | Verified? | Safe wording |
|---|---|---|---|---|---|
| PS ID is SIH26159 | 1 | official portal record; `docs/research/19` | PS | ✅ | as-is |
| PS title, theme, category | 1 | same | PS | ✅ | verbatim from the portal |
| Team ID / Team Name | 1 | — | — | ⟨FILL⟩ | must match portal registration exactly |

## Slide 2 — IDEA TITLE

| Claim | Slide | Evidence source | Type | Verified? | Safe wording |
|---|---|---|---|---|---|
| Reads passive PCAP of SMTP/IMAP/POP3 incl. implicit TLS | 2 | `session/protocols.py`; 10 real captures | CODE+REAL | ✅ | as written |
| Produces standards-cited cryptographic posture | 2 | rule registry (11 standards) | CODE | ✅ | as written |
| No server connection, no keys, no message content | 2 | architecture: input is a file; no socket to a mail server | CODE | ✅ | as written |
| TLS 1.3 hides the certificate | 2 | RFC 8446 §2; measured 0/10 | STD+REAL | ✅ | "TLS 1.3 encrypts the Certificate message" |
| Stripped STARTTLS is byte-identical to a decline (within one session) | 2 | `docs/research/01B`; `SEC-STLS-002` returns `AMBIGUOUS` | CODE+RESEARCH | ✅ | as written |
| Cross-session compares against comparable prior sessions at the same endpoint/protocol/TLS mode | 2 | `crosssession/baseline.py` — *"prior comparable session at the same endpoint, protocol and TLS mode"* | CODE | ✅ | **must use this scoping**, not "every session" |
| Six evidence states | 2/3 | `evidence/states.py` | CODE | ✅ | exact spelling per handoff §F |
| 0 of 5 audited implementations perform cross-session reasoning | 2 | `docs/research/01D` §4 (grep + source reading of 5 repos) | AUDIT | ✅ | **scope to the five audited** — never generalise |

## Slide 3 — TECHNICAL APPROACH

| Claim | Slide | Evidence source | Type | Verified? | Safe wording |
|---|---|---|---|---|---|
| Python 3.9+ | 3 | `pyproject.toml` `requires-python = ">=3.9"` | CODE | ✅ | as-is |
| TShark/Wireshark, FastAPI, SQLite, ReportLab | 3 | `pyproject.toml` extras; `dissect/tshark.py` | CODE | ✅ | as-is |
| 0 third-party Python runtime packages in the analysis core | 3 | import-set inspection 2026-09-23 | RUN | ✅ | **must be paired with the TShark statement** |
| TShark is the required external dissection binary | 3 | `dissect/tshark.py`; version-checked, fails closed | CODE | ✅ | as written |
| Dashboard: no npm packages, no build step | 3 | no `package.json` in `dashboard/` | CODE | ✅ | as-is |
| 16 deterministic rules | 3 | `len(ALL_RULES)` = 16 | CODE | ✅ | as-is |
| 3 cross-session rules | 3 | `crosssession/rules.py` | CODE | ✅ | as-is |
| Baseline requires ≥5 prior comparable sessions | 3 | `DEFAULT_MIN_HISTORY = 5` | CODE | ✅ | as written |
| Assesses TLS version, cipher, key exchange, forward secrecy, X.509 properties, chain structure, insecure config | 3 | `SEC-TLS-*`, `SEC-KEX-001`, `SEC-FS-001`, `SEC-CERT-001..005`, `SEC-CFG-001` | CODE | ✅ | certificates: "observable properties and chain structure where the handshake exposes them" |
| Every finding cites one of 11 published standards | 3 | enumerated from rule `standards` tuples | CODE+STD | ✅ | as-is |
| ML capped at 4.0 vs 30-point tier gap; cannot create a finding | 3 | `MAX_ML_ADJUSTMENT = 4.0`; `SEVERITY_WEIGHT` INFO 0 → CRITICAL 55; `MLAnomalyResult` has no severity/status field | CODE | ✅ | as written — arithmetic invariant |
| Provenance chain | 3 (footer) | `EvidenceRef`; traced across 13 executions | CODE+RUN | ✅ | **never** "chain of custody" |

## Slide 4 — FEASIBILITY AND VIABILITY

| Claim | Slide | Evidence source | Type | Verified? | Safe wording |
|---|---|---|---|---|---|
| 1219 automated tests, 0 failures, 0 skips | 4 | 3 independent full-suite runs | TEST+RUN | ✅ | as-is; **do not** add a coverage % (never measured) |
| 10 real Postfix + Dovecot captures | 4 | `research/experiments/oq33r/out/` | REAL | ✅ | "real Postfix/Dovecot captures" |
| 3 protocols, 4 TLS modes | 4 | corpus composition: implicit TLS, STARTTLS/STLS upgrade, plaintext, declined/not-offered | REAL | ✅ | as-is |
| 115–320 ms per validated capture | 4 | measured end-to-end, cold start included | RUN | ✅ | **never** "real-time" |
| 20/20 identical repeat runs | 4 | 4 scenes × 5 runs | RUN | ✅ | as-is |
| Adding certificate analysis changed no existing verdict | 4 | Phase-11 baseline diff vs `v0.5.0-phase10`, 10/10 identical | TEST+REAL | ✅ | as-is |
| Runs without network access | 4/5 | zero network calls in `src/`; live health check | CODE+RUN | ✅ | **never** "air-gapped" |
| TLS 1.3 encrypts the certificate; 0 of 10 real captures expose one | 4 | RFC 8446 §2; measured | STD+REAL | ✅ | style as a **boundary**, not a failure rate |
| Trust needs an anchor a PCAP lacks | 4 | RFC 5280 §6; ADR-0023 | STD | ✅ | "chain structure validated; trust is not" |
| ML: 0 unique true detections on held-out data | 4 | ADR-0015, ADR-0024 | TEST | ✅ | present as an architectural boundary, not a failure |
| TShark version-checked, fails closed | 4 | `TsharkVersionError`; `tshark_min_major = 4` | CODE | ✅ | as-is |
| Certificate analysis validated on 3 generated TLS 1.2 fixtures | 4 | `research/experiments/p11cert/` | GEN | ✅ | **"GENERATED TLS 1.2 FIXTURE" label is mandatory** |
| RSA-1024 + SHA-1 → CRITICAL (44.0) | 4 (optional) | `smtps_tls12_weak_sha1_rsa1024.pcap` | GEN | ✅ | **generated fixture — must be labelled** |

## Slide 5 — IMPACT AND BENEFITS

| Claim | Slide | Evidence source | Type | Verified? | Safe wording |
|---|---|---|---|---|---|
| Audience: SOC, DFIR, IR, enterprise mail admins | 5 | PS text, `docs/research/19` §8 item 5 | PS | ✅ | as-is — PS-sourced, not invented |
| Works on evidence teams already collect | 5 | input is a standard PCAP | CODE | ✅ | as-is |
| Passive; never touches production mail servers | 5 | architectural | CODE | ✅ | as-is |
| No keys, no message content | 5 | architectural | CODE | ✅ | as-is |
| Runs without network access; no external AI service | 5 | import-set inspection; local CPU-only model | CODE+RUN | ✅ | **never** "air-gapped" |
| Every finding cites a published standard | 5 | rule registry | CODE | ✅ | as-is |
| Exports JSON / HTML / PDF | 5 | verified this phase: valid JSON, script-free HTML, extractable PDF | RUN | ✅ | as-is |
| Surfaces silent transport-security failures | 5 | rule coverage | CODE | ✅ | as-is |
| ~~Market size / ROI / user counts~~ | — | **none exists** | — | ❌ | **PROHIBITED — no verified data** |

## Slide 6 — RESEARCH AND REFERENCES

| Claim | Slide | Evidence source | Type | Verified? | Safe wording |
|---|---|---|---|---|---|
| 11 standards listed | 6 | enumerated from rule `standards` tuples | CODE+STD | ✅ | these are the standards the code actually cites |
| Research corpus (PS verification, TLS visibility, STARTTLS prior art, competitor audit, ML evaluation) | 6 | `docs/research/`, ADR-0015/0024 | RESEARCH | ✅ | as-is |

## Claims explicitly excluded from the deck

| Excluded claim | Why |
|---|---|
| "Reduces false positives by X%" | OQ-25 never closed quantitatively — **any percentage is fabricated** |
| ML accuracy / precision / recall / F1 | measured result is 0 unique true detections |
| Throughput / captures-per-hour / max PCAP size | never measured |
| Market size, ROI, mailbox counts, adoption | no verified source |
| "First" / "unique" / "only" / "revolutionary" | contradicts our own novelty audit |
| "Real-time" | batch-over-PCAP |
| "Chain of custody" / "court admissible" | not a certified legal process |
| Coverage percentage for the test suite | never measured |
| `NOT_APPLICABLE` as an evidence state | it is a `BaselineStatus`, not an `EvidenceState` |

## Audit result

**Every slide claim in `FINAL-SLIDE-CONTENT.md` maps to a row above with an evidence source and a
verified status. No unsupported claim remains.** Nine claim classes are explicitly excluded and
recorded so they cannot re-enter.
