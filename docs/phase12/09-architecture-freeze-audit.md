# Phase 12 — 09. Architecture freeze audit

**Method:** measured directly — `git diff --stat v0.5.0-phase10^{commit} v0.6.0-phase11^{commit} --
src/` shows exactly 17 files touched by the entire Phase-11 requirement-closure effort. Everything
not in that list has been untouched since its originating phase, some for as long as 8 phases.
That is direct, dated evidence of stability, not an opinion about it.

---

## 1. Stability classification

| Component | Classification | Evidence |
|---|---|---|
| `evidence/states.py` (six-state model, `Provenance`) | **stable, structurally frozen** | untouched by Phase 11 (confirmed by the diff above); a dedicated test (`test_evidence_contract_is_untouched`) fails the build if any future change touches it without updating the guard itself |
| `session/` (protocol state machines) | **stable, extended carefully** | Phase 11 added two new fields and one shared derivation method (`_apply_crypto`) without altering any Phase-3 STARTTLS/plaintext logic; the Phase-7 freeze guard (re-pointed in Phase 11 to an explicit ADR-linked allowlist) caught and required justification for every touched line |
| `analysis/` (deterministic rules) | **stable core, actively growing edge** | 8 pre-Phase-11 rules untouched in substance; `SEC-TLS-003` was the one rule *narrowed* (not deleted) because its own limitation text became false — a correct, deliberate, ADR-recorded change, not drift |
| `crosssession/` | **stable, dormant since Phase 5** | zero touches across Phases 6–11; 3 rules, well-tested, but genuinely under-exercised against real traffic (the real corpus has too few same-server sessions to trigger baselines — a corpus limitation, not a code fragility) |
| `ml/` | **stable, deliberately inert** | zero touches by Phase 11, and a dedicated test now enforces that structurally (`test_ml_lane_is_untouched_by_phase_eleven`); "stable" here specifically means correctly bounded and non-participating, which is the safest possible state for a component with zero demonstrated detection value |
| `posture/scoring.py`, `posture/prioritise.py`, `posture/remediation.py`, `posture/fusion.py` | **stable, untouched by Phase 11** | only `posture/model.py` changed (new `IssueClass` members, version bumps) — the scoring formula, the prioritisation factors, and the remediation templates are byte-identical to Phase 10 |
| `backend/` | **stable, zero source changes since Phase 8** | Phase 11 required no backend code change at all — the API surfaces new findings automatically because it never re-implements posture logic, only serves the canonical document |
| `reporting/` | **stable, zero source changes since Phase 9** | same property — HTML/PDF/JSON rendering needed no change to surface Phase-11 certificate findings |
| `dashboard/` | **stable, zero source changes since Phase 10** | same property — the four-screen console needed no change either |
| `crypto/` (suites, oids, keyexchange, certificates) | **newest, most-tested-per-line, least field-validated** | 2023 lines added in one phase; 97 dedicated adversarial tests; but real-world validation rests on 3 generated TLS 1.2 fixtures, because the entire real corpus is TLS 1.3 and cannot exercise it — see §2 |
| Test suite (1219 tests) | **stable, and itself the primary stability mechanism** | three independent full-suite runs this phase, all 1219/0/0/0; the one historically nondeterministic test was fixed in the Phase-11 release-hygiene commit with zero production-code change |

## 2. The one genuinely fragile area, named precisely

`crypto/certificates.py`'s **attribution logic** — the rule that decides which extracted field
belongs to which certificate in a multi-certificate chain. This is the single place in the entire
codebase where three real defects were found and fixed *during* Phase 11 itself (subject/issuer
fabrication from misread DN components, SAN entries mis-paired by coincidental array-length match,
and a count-anchor field that is `null` for exactly the common single-certificate case). All three
are now fixed, tested, and guarded by regression tests naming the exact defect. That is a genuine
strength — the defects were caught before release, not after — but it also means this is the part
of the system with the **least margin for a future undiscovered edge case**, because it parses a
flattened wire format (tshark `-T ek`) that was never designed to express per-certificate
attribution, and the only real-world corpus available to validate it is three generated fixtures.

**Recommendation carried into §13: do not extend chain-attribution logic without generating and
measuring against a new real multi-certificate fixture first** — extending it against assumption,
the way the three original defects were introduced, is exactly the failure mode already observed
once in this codebase.

## 3. Components that must NOT be touched before the deadline

| Component | Why not |
|---|---|
| `posture/scoring.py` (the `F2-group-damped` formula and its weights) | selected over two alternatives against a 60-capture calibration set (ADR-0016); any change requires re-running that calibration, which is not feasible in the remaining 8 days, and would silently change the meaning of every historical score |
| Any existing `IssueClass` enum member name | renaming breaks fusion identity for every assessment recorded before the rename — `DEPRECATED_TLS_VERSION`'s cosmetic naming wart (doc 07 §4) is deliberately left as-is for exactly this reason |
| `MAX_ML_ADJUSTMENT` / the ML boundary generally | the entire ADR-0015/0024 defensibility rests on this bound being immovable; loosening it "to let the model show more value" would be the exact overclaim this project's own discipline exists to prevent |
| `evidence/states.py` | already structurally frozen by its own guard test; any change here ripples through all nineteen rules |
| certificate attribution logic in `crypto/certificates.py` | see §2 |

## 4. Overall freeze readiness

**The architecture is mature enough to freeze.** Nine of thirteen major components have had zero
source changes for at least one full phase, several for many; the two components that did change
in Phase 11 (`analysis/`, `crypto/`) did so with unusually high test density (97 dedicated tests
for 2023 new lines) and did not require any change at all in the four downstream layers
(`backend/`, `reporting/`, `dashboard/`, `posture/scoring`), which is itself strong evidence the
layering discipline held. This finding feeds directly into the `FREEZE` recommendation in
`13-final-engineering-decision.md`.
