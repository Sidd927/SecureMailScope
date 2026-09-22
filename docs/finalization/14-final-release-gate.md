# Finalization — 14. Final release gate

---

## TESTS

Full suite (`PYTHONPATH=src python3 -m pytest -q`), run **3 independent times** this phase.

| Run | Result |
|---|---|
| 1 | `1219 passed in 62.82s` |
| 2 | `1219 passed in 63.87s` |
| 3 (with `-rs`, skip reasons shown) | `1219 passed in 66.07s` — zero skip lines printed |

## RESULT

**PASS**, all three runs, identical count every time.

## COUNT

1219 collected, 1219 passed.

## FAILURES

0, in any of the three runs.

## SKIPS

0, in any of the three runs (`-rs` would have printed any skip with its reason; none appeared).

## ENVIRONMENT

Python 3.9.6 · tshark 4.6.8 (Wireshark) · macOS-26.6.2-arm64 · zero third-party runtime
dependencies in the core (`docs/finalization/00-start-state-audit.md` §1–2).

## GIT COMMIT

`aceea0248ad3bba5b3faa163dc5a1ee20d87bc39` (branch `phase/finalization`) at the time this document
was drafted; superseded by the final commit reported in the closing summary once this document and
`15-final-project-status.md` are committed.

## RELEASE BASE

`v0.6.0-phase11` = `c5352de3b59690bbe3f3192468c9651d10b7dc54`. **Zero production drift**:
`git diff --stat v0.6.0-phase11^{}..HEAD -- src/` is empty. All work this phase and Phase 12 landed
in `docs/`, `demo/`, and `README.md` only — 70 files changed outside `src/`, 0 inside it.

All six immutable references re-verified this phase, unchanged:

| Ref | Commit |
|---|---|
| `main` | `2fd5f0939c6773ba110cbe39e10a86bff2deaca3` |
| `v0.1.0-phase1` | `8e8a2881ea05a787567b4726c1f72f39b2b8eba6` |
| `v0.2.0-phase7` | `9b3e6e496d81d72076821bfbe5f2596178b9a484` |
| `v0.3.0-phase8` | `a46781a653ed50b79ebf7a343ea3f32e0990e7bf` |
| `v0.4.0-phase9` | `0019c6f8919318b625f2430b5abadaa66fdf9b68` |
| `v0.5.0-phase10` | `f8cbc0e3297ecca947a8ab08061e90056cb28cc6` |
| `v0.6.0-phase11` | `c5352de3b59690bbe3f3192468c9651d10b7dc54` |

No new tag created — confirmed `git tag -l "v0.7*"` returns nothing, matching the explicit
instruction not to tag during this phase.

## DEMO STATUS

**PASS.** `demo/` built and verified this phase:

- 9 captures staged (7 original scenes + 2 cross-session deep-dive discoveries), all as symlinks
  into the existing research corpus, confirmed committed as git symlinks (mode `120000`), not
  file copies.
- 4 core scenes each executed **5 times independently** — 20/20 successes, stable results
  (`docs/finalization/03-demo-rehearsal.md`).
- One full real-HTTP round trip (upload → assessment → dashboard → JSON/HTML/PDF reports)
  succeeded against the actual running backend server.
- `demo/commands/preflight.sh` written and tested live — ran clean.
- One real discrepancy found during rehearsal (an API response-nesting question, not a defect),
  investigated to root cause, and closed by documentation.

## DOCUMENTATION STATUS

**PASS.** README's checkout instructions, capability description, TLS-1.3 certificate-visibility
paragraph, AI/ML claim precision, and status section all corrected with full BEFORE/AFTER/RATIONALE
in `docs/finalization/01-documentation-audit.md`. Two secondary navigation documents
(`ARCHITECTURE_STATUS.md`, `CLAUDE_CONTINUATION_CONTEXT.md`) header-corrected with pointers to the
authoritative current status.

## KNOWN LIMITATIONS

Carried forward, not newly discovered, and none blocking:

- **D-11** (certificate chain validation): PARTIAL — chain structure validated; trust and
  revocation not observable from passive PCAP alone. Reasons re-confirmed, not re-argued, in
  `docs/finalization/08-open-requirements.md`.
- **A-02** (AI-assisted anomaly detection): PARTIAL — real, evaluated, unsupervised model; zero
  demonstrated detection value on any corpus this project holds.
- No pre-existing screenshots exist in `demo/screenshots/` — needs a live browser session,
  explicitly recorded as a gap rather than silently left empty (`docs/finalization/02-demo-bundle-audit.md` §4).
- The real 10-capture corpus is 100% TLS 1.3 and cannot exercise the certificate-extraction family
  at all; that family is validated only against 3 generated fixtures (`docs/finalization/04-real-pcap-evidence-pack.md` §3).
- `main` remains frozen at Phase 3 by deliberate process choice — mitigated by documentation
  (README's new checkout callout), not by touching `main`.

## RELEASE-BLOCKING ISSUES

**None.**

## REMAINING NON-BLOCKING FUTURE WORK

- `demo/screenshots/` population (needs a live browser session)
- D-11 operator-supplied trust anchors — reserved, scoped in full in `docs/phase12/14-proposed-next-phase.md`, contingent on Grand Finale advancement
- EC certificate fixtures, OCSP stapling measurement (OQ-59) — small, deferred, reasons stated in `docs/finalization/08-open-requirements.md`
- The actual slide deck / PowerPoint build-out from `docs/finalization/09-presentation-evidence.md`

## GATE VERDICT

**PASS.** No release-blocking issue is outstanding.
