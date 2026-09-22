# Finalization — 12. Offline demo audit

**Verified this phase, not merely inherited from Phase 12:** zero code path in `src/securemailscope/`
makes a network call. Confirmed by module-import-set inspection (`docs/phase12/00-release-state-audit.md`
§2, re-confirmed unchanged by `git diff --stat -- src/` showing zero drift since that measurement)
and by a **live** health-check this phase (`curl` against the actual running backend, §5 of
`docs/finalization/11-deployment-runbook.md`) that succeeded without any network reachability
requirement.

---

## 1. Dependency-by-dependency check

| Dependency | Present? | External network required? |
|---|---|---|
| Internet | not required at all | — |
| External APIs | none exist | — |
| LLM APIs | none exist — there is no LLM anywhere in this system | — |
| Cloud inference | none — the ML lane is a local, unsupervised, CPU-only model | — |
| Remote model downloads | none — the model is fitted from governed features at analysis time, not downloaded | — |
| External DNS | not used — the backend binds to `127.0.0.1` by IP, no hostname resolution in the analysis path | — |
| External GitHub services | not used at runtime — Git is only used to check out the repository, not by the running application | — |
| tshark | **yes, hard dependency** | tshark itself is a local binary; no tshark feature this project relies on requires network access (no live capture is performed — only `-r <file>` static reads) |

**tshark is confirmed as the single external runtime dependency**, and it operates entirely
locally against a file already on disk — never against a live interface or a network resource.

## 2. Preflight script

Per the brief's explicit permission to add a small, low-risk preflight check: `demo/commands/preflight.sh`
was written and tested this phase. It checks exactly the failure points already identified across
this finalization phase's other documents — nothing speculative:

- Python version (≥ 3.9)
- tshark presence and version string
- the checkout is on or after `v0.6.0-phase11` (`git merge-base --is-ancestor`)
- every capture referenced in `demo/captures/` exists and is non-empty
- write permission to the data directory
- whether port 8000 is already in use (a warning, not a blocker — `--port` is trivial to change)
- whether the optional backend and PDF-reporting extras are importable

**Tested live this phase:** ran clean, all checks `OK`, one accurate `WARN` (an unrelated local
SSH port forward already using port 8000, correctly detected and correctly treated as a warning
rather than a failure since the fix is a one-flag change).

**Deliberately not built:** anything beyond this — no dependency-version pinning enforcement, no
automatic remediation, no network reachability probe (there is nothing to reach). The brief
explicitly warns against overengineering this, and the six checks above are exactly the six
things this finalization phase found could plausibly go wrong on a fresh machine.

## 3. Conclusion

**The demo can run fully offline, verified by direct execution rather than by architectural
inference alone.** The only action item is environmental (confirm tshark's version on the actual
demo machine ahead of time, per `demo/RUNBOOK.md` §1) — not a code or dependency gap.
