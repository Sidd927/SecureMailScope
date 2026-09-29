# Finalization — 06. Cross-session reasoning, judge-visible

**Everything below is real engine output**, produced this phase by running
`CrossSessionEngine().analyse()` directly against two captures already in the golden corpus
(`research/experiments/oq28/pcaps/G_control_endpoint.pcap`,
`.../H_no_control.pcap`) — not paraphrased, not constructed for illustration. Both captures
contain enough sessions (12 and 6 respectively, all to the same server) to actually exercise the
≥5-session baseline requirement live, which `docs/finalization/00-start-state-audit.md` §4
correctly flagged the real 10-capture OQ-33r corpus as too small to do.

**This closes the gap Phase 12 identified** ("the cross-session deep-dive has no staged
real-world fixture") — not with a new fixture, but by discovering the golden corpus already
contains exactly what was needed, previously undemonstrated.

---

## 1. The positive case — a control endpoint exists

**Capture:** `G_control_endpoint.pcap` — 12 SMTP sessions to `10.0.0.80:587`.

**SESSION A–E (the client under scrutiny), observed behaviour:** 5 sessions, all from the same
client identity, none of them upgrades to TLS — `STARTTLS_ADVERTISED: false` in every one.

**BASELINE for this client:** self-consistent. Taken alone, 5-for-5 "no upgrade" looks like
nothing more than a client that doesn't support STARTTLS — there is no *internal* inconsistency
to flag.

**CONTROL ENDPOINT:** 6 *other* sessions at the *same server*, all of them successfully
upgrading to TLS. This is the control — direct evidence that the server itself offers and
completes the upgrade for other clients.

**DEVIATION, session 6 of the client under scrutiny — real engine output, verbatim:**

> **Conclusion:** *"This endpoint consistently lacks the upgrade capability while comparable
> endpoints at the same server consistently have it."*
>
> **Explanation:** *"This client's own history is self-consistent (5 prior sessions all 'false'),
> so its behaviour alone looks unremarkable. However 6 comparable session(s) from other clients
> at the same server did upgrade successfully. A ca[pability difference exists]..."*
>
> **Status:** `OBSERVED_ISSUE` · **Severity:** `MEDIUM` · **Rule:** `CS-STARTTLS-001`

**CONCLUSION the evidence supports:** a capability or configuration difference between this
client's connections and every other observed client's connections to the same server — worth an
analyst's attention.

**LIMITATION, stated by the engine itself, in the same finding:**

> *"Passive PCAP evidence alone cannot distinguish a consistently legitimate plaintext
> configuration from a consistently stripped STARTTLS configuration when no unaffected comparable
> control endpoint or other differentiating evidence exists. Per-client server policy and
> interference are indistinguishable here."*

**What is never said:** *"we detected the attacker."* The finding is deliberately phrased as a
**deviation** — *"consistently lacks the upgrade capability while comparable endpoints... have
it"* — not as an attack claim, exactly per the brief's required phrasing discipline.

## 2. The negative case — no control endpoint exists

**Capture:** `H_no_control.pcap` — 6 SMTP sessions, all to the same server, **no other client
observed at all.**

**SESSION A–E:** 5 sessions, all `STARTTLS_ADVERTISED: false`.

**BASELINE:** self-consistent, 5-for-5.

**CONTROL ENDPOINT: none.** This is the entire point of this capture's name and design — every
session in it is the same client, so there is no independent second signal to check against.

**SESSION F — real engine output, verbatim:**

> **Conclusion:** *"Advertisement behaviour matches the established baseline."*
>
> **Explanation:** *"All 5 prior comparable sessions showed 'false' and this session agrees. No
> comparable control endpoint was available to corroborate this from a second angle."*
>
> **Status:** `COMPLIANT` · **Severity:** `INFO` · **Rule:** `CS-STARTTLS-001`
>
> **Limitation:** *"Passive PCAP evidence alone cannot distinguish a consistently legitimate
> plaintext configuration from a consistently stripped STARTTLS configuration when no unaffected
> comparable control endpoint or other differentiating evidence exists."*

**This is the honest negative case the brief explicitly asks to demonstrate, not hide.** A server
that never offers STARTTLS to *any* observed client, and an attacker that strips STARTTLS from
*every* session at that server with total consistency, are **passively indistinguishable** — the
capture shows the same bytes either way. The engine's own output says this, unprompted, in the
same sentence as its `COMPLIANT` verdict, rather than reporting a false sense of security.

## 3. Why this is a feature, not a gap

A tool that claimed certainty here would be lying. A tool that stayed silent about the limitation
would be hiding a real gap in what the evidence can establish. SecureMailScope's cross-session
engine does neither: it reports `COMPLIANT` (the observed behaviour is internally consistent) and
states, in the same finding, exactly what that verdict does and does not prove. This is the same
discipline documented system-wide in `docs/phase12/07-forensic-honesty-audit.md`, demonstrated
here with real evidence from a capture built specifically to exercise it.

## 4. Now staged in the demo bundle

Both captures are symlinked into `demo/captures/` as
`deepdive_cross_session_control_endpoint.pcap` (→ `G_control_endpoint.pcap`) and
`deepdive_cross_session_no_control.pcap` (→ `H_no_control.pcap`), the same pattern used for every
other scene. The Phase-12 "no staged fixture for this deep-dive" gap is closed:

```bash
bash demo/commands/run_scene.sh deepdive_cross_session_control_endpoint
bash demo/commands/run_scene.sh deepdive_cross_session_no_control
```

both run end to end through the real pipeline. Note these two scenes surface their most
interesting evidence in the **cross-session findings**, which `run_scene.sh` does not print by
default (it prints top-level posture/score only) — for the live demo, drive these two through the
dashboard's Findings screen instead, where the `CS-STARTTLS-001` conclusion, explanation, and
limitation text shown in §1–2 above are all visible.
