# 22 — OQ-46 and OQ-47: Validation and Resolution

**Date:** 2026-09-20 · **Branch:** `phase/07-evidence-fusion-posture`
**Status:** Both **FIXED** · **Plan:** `21-phase-7-hardening-plan.md`
**Corpora:** `research/experiments/oq46_47/` · **Tests:** `tests/test_hardening_oq46_oq47.py`

---

## Part 1 — OQ-46: `Completeness.TRUNCATED` was unreachable

### Root cause

`session/base.py:_finalise` assigned exactly two values:

```python
if setup and closed:   COMPLETE
else:                  INCOMPLETE
```

`TRUNCATED` appeared in **no assignment anywhere in `src/`** — only in the enum and in
hand-built test fixtures. `reconstruct.py:_transport_only_session` hard-coded
`INCOMPLETE` as well. Compounding it, `reconstruct_sessions(frames, capture_id)`
received no capture-level context, so tshark's own report that the *file* was cut short
(`DissectStatus.TRUNCATED` → `RunStatus.PARTIAL`) never reached the session layer.

### Why it was a correctness defect, not a cosmetic gap

`crosssession/comparability.py:112` excludes truncated sessions from baselines
precisely because "its behaviour may be an artefact of the capture". With `TRUNCATED`
unreachable, that guard was dead code in production and truncated sessions **did** enter
baseline construction. That is a contamination path into cross-session reasoning, which
is why this was fixed rather than documented away.

### The distinction the fix had to get right

| State | Evidence |
|---|---|
| `COMPLETE` | setup observed **and** FIN/RST observed |
| `TRUNCATED` | **no teardown**, and either tshark reported the file cut mid-packet or nothing in the capture follows this stream's last frame |
| `INCOMPLETE` | everything else |

Two cases are deliberately **not** truncation:

* **A stream that went quiet while the capture continued.** Other traffic was still
  being recorded, so the recording did not stop there. Over-applying `TRUNCATED` would
  silently shrink cross-session history for no reason.
* **A late capture start** — no SYN but a real teardown. The session closed; its
  *beginning* is missing, which is a different gap in the evidence.

The second case was caught by the crafted corpus, not by reasoning: the first
implementation classified `F_missing_setup` as `TRUNCATED`. The fix now requires
"no teardown observed" as a precondition.

### Corpus and results

`research/experiments/oq46_47/oq46/` — 8 captures, real TCP with correct sequencing,
hash-pinned in `manifest.json`.

| Case | Expected | Result |
|---|---|---|
| `A_clean_teardown` | COMPLETE | ✅ |
| `B_reset_teardown` | COMPLETE | ✅ |
| `C_cut_mid_dialogue` | TRUNCATED | ✅ |
| `D_cut_during_starttls` | TRUNCATED | ✅ |
| `E_cut_during_handshake` | TRUNCATED | ✅ |
| `F_missing_setup` | INCOMPLETE | ✅ |
| `G_incomplete_exchange` | TRUNCATED | ✅ |
| `H_quiet_stream_then_more_traffic` | INCOMPLETE + COMPLETE | ✅ |

### Behavioural impact — enumerated

**2 of 60 existing captures changed.** The only possible change is
`INCOMPLETE → TRUNCATED`, because the `COMPLETE` branch was untouched.

| Capture | Change | Classification |
|---|---|---|
| `C19_truncated` | 1 session INCOMPLETE→TRUNCATED; cross-session baselines 15→14, abstentions 15→16, cross findings 45→46 | **EXPECTED-CORRECTION** — the newly-truncated session is now excluded from baselines, which is what the Phase-5 guard was written to do |
| `E_incomplete` | 1 session INCOMPLETE→TRUNCATED; no downstream change | **EXPECTED-CORRECTION** |

**Posture score and band were unchanged on every capture.**

Worth stating plainly: in `C19_truncated` only **1 of 30** sessions is truncated, even
though the generator cut all 30. That is correct. The generator cut each session's tail,
but in the resulting capture 29 of them are followed by more traffic — so the *recording*
did not stop there. Only the session owning the capture's last frame was ended by the
recording.

---

## Part 2 — OQ-47: segmented multi-line `250-` lost `STARTTLS`

### Root cause — measured, and not what Phase 6 recorded

Phase 6 recorded this as "tshark reports two capability responses and Phase 3 evaluates
them independently". Direct inspection of `B01_all_upgrade` found **three** layers, two
of them worse than that description.

**Mode A — the token is cut and the remainder is dropped** (stream 38, frames 731/732):

```
frame 731  params [..., 'PIPELINING', 'STARTTL']
frame 732  params ['AUTH PLAIN LOGIN', 'CHUNKING', 'HELP']
```

tshark splits `STARTTLS` into `STARTTL` and **drops the trailing `S` from its structured
output entirely**. No substring match can recover it.

**Mode B — a mid-line split invents a response code** (stream 11, frames 212/213):

```
frame 212  code 250  params ['mx1.corp.internal Hello client', 'SIZE 5']
frame 213  code 242  params ['800', '8BITMIME', 'PIPELINING', 'STARTTLS', ...]
```

The split falls inside `52428800`, and tshark parses the continuation as a fresh `242`
response. `STARTTLS` **is** in frame 213's parameters, but the extractor only scanned
parameters when the code began `250`, so it never looked.

**Mode C — we threw the bytes away ourselves.** `normalize.py` retained `tcp.payload`
only when `app_proto is not None`. When a segment is out of order or split mid-line,
tshark cannot attribute it to SMTP and its protocol stack degrades to plain `tcp` — so
our own normalizer discarded the frame's payload, which sometimes held the **only** copy
of the capability line. This was the deepest layer and was invisible until the
many-segment and reordered scenarios were built.

### Ruled out first: tshark preferences

Re-ran with `-o tcp.desegment_tcp_streams:TRUE -o smtp.desegment_lines:TRUE`. Output is
**byte-identical** to the default. tshark's SMTP dissector does not reassemble a reply
split mid-line, so the fix could not live in the invocation.

### The fix

> **Same valid byte stream → same semantic reconstruction.** Not "recognise more
> strings".

Making the code-gate permissive would have fixed Mode B, still failed Mode A, and
invited false advertisements from unrelated responses. Instead the capability line is
re-read from the **reassembled server→client payload** of the EHLO response — the same
remedy the Phase-2 POP3 CAPA defect required when tshark exposed that body as empty
strings.

Constraints honoured:
- reassembly by **TCP sequence**, not arrival order;
- retransmissions collapsed on sequence number;
- matched as a **whole token on a `250-`/`250 ` continuation line** (`^250[- ]STARTTLS\s*$`);
- the scan window is bounded to **between EHLO and the next client command**, so message
  content can never reach it;
- provenance names the frames that actually carried the bytes;
- absence in the reassembled stream still yields `AMBIGUOUS` — never an invented
  advertisement.

### Corpus and results

`research/experiments/oq46_47/oq47/` — 14 captures. Every segmented case has an
unsegmented twin carrying identical application bytes, so the equivalence property is
asserted directly rather than inferred.

| Case | Expected | Result |
|---|---|---|
| `A_whole_in_one_segment` | True / OBSERVED | ✅ reference |
| `B_split_before_capability` | True / OBSERVED | ✅ |
| `C_split_inside_token` | True / OBSERVED | ✅ mode A |
| `D_split_before_final_letter` | True / OBSERVED | ✅ mode A |
| `E_split_between_cr_and_lf` | True / OBSERVED | ✅ |
| `F_split_many_segments` | True / OBSERVED | ✅ mode C |
| `G_split_mid_numeric` | True / OBSERVED | ✅ mode B |
| `H_retransmitted_segment` | True / OBSERVED | ✅ |
| `I_reordered_segments` | True / OBSERVED | ✅ mode C |
| `J_absent_whole` | False / AMBIGUOUS | ✅ |
| `K_absent_split` | False / AMBIGUOUS | ✅ |
| `L_advertised_never_used` | True / OBSERVED | ✅ |
| `M_server_refuses` | True / OBSERVED | ✅ |
| `N_forged_capability_in_message_body` | **False / AMBIGUOUS** | ✅ security property |

`K` and `N` are the tests that a permissive fix would fail: `K` asserts absence survives
segmentation, and `N` writes `250-STARTTLS` into a DATA body and asserts it is **not**
read as an advertisement.

### Behavioural impact — enumerated

**6 of 60 existing captures changed**, all in generator B — the only corpus with random
segmentation. Generators A and C never split a capability reply, and neither did the
real-vendor corpus.

| Capture | Change | Classification |
|---|---|---|
| `B01_all_upgrade` | score 88.0 → **100.0**, band ADEQUATE → **STRONG**, spurious `STARTTLS_BEHAVIOUR_DEVIATION` removed, findings 162 → 160 | **EXPECTED-CORRECTION.** Ground truth: every session legitimately advertises and upgrades. The deviation existed *only* because two sessions falsely appeared not to advertise — a false positive, now gone |
| `B06_strip_command` | score 14.78 → **26.78**, spurious deviation removed; **both genuine attack findings unchanged** (`PLAINTEXT_AUTH_EXPOSURE` HIGH ×10, `NO_TLS_PROTECTION` MEDIUM ×10) | **EXPECTED-CORRECTION.** The real detections survive; only the segmentation artifact went away |
| `B07_failed_upgrade` | coverage assessed 20 → 25 | **EXPECTED-CORRECTION** — five sessions now yield a conclusion instead of abstaining |
| `B04`, `B09`, `B16` | fewer redundant findings; assessment id | **EXPECTED-CORRECTION** |

**No genuine detection was lost, and no score moved in the wrong direction.**

### One test expectation updated

`tests/test_session_reconstruction.py::test_truncation_preserves_observations_without_inventing_final_state`
asserted every session in `E_incomplete` was `INCOMPLETE` — true only because
`TRUNCATED` was unreachable. It now asserts the session is **not COMPLETE** and,
additionally, that **exactly one** session is truncated and it is the one owning the
capture's last frame. The reason is recorded inline. The test was strengthened, not
relaxed; no other expectation was touched.

---

## Reproduction

```bash
python3 research/experiments/oq46_47/craft_hardening.py
PYTHONPATH=src python3 -m pytest tests/test_hardening_oq46_oq47.py -q
```
