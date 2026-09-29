# 21 — Phase 7 Hardening Plan

**Date:** 2026-09-20 · **Branch:** `phase/07-evidence-fusion-posture` from `e9de38f`
**Status:** Plan, written before implementation. Baseline: 381 tests passing, tree clean.

---

## 1. OQ-46 — `Completeness.TRUNCATED` is unreachable

### Root cause (confirmed by inspection, not assumed)

`session/base.py:_finalise` assigns exactly two values:

```python
if setup and closed:   session.completeness = Completeness.COMPLETE
else:                  session.completeness = Completeness.INCOMPLETE
```

where `setup` = SYN and SYN-ACK observed, `closed` = FIN or RST observed
(`grouping.py:transport_flags`). `TRUNCATED` appears in no assignment anywhere in
`src/`. `reconstruct.py:_transport_only_session` likewise hard-codes `INCOMPLETE`.

Compounding it: `reconstruct_sessions(frames, capture_id)` receives no capture-level
context, so even the information that tshark reported the *file* as cut short
(`DissectStatus.TRUNCATED` → `RunStatus.PARTIAL`, `pipeline.py:103`) never reaches the
session layer.

### Consequence

The Phase-5 guard at `crosssession/comparability.py:112` — which excludes truncated
sessions from baselines precisely because "its behaviour may be an artefact of the
capture" — is dead code in production. Truncated sessions therefore **do** enter
baseline construction. This is a real contamination path, not a cosmetic gap, so it is
**fixed**, not documented away.

### What distinguishes the states

| State | Evidence |
|---|---|
| `COMPLETE` | setup observed **and** FIN/RST observed |
| `TRUNCATED` | no teardown **and** the capture itself stopped while this session was still open |
| `INCOMPLETE` | any other missing boundary (no setup, or the stream simply went quiet while the capture continued) |

Two independent signals establish "the capture stopped while this session was open",
both derivable from evidence already present:

1. **Capture-level**: tshark reported the file truncated (exit 14). Every still-open
   session is then truncated by the file, whatever its position.
2. **Session-at-capture-end**: the session's last frame *is* the capture's last frame
   and no teardown was seen. Nothing came after it, so the recording ended mid-session.

A stream with no teardown whose last frame is followed by other traffic is **not**
capture truncation — the capture kept running, so the gap has another cause. It stays
`INCOMPLETE`. This distinction is the point of the fix and is asserted by test.

Normal teardown can never be misread as truncation because `closed` is checked first.

### Minimal change

- `StreamGroup` gains `capture_last_frame`, set once by `group_streams`.
- `reconstruct_sessions(..., capture_truncated: bool = False)` — defaulted, so every
  existing caller keeps working.
- `_finalise` and `_transport_only_session` consult both signals.

### Expected output change

Sessions that were `INCOMPLETE` **and** sit at the capture's end become `TRUNCATED`.
This changes Phase-3 output, Phase-5 comparability and Phase-7 coverage on affected
captures. Every change will be enumerated and classified before any expectation is
updated.

---

## 2. OQ-47 — segmented multi-line SMTP `250-` can lose `STARTTLS`

### Root cause (measured, and *not* what Phase 6 assumed)

Phase 6 recorded this as "tshark reports two capability responses and Phase 3 evaluates
them independently". Direct inspection of `B01_all_upgrade` shows two distinct and worse
failure modes:

**Mode A — token split across segments** (stream 38, frames 731/732):

```
frame 731  params [... 'PIPELINING', 'STARTTL']
frame 732  params ['AUTH PLAIN LOGIN', 'CHUNKING', 'HELP']
```

tshark splits `STARTTLS` into `STARTTL` and **drops the trailing `S`** from its
structured output entirely. No substring match can recover it.

**Mode B — mid-line split invents a bogus response code** (stream 11, frames 212/213):

```
frame 212  code 250  params ['mx1.corp.internal Hello client', 'SIZE 5']
frame 213  code 242  params ['800', '8BITMIME', 'PIPELINING', 'STARTTLS', ...]
```

The split falls inside `52428800`; tshark parses the continuation as a fresh `242`
response. `STARTTLS` **is** present in frame 213's parameters, but our extractor only
scans parameters when `code.startswith("250")`, so it never looks.

### Ruled out: tshark preferences

Re-ran with `-o tcp.desegment_tcp_streams:TRUE -o smtp.desegment_lines:TRUE`. Output is
**byte-identical** to the default. tshark's SMTP dissector does not reassemble a reply
split mid-line, so the fix cannot live in the invocation.

### The fix, and what it must not be

> The goal is **same valid byte stream → same semantic reconstruction**, not "recognise
> more strings".

Making the code-gate permissive (Mode B) would still fail Mode A, and would invite false
advertisements from unrelated response codes. Instead: reassemble the server→client
application bytes for the capability exchange and read the capability lines from the
reassembled stream.

`FrameEvidence.payload_text` already carries the raw payload, bounded by
`decode_payload`, and the two frames above contain the complete `250-STARTTLS` line
between them. There is direct precedent: the Phase-2 POP3 defect was fixed the same way
when tshark exposed `pop_response_data` as empty strings.

Constraints the fix must honour:
- reassemble by **TCP sequence**, not arrival order;
- collapse retransmissions (same seq) rather than double-count;
- match `STARTTLS` as a **whole token on a `250-`/`250 ` continuation line**, never as a
  loose substring;
- record provenance: the resulting evidence must name the frames it was reassembled
  from, and `INFERRED` rather than `OBSERVED` is not appropriate here — the bytes were
  observed, only tshark's structuring of them was lossy;
- never invent an advertisement: absence in the reassembled stream stays `AMBIGUOUS`.

---

## 3. OQ-33r — real-world validation

### Environment assessment (measured)

| Capability | Status |
|---|---|
| Live packet capture on the host | ❌ `/dev/bpf0` is root-only; no sudo |
| Docker | ✅ via a **pre-existing** Colima VM (not started by this work) |
| Network for image pulls | ✅ |
| Host Postfix / Sendmail binaries | present, but running them needs root and mutates the host |

### Approach

Real vendor traffic inside a container, captured by `tcpdump` on the container's
loopback. Three **independent vendor codebases** — Postfix (SMTP), Dovecot (IMAP/POP3),
Exim (SMTP) — driven by Python's own `smtplib`/`imaplib`/`poplib` clients. The
application bytes are then produced by real server software rather than by our
generators, which is exactly the gap OQ-33r names.

Safety: disposable container, throwaway accounts, synthetic message content, local test
certificates, no real mail and no personal data. Containers are removed afterwards; the
user's existing images are untouched.

### Honest expectation

This is **not** full multi-vendor production validation. It gives real server dialects
and real packetisation for SMTP/IMAP/POP3 over a loopback link. It does not give WAN
path effects, real client diversity, or production TLS configurations. The verdict will
be classified `PASS` / `PASS WITH LIMITATIONS` / `BLOCKED` on the evidence obtained, and
anything unattempted will be named.

---

## 4. Sequencing

1. OQ-46 fix + regression tests (9 scenarios from the brief).
2. OQ-47 fix + regression tests, including segmented ≡ unsegmented equivalence.
3. Golden/corpus diff: enumerate and classify **every** changed output before updating
   any expectation.
4. OQ-33r corpus build and validation matrix.
5. Full regression (levels 1–8), posture invariants, ML boundary, provenance,
   abstention, performance.
6. Documentation and the completion report.

## 5. Invariant coverage gaps to close

Reviewing the 15 invariants against existing tests, these lack an explicit assertion and
will get one: **INVARIANT 2** (COMPLIANT gives no credit for something merely not
observed), **INVARIANT 8** (ML cannot turn UNKNOWN into OBSERVED), **INVARIANT 15**
(posture is canonical — no second scoring path). The other twelve are already covered by
Phase-7 tests.

## 6. Explicit non-goals

No Phase 8. No backend, dashboard or reporting. No LLM. No ML changes or re-selection.
No architecture redesign. No new finding or posture model.
