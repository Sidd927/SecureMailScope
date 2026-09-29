# Phase 12 — 07. Forensic honesty audit

Folds in brief §15 (forensic honesty) and §16 (security claim audit — no dedicated filename was
specified for it; it belongs here because every row of the claim register below is precisely the
"observed/inferred/ambiguous/not-observable" discipline applied per-rule).

---

## 1. The six evidence states, and whether they are ever collapsed

`OBSERVED · INFERRED · UNKNOWN · AMBIGUOUS · INCOMPLETE · NOT_OBSERVABLE` — defined once in
`evidence/states.py`, consumed everywhere. Searched every rule, the posture layer, the reporting
layer, and the dashboard for a place where two of these get silently merged into one. **None
found.** Specific checks:

| Risk | Searched | Result |
|---|---|---|
| `UNKNOWN` rendered as `False` | rule evaluations, dashboard chips | not found — `EvidenceField.value_or()` refuses to hand back a value for any non-conclusive state, structurally |
| `NOT_OBSERVABLE` rendered as a compliant/secure state | dashboard `protocolPanel`, report sections | not found — guarded by an explicit code comment and `test_scene_b_no_findings_is_not_rendered_as_secure` |
| Certificate absence → certificate invalid | `SEC-CERT-001` | explicitly refused: *"absence of certificate evidence is not evidence of an absent, invalid or untrusted certificate"* |
| Certificate structure → certificate trust | `SEC-CERT-005`, `SEC-TLS-003` | explicitly refused, both in the finding text and by `test_chain_never_claims_trust_or_revocation` |
| Forward secrecy `UNKNOWN` → forward secrecy `False` | `SEC-FS-001` | explicitly refused: *"NOT a finding that forward secrecy is absent"* — no ServerHello yields `UNKNOWN`, never `False` |
| Chain-link mismatch → chain "broken"/"invalid" | `SEC-CERT-005` | reported `AMBIGUOUS`, with the explicit text *"NOT a finding that the chain is invalid"* — a missing identifier is distinguished from a genuinely inconsistent chain |
| Behavioural deviation → attacker attribution | cross-session rules | explicitly refused: *"no attacker, intent or attribution is or can be established from a packet capture"*, reaching the console verbatim (`test_scene_a_inversion_declines_are_not_attacks`) |
| ML anomaly score → attack | `ml/`, `posture/` | structurally impossible — `MLAnomalyResult` carries no severity/status field, `ANOMALY` never penalises the score |

## 2. Security claim register (brief §16)

Every user-facing security claim, with its evidence, rule, standard, observability boundary, and
limitation. Pulled directly from the running rule registry (`ALL_RULES`), not transcribed from
memory.

| Rule | Claim (conclusion text, paraphrased) | Standard cited | Observability | Limitation stated in the finding |
|---|---|---|---|---|
| `SEC-TLS-001` | negotiated TLS version meets/fails current guidance | RFC 8996 (BCP 195); NIST SP 800-52r2 §3.1 | requires an observed ServerHello | unrecognised version values are `AMBIGUOUS`, never assumed weak |
| `SEC-TLS-002` | what the handshake evidence actually establishes (never manufactures completion) | RFC 8446 §2 | requires application data to claim `ESTABLISHED` | a partial handshake reports partial evidence, not success |
| `SEC-TLS-003` | certificate trust/revocation boundary | RFC 5280 §6; RFC 6960; RFC 8446 §2 | **never** observable from a passive capture, at any TLS version | states explicitly what would be required (trust anchor; OCSP/CRL access) |
| `SEC-STLS-001` | STARTTLS/STLS upgrade outcome | RFC 3207 §6; RFC 2595 | requires observing the upgrade command and its response | ambiguity is preserved where the two outcomes are byte-identical |
| `SEC-STLS-002` | STARTTLS/STLS advertisement posture | RFC 3207 §6; RFC 2595 | requires a captured capability response | absent advertisement is `AMBIGUOUS`, never `False` (01B research) |
| `SEC-STLS-003` | implicit TLS session identification | RFC 8314 | requires the connection on a recognised implicit-TLS port | — |
| `SEC-PLAIN-001` | authentication activity without TLS protection | RFC 8314 §3 | requires an observed auth command | — |
| `SEC-PLAIN-002` | mail session carried no TLS at all | RFC 8314 §3 | requires the full session to be observed | — |
| `SEC-KEX-001` | negotiated key-exchange mechanism | RFC 8446 §4.2.8 | requires an observed ServerHello; TLS 1.3 needs `key_share` specifically | unrecognised suite is `AMBIGUOUS`, closed-world table, never guessed |
| `SEC-FS-001` | forward secrecy present/absent | RFC 8446 §1.2 + App. D.5; NIST SP 800-52r2 §3.3.1 | requires an observed ServerHello | never `False` from an unobserved handshake (§1 above) |
| `SEC-CERT-001` | certificate extraction, or the specific reason none is visible | RFC 5280; RFC 8446 §2 | requires a cleartext `Certificate` message (TLS ≤1.2, full handshake) | names the exact reason — encrypted / not sent / truncated |
| `SEC-CERT-002` | certificate validity window | RFC 5280 | requires a decoded validity window **and** a capture timestamp | evaluated against **capture time**, never wall-clock; abstains without a timestamp |
| `SEC-CERT-003` | public key algorithm and length | NIST SP 800-57 Pt.1 Rev.5 §5.6.1 | requires a decoded public key | unread key parameters are `INSUFFICIENT_EVIDENCE`, not assumed strong or weak |
| `SEC-CERT-004` | signature algorithm, incl. deprecated hashes | RFC 9155; NIST SP 800-131A Rev.2 | requires a decoded signature OID | unrecognised OID is unidentified, never weak |
| `SEC-CERT-005` | chain structure (ordering, linkage, self-signing) | RFC 5280 §4.2.1.1; §6; RFC 6960 | requires ≥1 extracted certificate; identifiers (AKI/SKI) for linkage | explicitly **not** a trust or revocation claim, stated in every finding |
| `SEC-CFG-001` | coverage of a declared, versioned 7-item insecure-configuration checklist | RFC 8996; NIST SP 800-52r2; NIST SP 800-57 Pt.1 Rev.5; RFC 9155 | per-item, inherited from the item's own rule | unevaluated items are `NOT_OBSERVABLE`, never a false pass; checklist is closed and versioned |
| `CS-STARTTLS-001` (`StartTlsAdvertisementDeviationRule`) | one session's advertisement deviates from its server's own baseline | (behavioural, not standards-bound — a deviation, not a base issue) | requires ≥5 comparable sessions for a baseline | never asserts intent or attribution |
| `CS-STARTTLS-002` (`StartTlsUpgradeDeviationRule`) | one session's upgrade outcome deviates from baseline | same | same | same |
| `CS-TLS-001` (`TlsVersionDeviationRule`) | one session's negotiated version deviates from baseline | same | same | same |

## 3. What the system must never imply — verified, not assumed

Every line item the brief lists was searched for directly against production code and finding
text (not against test assertions alone, since a test could in principle assert the wrong thing —
the check here is on what the **rule itself emits**):

| Forbidden implication | Verified absent by |
|---|---|
| missing evidence = secure | `_NON_ASSERTIVE` status set in `analysis/model.py` structurally forbids severity above `INFO` for any non-`OBSERVED_ISSUE` status |
| missing evidence = insecure | same mechanism — `NOT_OBSERVABLE`/`AMBIGUOUS`/`INSUFFICIENT_EVIDENCE` can never carry a penalising severity |
| anomaly = attack | `MLAnomalyResult` has no severity/status field; `ANOMALY` issue class never penalises |
| certificate extraction = certificate trust | `SEC-CERT-005`'s `boundary` tuple, emitted on every certificate-chain finding regardless of outcome |
| certificate absence = invalid certificate | `SEC-CERT-001`'s explicit denial, quoted in §1 |
| deviation = attacker | cross-session finding text, quoted in §1 |

## 4. One nuance worth stating plainly, not hiding

`DEPRECATED_TLS_VERSION`'s `IssueClass` member name is itself verdict-shaped (it names the bad
outcome, not the dimension being assessed) — the same pattern that was found and fixed for
`FORWARD_SECRECY_ABSENT` during Phase 11 (renamed to `FORWARD_SECRECY` because the class also
carries the *compliant* finding). `DEPRECATED_TLS_VERSION` was deliberately **left unrenamed** in
Phase 11, because renaming it would change the fusion identity of every assessment stored before
this phase — a real, accepted trade-off, not an oversight. It does not currently mislead in
practice (unlike the forward-secrecy case, this class is asymmetric: a *compliant* TLS-version
finding is genuinely a different, non-deprecated condition, so the class name being
verdict-shaped happens not to produce a false statement) but it is recorded here because a
forensic-honesty audit that only reports clean results is not trustworthy. This is not treated as
a defect requiring a fix — see `13-final-engineering-decision.md` for why renaming it now would
cost more (breaking stored-assessment fusion identity) than it would gain (a cosmetic wart on one
enum member).
