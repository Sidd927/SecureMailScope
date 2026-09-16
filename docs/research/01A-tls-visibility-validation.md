# 01A — Critical Validation Pass: TLS Passive Visibility

**Purpose:** Stress-test the "observability paradox" conclusion from doc 01 §6.1 before it is allowed
to shape the solution direction.
**Status:** Complete (v1) · **Date:** 2026-09-16
**Verdict up front:** The conclusion was **technically correct but strategically misweighted**, and
the differentiation hypothesis built on it has **substantial prior art**. Both are corrected below.

---

## 1. Executive summary of this pass

| Claim from doc 01 | Verdict after validation |
|---|---|
| TLS 1.3 encrypts the `Certificate` message; passive extraction is impossible without keys | ✅ **Upheld and strengthened.** Confirmed by RFC 8446 and by Zeek's own documentation. |
| Therefore requirements D-10…D-14 are conditionally unachievable | ✅ **Upheld, and the condition is broader than I stated** — *all* resumed sessions lose the certificate, including TLS 1.2 ones. I missed this. |
| "The tool sees least when the target is safest" | ⚠️ **Overstated.** True for certificates only. Version, cipher suite, key-exchange group, SNI, resumption and 0-RTT all remain visible in TLS 1.3. |
| This is our strongest candidate differentiator | ❌ **Rejected.** A May 2026 paper already formalises evidence-tiered TLS observability with `unknown`/`not_applicable`/`ambiguous`/`contradictory` as first-class states. See §6. |
| *(Not identified in doc 01)* | 🆕 **The real opportunity is the STARTTLS negotiation layer**, which is cleartext in every TLS version, carries a documented attack taxonomy, and is what the PS Background actually emphasises. See §7. |

**The single most important correction:** I framed certificate blindness as the defining property of
the problem. Recounting against the PS, **only 5 of 22 listed deliverables depend on certificate
contents**. Roughly three-quarters of the PS is achievable from passive PCAP under *every* TLS
version. The "paradox" is a real caveat, not a crisis, and treating it as the centrepiece would have
misallocated the project.

---

## 2. Passive visibility evidence matrix

**Scope of the matrix.** "Visible" = recoverable from a PCAP by an observer with **no key material,
no active probing, and no external lookups**. Handshake-type distinctions matter enormously and are
broken out separately.

**Legend:** ✅ visible · ⚠️ partial/conditional · ❌ not visible · ➖ not applicable to that version

### 2.1 Full handshake (no resumption)

| # | Property | TLS 1.0 | TLS 1.1 | TLS 1.2 | TLS 1.3 | Basis / note |
|---|---|:--:|:--:|:--:|:--:|---|
| 1 | ClientHello | ✅ | ✅ | ✅ | ✅ | Cleartext in all versions. |
| 2 | ServerHello | ✅ | ✅ | ✅ | ✅ | Cleartext in all versions (RFC 8446 §4.1.3). |
| 3 | Cipher suite (offered) | ✅ | ✅ | ✅ | ✅ | ClientHello `cipher_suites`. |
| 4 | Cipher suite (**negotiated**) | ✅ | ✅ | ✅ | ✅ | ServerHello `cipher_suite` is cleartext even in 1.3. |
| 5 | Version (offered) | ✅ | ✅ | ✅ | ✅ | 1.3 moves real versions to `supported_versions`; `legacy_version` is pinned to 0x0303. |
| 6 | Version (**negotiated**) | ✅ | ✅ | ✅ | ✅ | 1.3: `supported_versions` in ServerHello = 0x0304 (RFC 8446 §4.2.1). Parsing `legacy_version` alone **misreports TLS 1.3 as TLS 1.2** — a classic implementation bug we must avoid. |
| 7 | Key exchange mechanism | ✅ | ✅ | ✅ | ✅ | ≤1.2: encoded in cipher-suite name + `ServerKeyExchange`. 1.3: `key_share` group in cleartext ServerHello. |
| 8 | Supported groups / curves | ⚠️ | ⚠️ | ⚠️ | ✅ | ≤1.2: only if `elliptic_curves`/`supported_groups` extension present (RFC 4492). 1.3: `key_share` + `supported_groups` always present. |
| 9 | Signature algorithms (offered) | ➖ | ➖ | ✅ | ✅ | `signature_algorithms` extension introduced in TLS 1.2. Does not exist in 1.0/1.1. |
| 10 | Signature algorithm (**selected**) | ✅ | ✅ | ✅ | ❌ | ≤1.2: visible in `ServerKeyExchange` signature / cert. 1.3: inside encrypted `CertificateVerify`. |
| 11 | **Server certificate** | ✅ | ✅ | ✅ | ❌ | **The core limitation.** 1.3 `Certificate` is encrypted under handshake keys (RFC 8446 §2). |
| 12 | Certificate **chain** | ✅ | ✅ | ✅ | ❌ | Same message. |
| 13 | Certificate **expiry** | ✅ | ✅ | ✅ | ❌ | Requires cert contents. |
| 14 | Certificate **public key / length** | ✅ | ✅ | ✅ | ❌ | Requires cert contents. |
| 15 | Certificate **signature algorithm** | ✅ | ✅ | ✅ | ❌ | Requires cert contents. Where SHA-1 certs would be caught. |
| 16 | **Client** certificate (mTLS) | ✅ | ✅ | ✅ | ❌ | 1.3: encrypted. |
| 17 | **Forward secrecy** | ✅ | ✅ | ✅ | ✅ | ≤1.2: derived from suite (`TLS_ECDHE_*`/`TLS_DHE_*` = PFS; `TLS_RSA_*` = none). 1.3: **always true by construction** — static RSA and static DH removed (RFC 8446 §1.2). |
| 18 | SNI | ✅ | ✅ | ✅ | ⚠️ | Cleartext unless **ECH** is in use, which conceals it. |
| 19 | ALPN — client offer | ✅ | ✅ | ✅ | ✅ | ClientHello, cleartext. |
| 20 | ALPN — **server selection** | ✅ | ✅ | ✅ | ❌ | 1.3 moves it to encrypted `EncryptedExtensions`. Rarely used for mail, but the asymmetry is real. |
| 21 | Session resumption **offered** | ✅ | ✅ | ✅ | ✅ | ≤1.2: session ID / ticket. 1.3: `pre_shared_key` + `psk_key_exchange_modes`. |
| 22 | Session resumption **accepted** | ✅ | ✅ | ✅ | ✅ | ≤1.2: matching session ID / abbreviated flow. 1.3: `pre_shared_key` in cleartext ServerHello. |
| 23 | 0-RTT / early data | ➖ | ➖ | ➖ | ✅ | `early_data` extension in cleartext ClientHello (RFC 8446 §4.2). TLS 1.3 only. |
| 24 | Handshake failure / alert | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Pre-key-change alerts are cleartext; later alerts are encrypted. Failure is still inferable from flow behaviour. |
| 25 | Record sizes / timing | ✅ | ✅ | ✅ | ✅ | Always observable. The basis of encrypted-traffic analysis. |
| 26 | Client TLS-stack fingerprint | ✅ | ✅ | ✅ | ✅ | JA3 / **JA4** from cleartext ClientHello. |
| 27 | Server TLS-stack fingerprint | ✅ | ✅ | ✅ | ✅ | JA3S / **JA4S** from cleartext ServerHello. |

### 2.2 Resumed sessions — the correction I missed

| Property | TLS 1.2 resumed | TLS 1.3 PSK resumed |
|---|:--:|:--:|
| Certificate, chain, expiry, key, sig alg | ❌ | ❌ |
| Version, cipher suite, resumption status | ✅ | ✅ |

**FACT (RFC 8446 §2.2).** In a PSK handshake *"the server is authenticating via a PSK, it does not
send a Certificate or a CertificateVerify message."* In TLS 1.2 abbreviated handshakes the
`Certificate` message is likewise omitted.

**This materially widens the limitation.** Doc 01 framed certificate blindness as a TLS 1.3 problem.
It is not — **it is a property of every resumed session at any version**. Mail clients (IMAP/POP3
especially) poll frequently and resume aggressively, so in a realistic enterprise mail capture a
*large* fraction of sessions may carry no certificate regardless of TLS version.

**Mitigation available and worth building — "inherited evidence."** In TLS ≤1.2 the session ID is
cleartext, so a resumed session can be linked to the full handshake that established it *if that
handshake is in the same capture*, inheriting its certificate evidence. This must be reported as
**inherited**, not **observed** — the certificate could have changed. In TLS 1.3 this linkage is
unavailable, because `NewSessionTicket` is sent encrypted.

### 2.3 The STARTTLS / application layer — where passive capture is strongest

**This layer is cleartext in every TLS version, and doc 01 under-weighted it severely.**

| Property | SMTP | IMAP | POP3 | Visible? |
|---|---|---|---|:--:|
| Service banner | `220 ...` | `* OK ...` | `+OK ...` | ✅ |
| Capability advertisement | `EHLO` → `250-STARTTLS` | `CAPABILITY` → `STARTTLS` | `CAPA` → `STLS` | ✅ |
| Upgrade command | `STARTTLS` | `a001 STARTTLS` | `STLS` | ✅ |
| Server's response to upgrade | `220 Ready to start TLS` | `a001 OK` | `+OK` | ✅ |
| Whether the client **proceeded** to TLS | ✅ | ✅ | ✅ | ✅ |
| Whether the client **continued in cleartext** | ✅ | ✅ | ✅ | ✅ |
| Cleartext `AUTH` / `LOGIN` credentials | ✅ | ✅ | ✅ | ✅ (a finding in itself) |
| Post-upgrade command injection residue | ✅ | ✅ | ✅ | ✅ |

**Implicit TLS (SMTPS 465 / IMAPS 993 / POP3S 995)** has **no cleartext application phase at all** —
the connection opens with a `ClientHello`. Protocol identification there cannot use banners and must
fall back on port, SNI, certificate SANs (TLS ≤1.2 only) and traffic shape. Note the PS's dataset
hint names exactly these implicit-TLS variants, so both paths must be handled.

---

## 3. What real passive tools actually extract

**FACT.** Zeek's own `ssl.log` documentation states plainly: *"Note that there is no mention of
certificates in the `ssl.log`. TLS 1.3 hides these from passive observation systems."* Zeek still
logs `version`, `cipher`, `curve`, `server_name`, `resumed`, `established`, `next_protocol`, and
(with packages) JA3/JA3S. Certificates, when visible, go to a separate `x509.log` linked by file ID.

This is decisive corroboration from a mature production tool, independent of my RFC reading. It also
tells us the achievable output shape: **Zeek's field set is very close to the visible column of
§2.1**, which is a useful sanity bound on what any passive tool can deliver.

**JA3/JA4.** Client fingerprints are computed from the cleartext ClientHello; JA4S from the
ServerHello. These work at all TLS versions and are therefore unaffected by the 1.3 limitation.
⚠️ **Licensing caveat:** JA4 (TLS client) is BSD-3-Clause, but **JA4S, JA4X, JA4H, JA4L and JA4SSH
are under the FoxIO License 1.1** — permissive for academic and internal use, not for monetisation.
Relevant if this project is ever commercialised; fine for SIH.

**Industry corroboration.** Corelight's *Maintain Security Visibility in the TLS 1.3 Era* and the
NIST NCCoE project *Addressing Visibility Challenges with TLS 1.3 within the Enterprise* both exist
specifically because this is a recognised, unsolved enterprise problem — which confirms the problem
is real, and equally confirms we are not the first to notice it.

---

## 4. Certificate availability — passive vs. auxiliary

Kept strictly separate, as instructed. Blurring these is the central integrity risk of this project.

### 4.1 PASSIVE PCAP ONLY (no keys, no probing, no lookups)

| Scenario | Certificate available? |
|---|---|
| TLS 1.0/1.1/1.2, full handshake | ✅ Yes — cleartext `Certificate` message |
| TLS 1.2, resumed session | ❌ No — abbreviated handshake omits it |
| TLS 1.2 resumed, **full handshake present earlier in same capture** | ⚠️ **Inherited** via cleartext session ID — must be labelled inherited, not observed |
| TLS 1.3, full handshake | ❌ No — encrypted (RFC 8446 §2) |
| TLS 1.3, PSK resumption | ❌ No — not sent at all (RFC 8446 §2.2) |
| TLS 1.3 with ECH | ❌ No, and SNI is concealed too |
| Truncated / mid-stream capture | ❌ No — and *must* be reported as truncation, not as absence |

### 4.2 PCAP + AUXILIARY EVIDENCE (each breaks at least one constraint)

| Source | What it yields | Constraint broken |
|---|---|---|
| **TLS key log** (`SSLKEYLOGFILE`) | Full decryption, including cert | Requires endpoint cooperation. **Not available to a real forensic analyst.** Must be a separately-labelled mode. |
| Server private key | Decryption for **non-PFS TLS ≤1.2 only** | Useless for TLS 1.3 and for any PFS suite — forward secrecy is precisely the point |
| **Active probe** of the mail server | Current cert chain | Violates I-02 (passive). Yields cert **at probe time**, not capture time — a different claim |
| **Certificate Transparency logs** | Certs historically issued for a name | Requires network access (breaks offline assumption A-02); CT coverage of internal enterprise mail CAs is poor |
| Endpoint / server-side artifacts | Cert store, mail server config, logs | Different evidence class entirely; outside a PCAP-only tool |
| TLS-terminating proxy / middlebox | Cert as seen by the middlebox | Changes the trust model; the observed cert may be the middlebox's own |
| **Prior observation in our own corpus** | Cert seen earlier for same server | Legitimate and offline-safe, but is a **historical claim**, not a claim about this session |

**Rule this establishes.** Every certificate finding must carry its **provenance**: `observed`,
`inherited`, `historical`, `actively-retrieved`, or `decrypted`. A tool that presents an actively
retrieved certificate as if it were passively observed is making a false forensic claim. This rule
is non-negotiable and should survive into whatever architecture we choose.

---

## 5. PS requirement feasibility matrix

`P` = passive PCAP only. Confidence reflects our certainty about the *feasibility claim*, not about
any individual finding.

| PS req | Passive? | TLS versions | Evidence required | Conf. | If not, why | Workaround |
|---|---|---|---|---|---|---|
| D-01 ingest PCAP | ✅ Full | all | file | High | — | — |
| D-02 protocol ID | ✅ Full / ⚠️ implicit-TLS | all | cleartext banner; else port+SNI+shape | High | Implicit TLS has no banner | SNI, cert SAN (≤1.2), port, traffic shape, JA4S |
| D-03 TCP reassembly | ✅ Full | all | packets | High | — | Report truncation/gaps explicitly |
| D-04 STARTTLS detection | ✅ **Full** | all | cleartext negotiation | High | — | — |
| D-05 STARTTLS **validation** | ✅ **Full** | all | cleartext negotiation | High | — | **Strongest requirement in the PS — see §7** |
| D-06 TLS handshake parse | ✅ Full (cleartext portion) | all | CH/SH records | High | 1.3 encrypts post-SH | Parse what is visible; mark the rest unobserved |
| D-07 negotiated version | ✅ Full | all | SH + `supported_versions` | High | — | Must read `supported_versions`, not `legacy_version` |
| D-08 cipher suite | ✅ Full | all | SH | High | — | — |
| D-09 key exchange | ✅ Full | all | suite name (≤1.2) / `key_share` (1.3) | High | — | — |
| **D-10 cert extraction** | ⚠️ **Partial** | ≤1.2 full only | `Certificate` msg | High | 1.3 encrypts; all resumption omits | Inherited linkage (≤1.2); else report unobserved |
| **D-11 chain validation** | ⚠️ Partial | ≤1.2 full only | chain + trust store | Med | as D-10 | Trust-store choice is itself unresolved (OQ-04) |
| **D-12 expiry analysis** | ⚠️ Partial | ≤1.2 full only | cert + **capture time** | High | as D-10 | Evaluate against capture timestamp, never wall-clock |
| **D-13 pubkey / length** | ⚠️ Partial | ≤1.2 full only | cert | High | as D-10 | — |
| **D-14 cert signature alg** | ⚠️ Partial | ≤1.2 full only | cert | High | as D-10 | — |
| D-15 weak crypto / deprecated TLS | ✅ **Full** | all | SH version + suite | High | — | Cert-level weakness (SHA-1) still limited by D-14 |
| D-16 insecure configuration | ✅ Mostly | all | negotiation + STARTTLS | Med | Scope undefined (AMB-06) | Bound it to an explicit checklist |
| D-17 forward secrecy | ✅ **Full** | all | suite (≤1.2) / by construction (1.3) | High | — | Trivially true for 1.3 |
| D-18 crypto feature extraction | ✅ Full | all | all visible fields | High | — | Feature set must encode *observability*, not just values |
| A-01 risk classification | ✅ | all | D-07…D-17 | High | — | Deterministic rules likely better than ML |
| A-02 anomaly detection | ✅ | all | JA4/JA4S, sequences, timing | Med | — | Validation is the hard part, not detection |
| A-03 posture scoring | ✅ | all | findings + **coverage** | Med | — | Score must be coverage-aware (§7.2) |
| A-04 prioritisation | ✅ | all | findings + context | Med | — | — |
| A-05 recommendations | ✅ | all | findings + standards | Med | — | Must be grounded; ungrounded crypto advice is a safety issue |
| R-01…R-05 reporting | ✅ | all | findings | High | — | — |

**Count.** Of 22 PS deliverables, **5 are certificate-dependent** (cert extraction, chain
validation, expiry, public key, signature algorithm). The remaining 17 are fully achievable from
passive PCAP at every TLS version. **This is the number that corrects doc 01's framing.**

---

## 6. Prior art on the evidence-tiering hypothesis

The hypothesis under test: *"SecureMailScope could distinguish VERIFIED / INFERRED / NOT OBSERVABLE
rather than pretending every cryptographic property can be determined."*

### 6.1 Verdict: **not novel.** Prior art is substantial and, in one case, near-identical.

| Prior art | What it establishes | Relation to our hypothesis |
|---|---|---|
| **Delgado, *Observability for Post-Quantum TLS Readiness: A Multi-Surface Evidence Framework*, arXiv 2605.02978 / IACR ePrint 2026/866, May 2026** | Four evidence surfaces (passive capture, active probe, cert chain, registry) over seven "planes"; **`unknown` / `not_applicable` / `ambiguous` / `contradictory` as first-class states**; scoring by *plane closure* against evidence availability rather than field completion; explicit handling of TLS 1.3 encryption, PSK resumption, and **truncation, where `unknown` is the correct answer** | ⛔ **This is the hypothesis, already formalised and evaluated.** Reports passive-only closure of 1.00 for session/key-establishment vs **0.29 for authentication/lifecycle** |
| **Casey's Certainty Scale (C-Scale), 2002**, and *Digital Evidence Certainty Descriptors* | Standard framework in digital forensics for expressing certainty in evidence; explicitly separates certainty of the *generating process* from certainty of *contents*; context-dependent, not per-evidence-type | The general principle of evidence-confidence tiering in forensics is **24 years old** |
| **CVSS Report Confidence** (Temporal: Confirmed / Reasonable / Unknown) | Confidence in a finding as a standard, scored dimension | Same axis. ⚠️ **Removed in CVSS v4.0** — worth knowing before we build on it |
| **Qualys "confirmed" vs "potential" vulnerabilities**; Nessus/Nmap confidence | Commercial scanners have shipped confidence tiering for two decades | Not a differentiator |
| **Zeek `ssl.log`** | Simply omits unavailable fields, and documents *why* in prose | Common practice — but **implicit** (empty field), not an explicit machine-readable state |

### 6.2 What is common, what is uncommon, what might still differentiate

**Common (claiming these would be marketing language):**
- Confidence scores on security findings.
- Leaving unavailable fields blank.
- Observing that TLS 1.3 hurts passive visibility — Corelight, NCCoE and Zeek all say so publicly.

**Uncommon but published (cannot claim as ours):**
- Uncertainty as a *first-class typed state* with provenance for *why* evidence is missing.
- Scoring assessment **coverage** rather than findings alone.
- Rewarding correct `unknown` output instead of penalising it.

**Possibly still differentiating — narrow, and to be verified in Phase 13:**
1. **Domain transfer.** Delgado's framework is HTTPS/TLS and **post-quantum-specific**; it does not
   cover SMTP/IMAP/POP3 or the STARTTLS negotiation layer. Applying evidence-aware observability to
   *email transport* is a genuine gap — but it is *application of a published method to a new
   protocol family*, which is honest engineering, **not a research contribution**. We must say so.
2. **Coverage-aware posture scoring for mail.** A score that declares "assessed 13 of 18 properties;
   5 unobservable because TLS 1.3 encrypted the certificate" is defensible and, as far as this
   search shows, not shipped by any mail-focused tool. Weak novelty; real user value.
3. **Provenance-typed certificate findings** (§4.2: observed / inherited / historical / retrieved /
   decrypted) applied to mail infrastructure.

**Honest conclusion.** Evidence tiering should be an **engineering correctness requirement** of our
system — it prevents us from shipping false forensic claims — **not our headline innovation.**
Presenting it as novel would be a claim a competent reviewer can refute in one search.

---

## 7. The reweighted opportunity: the STARTTLS layer

Validation moved the centre of gravity. The PS Background names *"insecure STARTTLS
implementations"* and *"downgrade attacks"* explicitly — and this is exactly the layer that is
**fully visible to passive capture at every TLS version**.

### 7.1 There is a published attack taxonomy, and it is detectable in PCAP

**FACT — Poddebniak, Ising, Böck, Schinzel, *Why TLS is better without STARTTLS*, USENIX Security
2021.** First systematic analysis of STARTTLS across **SMTP, POP3 and IMAP**. Attack classes:
**stripping, command injection, response injection, tampering, UI spoofing**. Built EAST, a testing
framework with 100+ test cases. Findings: **40+ STARTTLS issues; ~320,000 email servers (2%)
vulnerable to command injection; only 3 of 28 clients and 7 of 23 servers free of STARTTLS-specific
issues.** Their recommendation is to prefer implicit TLS over STARTTLS.

**FACT — Durumeric et al., *Neither Snow Nor Rain Nor MITM*, ACM IMC 2015.** Internet-scale
measurement of mail delivery security: **over 426 Autonomous Systems observed performing STARTTLS
stripping**; of 4.2M hosts failing the TLS handshake, **623,635 (14%) echoed back the command they
received — a middlebox-corruption signature**. Stripping caused ~20% of inbound Gmail messages from
seven countries to arrive in cleartext.

**FACT — RFC 3207 §6 (Feb 2002).** *"A man-in-the-middle attack can be launched by deleting the
'250 STARTTLS' response from the server. This would cause the client not to try to start a TLS
session."* §4.2 requires the client to discard pre-TLS knowledge and re-issue `EHLO`.

**INFERENCE.** Every one of these has a passively observable signature in the cleartext phase:
a missing `STARTTLS` capability on a server that should advertise it; a mangled or echoed command;
a client that continues in cleartext after seeing the advertisement; commands appearing *before*
the `220` response (injection); `AUTH` credentials sent without TLS; failure to re-issue `EHLO`
after upgrade.

**This is the strongest position available to us**, because:
- It is **immune to the TLS 1.3 limitation** — it happens before TLS starts.
- It matches the PS Background's own wording.
- It is grounded in two top-tier venues, so severity claims are citable rather than asserted.
- It is where certificate-focused tools — and, per §6, the teams that build them — look least.

⚠️ **Not a novelty claim.** Poddebniak et al. already found these attacks; EAST already tests for
them. What we would build is *passive detection from capture* rather than *active testing of a
server*, which is a different operational mode. Phase 13 must check whether passive STARTTLS-attack
detection already exists in Zeek/Suricata rule sets before any differentiation is claimed.

### 7.2 Where this leaves the "limitation as intelligence" idea

The instruction was to investigate whether the limitation can itself become forensic intelligence.
It partly can, and the honest version is narrower than the exciting version:

- ✅ **Defensible:** absence of certificate evidence is *itself* an observation with a typed cause
  (TLS 1.3 / resumption / truncation / ECH), and reporting coverage alongside score prevents a
  clean-looking report from meaning "we saw nothing."
- ✅ **Defensible:** a *rising* proportion of unobservable sessions over time is a real signal — of
  TLS 1.3 adoption (good) or of capture-position degradation (bad). Distinguishing those is useful.
- ⚠️ **Weak:** "TLS 1.3 usage is inferable from our blindness" — true but trivial, since the
  negotiated version is directly visible anyway (§2.1 row 6).
- ❌ **Reject:** any framing that treats blindness as a *feature*. It is a constraint we handle
  correctly. Dressing it up would be exactly the "impossibility turned into a fake feature" the
  brief warns against.

---

## 8. Why my previous conclusion could be wrong

Six alternative interpretations, argued as strongly as the evidence permits.

**Alt-1 — I manufactured a paradox from an uncharitable reading.**
The PS says "passive analysis of encrypted ... traffic" and separately "extraction and validation of
X.509 certificates." A natural reading is *analyse the handshake surrounding encrypted payloads, and
extract certificates where they are present* — with no contradiction intended. AMB-02 in doc 01
already identified this, then §6.1 proceeded as if the stronger reading were established.
**Assessment: partly right.** There is no contradiction *in intent*; there is a real constraint *in
practice*. "Contradiction" was the wrong word; "conditional achievability" is correct.

**Alt-2 — Enterprise mail is still mostly TLS 1.2, so the limitation rarely bites.**
MTAs upgrade far more slowly than browsers, and Holz et al. (2019) found early TLS 1.3 adoption
concentrated in a few large web players. If real enterprise mail captures are predominantly TLS 1.2
full handshakes, certificates are usually available and this is a footnote.
**Assessment: plausible, unmeasured.** ⚠️ But note §2.2 — *resumption* removes certificates at any
version, and mail clients poll and resume heavily. The limitation may bite often even in a pure TLS
1.2 environment, for a reason that has nothing to do with TLS 1.3. **This strengthens the finding
while invalidating my original explanation of it.**

**Alt-3 — NTRO expects participants to hold key material.**
The dataset field tells participants to *generate their own* captures from servers they control,
where `SSLKEYLOGFILE` is trivially available. Perhaps "passive" means "non-intrusive to the mail
infrastructure," not "without keys."
**Assessment: possible but should not be adopted as the default.** It is the reading that makes the
problem easy, which is reason for suspicion. A tool that only works with keys is not a forensic tool.
Correct response: support decryption as an explicitly-labelled **optional** mode, and never let it
silently inflate results. Recorded as **OQ-13**.

**Alt-4 — The certificate requirements simply matter less than I implied.**
Only 5 of 22 deliverables are certificate-dependent (§5). Even total certificate blindness leaves
~77% of the PS deliverable.
**Assessment: correct, and this is the most important correction in this document.** My Phase 1
framing gave a 5/22 sub-problem the status of the defining problem.

**Alt-5 — The limitation is well-known, so "noticing it" is not an achievement.**
Zeek documents it, Corelight wrote a white paper, NIST NCCoE ran a project, and an academic
framework formalised it in May 2026.
**Assessment: correct.** Noticing is table stakes. *Handling it correctly* is competent engineering.
Only the *email-specific application* is arguably unclaimed, and weakly so (§6.2).

**Alt-6 — The contradiction is deliberate, a discriminator planted by NTRO.**
**Assessment: unfalsifiable speculation.** No contact channel exists to test it. I am recording it
so it is not mistaken for analysis. It must not influence design.

### What this means for doc 01

Doc 01 §6.1 must be amended: the claim is upheld on the facts but must be (a) restated as
conditional achievability rather than contradiction, (b) widened to cover resumption at all
versions, (c) quantified as 5 of 22 deliverables, and (d) **stripped of its "strongest
differentiator" status**, which §6 refutes.

---

## 9. What remains definitely established

1. **F-07 upheld.** TLS 1.3 encrypts all handshake messages after ServerHello, including
   `Certificate` (RFC 8446 §2). Corroborated independently by Zeek's documentation.
2. **PSK/resumed handshakes send no `Certificate` message at all** (RFC 8446 §2.2), so certificate
   blindness is *not exclusive to TLS 1.3*. **New, and more consequential than the original finding.**
3. **TLS 1.3 is always forward-secret** — static RSA and static DH removed (RFC 8446 §1.2). So D-17
   is trivially satisfiable for 1.3, and holding a server private key does not restore visibility.
4. **Negotiated version, cipher suite, key-exchange group, SNI, resumption status and 0-RTT remain
   visible in TLS 1.3.** The blindness is specific, not general.
5. **`legacy_version` is pinned to 0x0303 in TLS 1.3** (RFC 8446 §4.1.3); the real version is in
   `supported_versions` (§4.2.1). Reading the wrong field misreports TLS 1.3 as TLS 1.2.
6. **The STARTTLS negotiation phase is cleartext in all versions** and carries a published,
   passively-detectable attack taxonomy (Poddebniak 2021; Durumeric 2015; RFC 3207 §6).
7. **Only 5 of 22 PS deliverables are certificate-dependent.**
8. **Evidence tiering is prior art**, formalised for TLS as recently as May 2026, and rooted in
   digital-forensics practice since 2002.
9. **Zeek is a concrete upper bound** on passive extraction: version, cipher, curve, server_name,
   resumed, established, next_protocol, JA3/JA3S — and no certificates under TLS 1.3.

## 10. What remains uncertain

| ID | Uncertainty | Why it matters | How to resolve |
|---|---|---|---|
| **OQ-02** | What fraction of real enterprise mail traffic is TLS 1.3 vs 1.2, and what fraction is resumed? | Determines whether certificate blindness is a footnote or the dominant case | Measurement study; our own lab corpus cannot answer it |
| **OQ-13** *(new)* | Is a key-log-assisted mode within the PS's intent? | Changes what is demonstrable, and the integrity story | No official channel; must be decided and documented as an interpretation |
| **OQ-14** *(new)* | Do Zeek/Suricata/commercial NSM already detect STARTTLS stripping and command injection passively? | If yes, §7 is not differentiating either | Phase 13: inspect Zeek scripts, ET/Suricata rules |
| **OQ-15** *(new)* | How reliable is implicit-TLS protocol identification without banners or certificates? | D-02 confidence on 465/993/995 | Experiment E-4 (§11) |
| **OQ-16** *(new)* | Is inherited-evidence linkage across TLS 1.2 resumption sound enough to report? | Could recover a large share of otherwise-lost certificate coverage | Experiment E-3 |
| OQ-03 | Authority for "weak"/"deprecated" beyond RFC 8996 | Needed for defensible severity | Phase 4: NIST SP 800-52r2, 800-131A, CERT-In |
| OQ-04 | Trust store and enterprise internal CAs | Naive validation flags all internal CAs as failures | Phase 4 |
| OQ-05 | Can anomaly detection be validated without real labelled data? | Determines whether A-02 survives | Phase 10 |
| — | Whether ECH is deployed in mail contexts at all | Would further reduce SNI visibility | Low priority; ECH in mail appears rare |

---

## 11. Experiment design (design only — no implementation)

**Purpose.** Establish empirically what a parser can recover per protocol × TLS version, and convert
OQ-02/15/16 from opinion into measurement. **No parser is to be written yet.**

### 11.1 Capture matrix

Base matrix, 6 cells as specified:

| | TLS 1.2 | TLS 1.3 |
|---|---|---|
| **SMTP** | C1 | C2 |
| **IMAP** | C3 | C4 |
| **POP3** | C5 | C6 |

Each cell is generated **twice** — once via **STARTTLS** (ports 25/587, 143, 110) and once via
**implicit TLS** (465, 993, 995) — giving 12 baseline captures. Implicit-TLS variants match the PS's
own dataset hint.

**Extension cells** (these test the findings that actually matter):

| ID | Capture | Tests |
|---|---|---|
| X1 | TLS 1.2 **resumed** session (session ID) | §2.2 — certificate absent at TLS 1.2 |
| X2 | TLS 1.2 full handshake **followed by** resumed session, same capture | OQ-16 — inherited-evidence linkage |
| X3 | TLS 1.3 **PSK resumption** | RFC 8446 §2.2 — no Certificate message |
| X4 | TLS 1.3 **0-RTT / early data** | `early_data` visibility |
| X5 | **STARTTLS stripped** (capability removed in transit) | D-05, RFC 3207 §6, Durumeric |
| X6 | **STARTTLS command echoed/mangled** | Durumeric's 14% middlebox signature |
| X7 | Client **continues in cleartext** despite advertisement | Opportunistic-TLS failure |
| X8 | Cleartext `AUTH`/`LOGIN` with no TLS | Credential exposure |
| X9 | Expired / self-signed / broken-chain certificate over TLS 1.2 | D-11, D-12 |
| X10 | Weak crypto: TLS 1.0/1.1, RC4/3DES, SHA-1 cert, RSA-1024 | D-15 |
| X11 | **Truncated capture** (cut mid-handshake) | Truncation must yield `unknown`, not a guess |
| X12 | Non-standard port (e.g. IMAPS on 9993) | D-02 port-independence |
| X13 | Interleaved multi-session capture, 50+ concurrent sessions | I-04 scale, correlation |

### 11.2 Method

1. **Lab.** Containerised mail servers (e.g. Postfix/Dovecot) with deliberately downgraded TLS
   policy for X10. ⚠️ Expect real friction: modern OpenSSL disables TLS 1.0/1.1, RC4 and 3DES by
   default, and re-enabling them may require a specific security level or an older build. **Budget
   real time for X10 — it is the likeliest schedule risk in the whole experiment.**
2. **Ground truth.** Record, independently of capture, the true configuration of each session
   (version, suite, cert, group). Without this there is nothing to measure recovery against.
3. **Key logs captured but quarantined.** Record `SSLKEYLOGFILE` for every run and store it
   *separately*. It is used **only** to establish ground truth and to measure how much passive
   analysis misses — **never** as a passive-analysis input. This is the single most important
   methodological control in the plan, and directly addresses doc 01 §6.3 Trap 1.
4. **Baseline comparison.** Run `tshark` and Zeek over every capture first. Their output is the
   *floor*: any claim that we extract more than Zeek must be demonstrated against this baseline,
   not asserted.

### 11.3 Measured outputs

For each capture, per property in §2.1: `recovered` / `not-recovered` / `wrong`, plus the reason for
non-recovery. Deliverables:

- **A recovery matrix** — observed reality vs. the predicted matrix in §2.1. *Predictions that fail
  are findings, not embarrassments; §2.1 is theory until this runs.*
- **A coverage figure per protocol × version** — the empirical basis for coverage-aware scoring (§7.2).
- **A precise answer to "what does this tool output for a TLS 1.3 session?"** — the evaluator
  question flagged in doc 01.

### 11.4 Success criteria and falsifiers

| | |
|---|---|
| **Success** | Recovery matches §2.1 within known exceptions; every non-recovery has a correctly typed cause; no capture produces a confidently wrong value. |
| **Falsifier 1** | Certificates prove recoverable from TLS 1.3 captures without keys → §2.1 is wrong; escalate immediately. |
| **Falsifier 2** | Certificates prove *unavailable* in most TLS 1.2 captures too (heavy resumption) → the limitation is far larger than stated; re-plan. |
| **Falsifier 3** | Zeek already recovers everything we do → no engineering differentiation; pivot to the STARTTLS/analysis layer (§7). |

---

## 12. Recommendations from this pass

1. **Amend doc 01 §6.1** per §8. Downgrade "contradiction" to "conditional achievability", widen to
   resumption, quantify as 5/22, and remove its differentiator status.
2. **Do not claim evidence tiering as innovation.** Implement it as a correctness requirement, cite
   Delgado 2026 and Casey's C-Scale as the basis, and say plainly that we are applying a known method
   to a protocol family it has not been applied to. This is more defensible than an overclaim, and
   survives an evaluator's search.
3. **Reweight investigation toward the STARTTLS layer** (§7) — visible at every TLS version,
   academically grounded, and named in the PS Background.
4. **Adopt the provenance rule** (§4.2) as a hard architectural constraint: every certificate finding
   is typed `observed` / `inherited` / `historical` / `retrieved` / `decrypted`.
5. **Quarantine key logs** as ground-truth-only (§11.2.3).
6. **Carry Zeek/tshark as the baseline** for every capability claim.
7. **Resolve OQ-14 early** — if Zeek/Suricata already detect STARTTLS stripping passively, §7 needs
   the same honest downgrade §6 just applied to evidence tiering.
