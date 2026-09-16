# 01B — OQ-14: STARTTLS Passive Detection Prior-Art & Capability Audit

**Question:** Do existing network-forensics/security tools already detect STARTTLS downgrade,
stripping, command injection, response injection and related SMTP/IMAP/POP3 weaknesses?
**Method:** Primary-source inspection of shipped source code, scripts and rule files.
**Status:** Complete (v1) · **Date:** 2026-09-16

---

## 1. OQ-14 verdict

> **The attacks are NOT detected by stock open-source tooling — but the primitives to detect them
> mostly exist and are unused. The gap is real, verified, and narrow: it is an integration and
> coverage gap, not a detection-science gap.**

Four verified sub-findings, each traced to source code below:

| # | Finding | Evidence |
|---|---|---|
| 1 | **No shipped Zeek script, Suricata event, or ET rule detects STARTTLS stripping.** | Zeek `policy/protocols/smtp/` contains 4 scripts, none TLS-related. ET Open SMTP+IMAP+POP3 rulesets = **43 active rules, zero mentioning STARTTLS or STLS**. |
| 2 | **Zeek's entire STARTTLS security output for SMTP is one boolean.** | `smtp.log` field `tls: bool`. The `smtp_starttls` handler sets `tls=T` and nothing else. |
| 3 | **IMAP and POP3 are effectively uncovered by both major tools.** | Zeek `imap/main.zeek` is **11 effective lines** (port registration only); Zeek has **no `pop3/main.zeek` and no pop3.log**. Suricata `app-layer-imap.c` is **96 lines of protocol-detection patterns only**; Suricata has **no POP3 app-layer parser**. |
| 4 | **Suricata's STARTTLS events cannot fire on the actual stripping attack.** | `TLS_REJECTED` requires the client to have *sent* `STARTTLS`. In a capability-stripping attack the advertisement is removed, the client never sends the command, and **no event fires at all**. |

**Consequence for strategy.** Finding 2.7 of `RESEARCH_STATUS.md` **survives**, but must be restated.
It is not "we detect attacks nobody detects" (too strong — the detection logic is straightforward and
the attacks are documented since 2002). It is:

> *Stock tooling exposes STARTTLS evidence for SMTP only, as a single boolean, with no security
> evaluation, and exposes essentially nothing for IMAP and POP3. No shipped script or rule converts
> that evidence into a downgrade finding.*

That is **POTENTIAL DIFFERENTIATION**, not a novel research contribution. §9 and §12 stress-test it.

---

## 2. Method and evidence standard

Per instruction, capability claims come from **inspecting shipped artifacts**, not documentation
summaries. Source was downloaded and searched directly.

| Classification | Criterion |
|---|---|
| **VERIFIED** | Source code, script, rule file or official docs demonstrably implement it. Quoted or line-referenced. |
| **PARTIAL** | A primitive exists (event, field, parser) but no shipped logic turns it into a security finding. |
| **INFERRED** | Strong reasoning from tool architecture; **source not directly inspected.** |
| **NOT FOUND** | Searched the relevant shipped artifacts; absent. |
| **N/A** | Not applicable to that tool's role. |

⚠️ **Audit limitations — stated up front.** I directly inspected **Zeek** and **Suricata** source and
**ET Open** rules. I did **not** inspect Snort 3, Arkime, NetworkMiner, RITA or Security Onion
source; those rows are `INFERRED` and are flagged as such. Commercial products are excluded except
where documentation is publicly verifiable. This is a real gap in the audit and is carried into §14.

---

## 3. Tool-by-tool audit (primary source)

### 3.1 Zeek — inspected

**SMTP** (`scripts/base/protocols/smtp/main.zeek`, 495 lines). The `smtp.log` `Info` record has
~25 logged fields (helo, mailfrom, rcptto, subject, headers, user_agent …). Exactly **one** is
TLS-related:

```zeek
## Indicates that the connection has switched to using TLS.
tls:               bool            &log &default=F;
```

The complete handler:

```zeek
event smtp_starttls(c: connection) &priority=5
	{
	if ( c?$smtp )
		{
		c$smtp$tls = T;
		c$smtp$has_client_activity = T;
		}
	}
```

**That is the entirety of Zeek's STARTTLS logic.** No capability parsing, no stripping check, no
downgrade check, no cleartext-continuation check. `grep -i "auth|password|credential"` over the file
returns **nothing** — Zeek does not track SMTP `AUTH` at all, so cleartext credential exposure
(capability **L**) is not detected.

**Available but unused primitives.** Zeek's documented SMTP events are `smtp_request`, `smtp_reply`,
`smtp_data`, `smtp_unexpected`, `smtp_starttls`. Critically, the docs state: *"After this event no
more SMTP events will be raised for the connection."* So `smtp_request`/`smtp_reply` **do** expose
the `250-STARTTLS` advertisement and the client's command — the raw material for stripping detection
is present. **No shipped script consumes it for that purpose.**

**IMAP** — `scripts/base/protocols/imap/main.zeek`, reproduced in full:

```zeek
module IMAP;
export {
	## Well-known ports for IMAP.
	const ports = { 143/tcp } &redef;
}
event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_IMAP, ports);
	}
```

The README states: *"the IMAP analyzer only supports analyzing IMAP sessions until they do or do not
switch to TLS using StartTLS. Hence, we do not get mails from IMAP sessions, only X509
certificates."* **There is no `imap.log`.** The analyzer exists solely to hand off to SSL.

**POP3** — `scripts/base/protocols/pop3/` contains only `README`, `__load__.zeek` (which loads a DPD
signature) and `dpd.sig`. **No `main.zeek`. No `pop3.log`. No events logged.**

**SSL/TLS posture — this is where Zeek is genuinely strong.** `policy/protocols/ssl/` ships
`weak-keys.zeek`, `expiring-certs.zeek`, `validate-certs.zeek`, `validate-ocsp.zeek`,
`validate-sct.zeek`, `known-certs.zeek`, `heartbleed.zeek`. `weak-keys.zeek` raises `Weak_Key`,
`Old_Version` and `Weak_Cipher` notices.

⚠️ **Two defaults in `weak-keys.zeek` are materially out of date, and this is a concrete, citable
gap:**

```zeek
option tls_minimum_version = TLSv10;
option unsafe_ciphers_regex = /(_EXPORT_)|(_RC4_)/;
option notify_minimal_key_length = 2048;
```

- `tls_minimum_version = TLSv10` means **TLS 1.0 and TLS 1.1 raise no notice by default** — only
  SSLv2/SSLv3 do. **RFC 8996 (BCP 195, March 2021) says both MUST NOT be used.** Zeek's shipped
  default contradicts current IETF best practice, and PS requirement D-15 explicitly asks for
  deprecated-TLS detection.
- `unsafe_ciphers_regex` covers only EXPORT and RC4. **3DES, NULL, anon-DH and CBC suites are not
  flagged.**
- Key-length checks apply only to RSA/DSA certificates, and require `c$ssl$cert_chain` — so they
  **silently do nothing for TLS 1.3 and for all resumed sessions**, exactly as doc 01A §2 predicted.
- Notices carry `$suppress_for=1day` — Zeek is an **alerting** system, deduplicating per host per
  day. It is not designed to produce a per-session posture assessment. This is an architectural
  difference, not a bug, and it matters for §9.

### 3.2 Suricata — inspected

**SMTP** (`src/app-layer-smtp.c`, 4,526 lines) has a real STARTTLS-aware state machine:

```c
} else if (IsReplyToCommand(state, SMTP_COMMAND_STARTTLS)) {
    if (reply_code == SMTP_REPLY_220) {
        state->parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        if (!SCAppLayerRequestProtocolTLSUpgrade(f)) {
            SMTPSetEvent(state, SMTP_DECODER_EVENT_FAILED_PROTOCOL_CHANGE);
        }
        ...
    } else {
        SMTPSetEvent(state, SMTP_DECODER_EVENT_TLS_REJECTED);
    }
}
```

Of 25 SMTP decoder events, **two are STARTTLS-relevant**: `TLS_REJECTED` and
`FAILED_PROTOCOL_CHANGE`. Others useful for protocol-state anomalies: `INVALID_REPLY`,
`UNABLE_TO_MATCH_REPLY_WITH_REQUEST`, `INVALID_PIPELINED_SEQUENCE`, `NO_SERVER_WELCOME_MESSAGE`.

🔴 **The decisive gap.** `TLS_REJECTED` fires only inside `IsReplyToCommand(state,
SMTP_COMMAND_STARTTLS)` — i.e. **only if the client actually sent `STARTTLS`**. The canonical
stripping attack removes `250-STARTTLS` from the EHLO response, so the client never sends the
command, so this branch is never reached and **no Suricata event fires**. Suricata detects a
*rejected* upgrade; it cannot detect a *suppressed* one.

Also note: these are decoder **events**, not alerts. They produce nothing unless a rule matches
`app-layer-event:smtp.tls_rejected`. See §3.3.

**IMAP** (`src/app-layer-imap.c`, **96 lines**) contains only
`IMAPRegisterPatternsForProtocolDetection()` — pattern registration for protocol identification
(`" CAPABILITY"` etc.). **No parser, no state machine, no events, no STARTTLS handling.**

**POP3** — no `app-layer-pop3.c` exists in `src/`. The app-layer parser list is: dnp3, ftp, htp,
http2, ike, **imap**, modbus, nfs, **smtp**, ssh, **ssl**, tftp, smb. **POP3 has no application-layer
parser.**

**TLS.** Suricata's SSL/TLS parser does log version, cipher, SNI, and certificate subject/issuer/
fingerprint/validity where visible — comparable to Zeek's `ssl.log`.

### 3.3 Emerging Threats Open ruleset — inspected

Downloaded `emerging-smtp.rules`, `emerging-imap.rules`, `emerging-pop3.rules`
(suricata-7.0.3 branch).

| File | Active rules | Disabled | STARTTLS/STLS mentions |
|---|---|---|---|
| `emerging-smtp.rules` | 17 | 9 | **0** |
| `emerging-imap.rules` | 17 | 16 | **0** |
| `emerging-pop3.rules` | 9 | 11 | **0** |

**43 active rules across all three email protocols; not one references STARTTLS or STLS.**

Rule subjects are exclusively malware, exploit and blocklist signatures — e.g. *"ET SMTP Potential
Exim HeaderX with run exploit attempt"*, *"ET SMTP EXE - ZIP file with .pif filename inside"*,
*"ET SMTP Spamcop.net Block Message"*, *"GPL IMAP login literal buffer overflow attempt"*.

**INFERENCE.** ET Open's email rules target *content threats and known exploits*, not *transport
cryptographic posture*. This is a category difference, and it explains why Suricata's STARTTLS
decoder events go unused in practice: no shipped rule references them.

### 3.4 Wireshark / tshark — INFERRED (source not inspected)

Dissects SMTP, IMAP, POP and TLS thoroughly; `tshark -T fields` can extract handshake fields for
scripting. Its role is *dissection and display*, not security evaluation: it has no posture engine,
no finding generation, no severity model. An analyst can see a stripping attack in Wireshark **if
they already know to look for it** — which is precisely the expertise-gated manual workflow doc 01
§10.1 identified as the root problem.

### 3.5 Other tools — INFERRED, not inspected

| Tool | Expected role | Classification |
|---|---|---|
| **Snort 3** | Has an SMTP service inspector; the GPL IMAP rules in ET originate here. Same architecture as Suricata — signature/event based, no posture assessment. | INFERRED |
| **Arkime** | Full-packet indexing and retrieval; stores sessions with TLS metadata for search. A retrieval layer, not an analysis layer. | INFERRED |
| **NetworkMiner** | Forensic extraction of files/credentials/hosts from PCAP. Credential extraction may overlap capability **L**. | INFERRED — ⚠️ **worth direct inspection** |
| **RITA** | Beaconing/C2 analysis over Zeek logs. Unrelated to crypto posture. | N/A |
| **Security Onion** | Distribution bundling Zeek + Suricata. Inherits their capabilities exactly; adds no STARTTLS logic of its own. | INFERRED |
| **A-Packets** | Online/on-prem PCAP analyzer. Its own site lists cleartext credential detection for *"HTTP Basic/Digest, SIP Digest & SMB, NTLMv1/v2, Kerberos & LDAP, Postgres & MSSQL, Telnet/FTP"* — **email protocols are not listed**, and no security scoring or posture report is documented. | VERIFIED (vendor page) |

⚠️ **Conflicting evidence, recorded honestly.** A search summary claimed some web PCAP analyzer
flags *"SMTP AUTH on port 25/587 without prior STARTTLS, IMAP LOGIN on plain 143, POP3 USER/PASS on
plain 110"*. A-Packets' own page does **not** substantiate this. The claim may refer to a different
tool (ToolsWalla was also named). **Unresolved → OQ-17.** If some analyzer already ships exactly
that rule set, capability **L** is prior art and part of §9's gap narrows.

---

## 4. Capability matrix

Rows A–Q as specified. Zeek/Suricata/ET columns are source-verified; others inferred.

| # | Capability | Zeek | Suricata | ET Open | Wireshark | Academic | Evidence |
|---|---|---|---|---|---|---|---|
| A | STARTTLS advertisement observed | 🟡 PARTIAL (SMTP only, via `smtp_reply`; not logged) | 🟡 PARTIAL (parsed, not evented) | ❌ | 🟡 INFERRED (manual) | ✅ | Zeek smtp events; Suricata `SMTP_COMMAND_STARTTLS` |
| B | STARTTLS command observed | 🟡 PARTIAL (`smtp_request`) | ✅ VERIFIED (parse) | ❌ | 🟡 INFERRED | ✅ | `app-layer-smtp.c:1374` |
| C | Successful TLS upgrade | ✅ VERIFIED SMTP (`tls` bool); 🟡 IMAP (SSL handoff only); ❌ POP3 | ✅ VERIFIED SMTP; ❌ IMAP/POP3 | ❌ | 🟡 INFERRED | ✅ | `smtp_starttls`; `SCAppLayerRequestProtocolTLSUpgrade` |
| D | **Absence/suppression of STARTTLS** | ❌ NOT FOUND | ❌ NOT FOUND | ❌ | 🟡 manual | ✅ (measurement papers) | No shipped script/rule |
| E | **STARTTLS stripping** | ❌ NOT FOUND | ❌ NOT FOUND (§3.2 — event cannot fire) | ❌ | 🟡 manual | ✅ Durumeric, Poddebniak | — |
| F | **Downgrade to plaintext** | ❌ NOT FOUND | ❌ NOT FOUND | ❌ | 🟡 manual | ✅ NDSS'25 | — |
| G | Malformed STARTTLS negotiation | 🟡 PARTIAL (`smtp_unexpected`) | 🟡 PARTIAL (`TLS_REJECTED`, `FAILED_PROTOCOL_CHANGE`) | ❌ | 🟡 manual | ✅ | Suricata event table |
| H | **Command injection around STARTTLS** | ❌ NOT FOUND | ❌ NOT FOUND (`INVALID_PIPELINED_SEQUENCE` is adjacent, not equivalent) | ❌ | 🟡 manual | ✅ Poddebniak (CVEs exist) | — |
| I | **Response injection around STARTTLS** | ❌ NOT FOUND | ❌ NOT FOUND | ❌ | 🟡 manual | ✅ Poddebniak | — |
| J | Suspicious server responses | 🟡 PARTIAL (`blocklists.zeek` — different purpose) | 🟡 PARTIAL (`INVALID_REPLY`) | 🟡 (blocklist msgs) | 🟡 manual | ✅ | — |
| K | Protocol state inconsistencies | 🟡 PARTIAL (`smtp_unexpected`) | 🟡 PARTIAL (`INVALID_PIPELINED_SEQUENCE`, `UNABLE_TO_MATCH_REPLY_WITH_REQUEST`) | ❌ | 🟡 manual | ✅ | — |
| L | **Cleartext credentials after expected TLS** | ❌ NOT FOUND (no AUTH tracking — grep-verified) | ❌ NOT FOUND | ❌ | 🟡 manual | ✅ | ⚠️ see OQ-17 |
| M | Certificate visibility / validation | ✅ **VERIFIED** (`validate-certs`, `expiring-certs`, `weak-keys`, `x509.log`) | ✅ VERIFIED (TLS cert logging) | ❌ | ✅ | ✅ | Zeek policy scripts |
| N | TLS version / cipher / key exchange | ✅ **VERIFIED** (`ssl.log` + `Old_Version`/`Weak_Cipher` notices) | ✅ VERIFIED | ❌ | ✅ | ✅ | `weak-keys.zeek` ⚠️ outdated defaults |
| O | Session resumption behaviour | ✅ VERIFIED (`resumed` field) | 🟡 PARTIAL | ❌ | ✅ | ✅ | `ssl.log` |
| P | **Middlebox tampering evidence** | ❌ NOT FOUND | ❌ NOT FOUND | ❌ | 🟡 manual | ✅ Durumeric (banner-mangling signature) | — |
| Q | **Cross-flow SMTP+IMAP+POP3 correlation** | ❌ **IMPOSSIBLE** (no imap.log, no pop3.log) | ❌ **IMPOSSIBLE** (no IMAP parser, no POP3 parser) | ❌ | ❌ | 🟡 partial | §3.1, §3.2 |

**Summary.** Existing tools are **strong on M/N/O** (TLS and certificate posture — mature, shipped,
tested) and **absent on D/E/F/H/I/L/P/Q** (the STARTTLS attack surface and cross-protocol email
correlation).

---

## 5. Parsing vs. detection

The instructed six-question test, applied to the strongest existing candidates.

| Question | Zeek SMTP | Suricata SMTP | Zeek SSL (`weak-keys`) |
|---|---|---|---|
| 1. Observe relevant packets? | ✅ Yes | ✅ Yes | ✅ Yes |
| 2. Reconstruct protocol state? | ✅ Yes (analyzer tracks state; `smtp_unexpected` proves it) | ✅ Yes (explicit command/reply state machine) | ✅ Yes |
| 3. **Explicitly detect the security condition?** | ❌ **No** — sets a boolean | ❌ **No** for stripping; 🟡 partial for rejection | ✅ **Yes** — weak key/version/cipher |
| 4. Generate alert/log/evidence artifact? | 🟡 `tls` field only | 🟡 Event only; needs a rule that ET does not ship | ✅ Notice with subject + fingerprint |
| 5. Correlate multiple protocol events? | ❌ No | ❌ No | ❌ No (per-connection) |
| 6. Distinguish benign from attack? | ❌ No — cannot tell "no STARTTLS offered" from "STARTTLS stripped" | ❌ No | 🟡 Partially — but thresholds are outdated |

**The load-bearing row is 6.** `tls=F` in Zeek's `smtp.log` is produced identically by:
(a) a server that never supported STARTTLS, (b) a server that offered it but the client declined,
(c) an active attacker stripping the advertisement, and (d) implicit TLS on port 465 where STARTTLS
is irrelevant. **Distinguishing these four requires exactly the capability-vs-command-vs-upgrade
state reconstruction that no shipped tool performs.** This is the most defensible single sentence in
this document.

---

## 6. Academic baseline

| Work | Problem | Protocols | Active/Passive | Input | Mechanism | Open? | Overlap with SIH26159 | Leaves unresolved |
|---|---|---|---|---|---|---|---|---|
| **Durumeric et al., IMC 2015** | Internet-scale mail delivery security | SMTP | **Active** scan + Gmail-side passive | ZMap scans, provider logs | Measurement; banner-mangling fingerprint (`250 XXXXXXXX`) | Data partly | Establishes stripping is real at scale (426+ ASes) | Not a tool; no per-capture assessment |
| **Poddebniak et al., USENIX Sec 2021** | STARTTLS implementation security | **SMTP, IMAP, POP3** | **Active** (EAST test harness) | Live client/server testing | 100+ test cases; taxonomy: stripping, command injection, response injection, tampering, UI spoofing | EAST released | **Highest overlap** — defines the attack classes | **Tests endpoints actively; does not detect from a capture.** Our mode is different |
| **Holz/Amann et al., "TLS in the wild" (arXiv 1511.00341)** | TLS in email/messaging protocols | SMTP, POP3, IMAP, XMPP, IRC | **Passive** | Uplink traffic via Bro/Zeek | Extended Bro for STARTTLS protocols | Partly | **High** — closest passive precedent | Measurement study, ~2015; not an analyst tool; no posture output |
| **NDSS 2025, "A Multifaceted Study on the Use of TLS and Auto-detect in Email Ecosystems"** | Client downgrade behaviour | SMTP/IMAP/POP3 clients | **Active** | 49 email clients tested | Manual + auto-detect config testing; **19 of 49 clients may silently downgrade to no-TLS**; taxonomy O-TLS vs OO-TLS | Unknown | **High, and recent** | Client-side testing, not capture analysis |
| **`tintinweb/striptls`** | Attack/audit proxy | SMTP, POP3, IMAP, FTP, NNTP, XMPP, ACAP, IRC | **Active MITM** | Live proxy | Named vectors: `StripFromCapabilities`, `StripWithInvalidResponseCode`, `StripWithTemporaryError`, `StripWithError`, `ProtocolDowngradeStripExtendedMode`, `InjectCommand`, `UntrustedIntercept`, `InboundStarttlsProxy` | ✅ **CC0-1.0 public domain** | Generates the attacks we must detect | Attack tool only |
| **`swanoop/ssl-stripping-detector`** | SSL stripping in PCAP | **HTTP/web**, not email | Passive | PCAP | Python GUI heuristics | ✅ | Low — wrong protocol family | Not email; prototype-grade |

**Two conclusions.**

1. **The attack classes are 2015–2025 published research, not new.** Any novelty claim about
   *identifying* these attacks is dead on arrival. Poddebniak's taxonomy is the canonical reference
   and we should adopt its vocabulary rather than invent our own.
2. **Every email-focused work is ACTIVE except "TLS in the wild" (2015).** Poddebniak tests servers
   and clients; NDSS 2025 tests clients; Durumeric scans. **Passive detection from a capture is
   genuinely thinly covered** — and passive is exactly what SIH26159 mandates.

🎁 **Major practical finding: `striptls` is CC0-1.0 public domain and implements the exact attack
vectors we need as ground truth.** This collapses the hardest part of the 01A §11 experiment
(fabricating realistic attack captures) from "build a MITM proxy" to "run an existing tool". It also
gives us *named, citable* attack vectors that map 1:1 to detector test cases.

---

## 7. STARTTLS state machines and attack deviations

### 7.1 Expected (benign) state machines

```
SMTP (RFC 3207)                  IMAP (RFC 2595)               POP3 (RFC 2595)
─────────────────                ───────────────               ───────────────
S: 220 banner                    S: * OK banner                S: +OK banner
C: EHLO host                     C: a001 CAPABILITY            C: CAPA
S: 250-... 250-STARTTLS          S: * CAPABILITY ... STARTTLS  S: +OK ... STLS
C: STARTTLS                      C: a002 STARTTLS              C: STLS
S: 220 Ready to start TLS        S: a002 OK Begin TLS          S: +OK Begin TLS
   ── TLS handshake ──              ── TLS handshake ──           ── TLS handshake ──
C: EHLO host   (MUST re-issue)   C: a003 CAPABILITY (re-issue) C: CAPA (re-issue)
   ── encrypted session ──          ── encrypted ──               ── encrypted ──
```

RFC 3207 §4.2 requires the client to *"discard any knowledge obtained from the server"* not obtained
from the TLS negotiation, and it *"SHOULD send an EHLO command as the first command after a
successful TLS negotiation."* **The re-issued EHLO is therefore a passively checkable conformance
condition** — and its absence is a finding. Most tools ignore this entirely.

### 7.2 Attack deviations and passive reconstructability

| # | Deviation | Passive signature | Reconstructable? |
|---|---|---|---|
| 1 | Capability stripped from EHLO/CAPABILITY | Advertisement absent where server otherwise supports it; classic **`250 XXXXXXXX`** banner mangling (length-preserving, ~8k hosts in 2018) | ✅ **Yes** — mangling is direct evidence; pure omission needs a baseline (see caveat) |
| 2 | STARTTLS command altered in transit | Client sends `STARTFLS`/malformed verb; server returns 5xx | ✅ **Yes** — high confidence |
| 3 | Server 220 response removed | Client sent command, no 220, session continues cleartext | ✅ **Yes** |
| 4 | Response replaced with fake error | `454 TLS not available due to temporary reason` then cleartext continuation | ✅ **Yes** — matches `striptls` `StripWithTemporaryError` |
| 5 | STARTTLS attempted → unexpected cleartext continuation | SMTP verbs in cleartext after a 220 | ✅ **Yes** — strong, unambiguous |
| 6 | TLS handshake fails → insecure fallback | Handshake begins then alert/RST, then cleartext | ✅ **Yes** |
| 7 | Command injection (pre-220 buffer) | Commands appearing before the 220 / carried across the TLS boundary | ✅ **Yes** — the Poddebniak class |
| 8 | Response injection | Server responses not attributable to a client command | ✅ Yes |
| 9 | Downgrade of EHLO to HELO | `ProtocolDowngradeStripExtendedMode` — HELO has no extensions, so no STARTTLS possible | ✅ **Yes** — subtle and rarely checked |
| 10 | Cleartext `AUTH`/`LOGIN`/`USER`+`PASS` | Credentials in the clear | ✅ **Yes** — trivially, and high-severity |
| 11 | Timing-based "successful" stripping | Client library believes TLS started when it did not (cf. Ruby `net-imap` GHSA-vcgp-9326-pqcp) | 🟡 Partial — client-side state is not in the capture |

⚠️ **Honest caveat on deviation 1.** *Pure omission* of the advertisement is **not distinguishable
from a server that genuinely does not support STARTTLS** from a single session. This is a real
epistemic limit, and claiming otherwise would be exactly the "impossibility turned into a feature"
error. It can be partially resolved by: the mangling signature (direct evidence), or by
**cross-session baselining** — observing the same server offering STARTTLS on other connections in
the capture. That makes it a **multi-session inference**, correctly typed `inferred`, never
`observed`. This limitation is itself a good demonstration of the provenance discipline from 01A §4.

**INFERENCE.** 10 of 11 deviations are reconstructible from passive capture. All occur in the
cleartext phase, so **all are immune to the TLS 1.3 certificate limitation**.

---

## 8. "A competitor can already do this" test

The adversarial question: *"Why not just run Zeek + Suricata + Wireshark on the PCAP?"*

| SIH26159 requirement | Honest answer |
|---|---|
| D-01 PCAP ingest | ⚫ **Already solved.** Fully. |
| D-02 protocol ID | ⚫ **Already solved** for SMTP/IMAP; 🟡 POP3 via Zeek DPD signature only |
| D-03 TCP reassembly | ⚫ **Already solved.** Do not rebuild this. |
| D-06 TLS handshake parse | ⚫ **Already solved** (both tools) |
| D-07/08/09 version/cipher/KEX | ⚫ **Already solved** — `ssl.log` |
| D-10…D-14 certificates | ⚫ **Already solved** where visible — `x509.log`, `validate-certs.zeek`, `expiring-certs.zeek` |
| D-15 weak crypto / deprecated TLS | 🟡 **Partially solved** — `weak-keys.zeek` exists but **defaults miss TLS 1.0/1.1 and 3DES/NULL/anon** (§3.1). Fixing thresholds is a config change, not innovation |
| D-17 forward secrecy | 🟡 Derivable from `ssl.log` cipher; not reported as such |
| **D-04 STARTTLS detection** | 🟡 SMTP boolean only; **nothing for IMAP/POP3** |
| **D-05 STARTTLS validation** | 🔴 **Genuinely absent** |
| **D-16 insecure configuration** | 🔴 Largely absent as an email-specific notion |
| **D-18 crypto feature extraction** | 🟡 Zeek logs are a good feature source — arguably *should* be reused |
| A-01…A-05 AI layer | 🔴 Absent — but see §12 objection 7 |
| R-01…R-05 reporting/dashboard | 🔴 Absent. Zeek/Suricata emit logs and alerts, not analyst-ready posture reports |

**Verdict, stated plainly as instructed:** **A large fraction of SIH26159 — roughly the entire
extraction layer, D-01/02/03/06/07/08/09/10–14 — is already solved by Zeek and Suricata.** A
SecureMailScope that reimplements PCAP parsing, TCP reassembly, TLS dissection and X.509 handling
from scratch would be **rebuilding mature infrastructure worse**, and an informed evaluator should
say so.

What is **not** solved: the STARTTLS security state machine (D-05), IMAP/POP3 coverage at all, the
cross-protocol email view (Q), and the conversion of logs into an analyst-ready posture assessment.

---

## 9. The composability gap hypothesis

Tested as instructed: *is the opportunity not a new detector, but the absence of an integrated
pipeline?*

**Does any existing system perform the full chain — PCAP → email protocol reconstruction → STARTTLS
state reconstruction → TLS crypto analysis → cross-session correlation → evidence graph → findings →
severity reasoning → analyst-readable posture report?**

**Answer: No system found does this for email.** Evidence:

| Stage | Zeek | Suricata | Wireshark | Combined stack |
|---|---|---|---|---|
| Email protocol reconstruction | SMTP ✅, IMAP ⚠️, POP3 ❌ | SMTP ✅, IMAP ❌, POP3 ❌ | all ✅ manual | **IMAP/POP3 still uncovered** |
| STARTTLS state reconstruction | ❌ | ❌ | manual | ❌ |
| TLS crypto analysis | ✅ | ✅ | ✅ | ✅ |
| Cross-session correlation | ❌ | ❌ | ❌ | ❌ |
| Evidence graph | ❌ | ❌ | ❌ | ❌ |
| Severity reasoning | 🟡 notices | 🟡 rule severity | ❌ | 🟡 |
| Analyst posture report | ❌ | ❌ | ❌ | ❌ |

**The strongest verified statement available to us:**

> Even combining Zeek, Suricata and Wireshark, an analyst cannot obtain a cryptographic security
> posture assessment covering SMTP **and IMAP and POP3**, because **Zeek produces no `imap.log` and
> no `pop3.log`, and Suricata has no IMAP parser and no POP3 parser at all.** The evidence for two
> of the three protocols the PS names does not exist in stock tooling output.

**Label: POTENTIAL DIFFERENTIATION.** Explicitly **not** a novel research contribution.

**And the honest counter, which must be stated alongside it:** this gap exists because nobody
prioritised it, not because it is hard. A competent team could write Zeek scripts covering much of
§7.2 in perhaps a week. Our advantage would be **completeness, integration and analyst-facing
output**, which is *product* differentiation. That is legitimate — SIH is a build competition, not a
paper venue — but it must never be dressed up as research novelty.

**Architectural consequence to carry into Phase 14.** Building *on* Zeek (consuming `ssl.log`,
`x509.log`, `conn.log`) rather than reimplementing packet parsing is the technically honest choice,
and it directly answers §8. ⚠️ Counter-consideration: it adds a heavy external dependency, may
complicate offline/air-gapped deployment (A-02), and Zeek's per-host/per-day notice suppression
model is a poor fit for per-session forensic assessment. **Unresolved — flagged for Phase 14, not
decided here.**

---

## 10. Experiment specification

Extends 01A §11. **Specification only — not executed.** No infrastructure built this pass.

### 10.1 Corpus

| ID | Capture | Generation method |
|---|---|---|
| T1 | Clean SMTP STARTTLS | Postfix + client, direct |
| T2 | Clean IMAP STARTTLS | Dovecot + client |
| T3 | Clean POP3 STLS | Dovecot + client |
| T4 | **STARTTLS stripping** | `striptls` `StripFromCapabilities` |
| T5 | **Failed TLS upgrade** | `striptls` `StripWithError` |
| T6 | **Unexpected cleartext continuation** | `striptls` `StripWithTemporaryError` |
| T7 | **Command injection** | `striptls` `InjectCommand` |
| T8 | **Response injection** | `striptls` `StripWithInvalidResponseCode` |
| T9 | EHLO→HELO downgrade | `striptls` `ProtocolDowngradeStripExtendedMode` |
| T10 | TLS 1.2 baseline | server config |
| T11 | TLS 1.3 baseline | server config |
| T12 | Resumed session | repeat connection |
| T13 | Cleartext AUTH, no TLS | client config |
| T14 | Banner mangling `250 XXXXXXXX` | manual/proxy |

`striptls` is CC0-1.0, covers SMTP/POP3/IMAP, and its vector names become test-case IDs — giving
traceability from a published attack tool to each detector test.

### 10.2 Baseline measurement — the point of the experiment

For every capture, record what **today's tools** produce:

```
tshark -r <cap> -Y "smtp || imap || pop || tls"
zeek -r <cap>          # → conn.log, smtp.log, ssl.log, x509.log, notice.log
suricata -r <cap>      # → eve.json
```

**Deliverable: a table of `capture × tool × what an analyst actually learns`.** Predicted outcome
from this audit: for T4–T9 and T14, Zeek reports `tls=F` and nothing else; Suricata reports nothing
for stripping; neither reports anything at all for the IMAP and POP3 variants.

**⚠️ This table is the single most valuable artifact in the whole research programme.** It converts
"existing tools don't do this" from an assertion into a demonstration, it is reproducible by a
sceptical evaluator, and it directly answers the §8 competitor objection with evidence.

### 10.3 Falsifiers

| | |
|---|---|
| **F1** | Zeek or Suricata *does* flag T4–T9 → §4 rows D/E/F are wrong; the gap closes; re-plan immediately |
| **F2** | A Zeek community package already implements §7.2 → differentiation reduces to IMAP/POP3 coverage alone |
| **F3** | `striptls` cannot produce realistic captures against modern servers → corpus strategy needs rework |
| **F4** | Some PCAP analyzer already ships email cleartext-credential detection (OQ-17) → capability **L** is prior art |

---

## 11. Requirement mapping

Preserving the VERIFIED / INFERRED / NOT OBSERVABLE distinction from 01A.

| Req | Passively observable? | Existing tooling | Custom work required | Auxiliary evidence | Indeterminate cases |
|---|---|---|---|---|---|
| D-01 ingest | ✅ VERIFIED | ⚫ Solved | None | — | — |
| D-02 protocol ID | ✅ VERIFIED (cleartext); 🟡 INFERRED (implicit TLS) | ⚫ SMTP/IMAP; 🟡 POP3 | Implicit-TLS identification | — | Non-standard ports w/o banner |
| D-03 reassembly | ✅ VERIFIED | ⚫ Solved | None | — | Truncated captures |
| D-04 STARTTLS detect | ✅ VERIFIED | 🟡 SMTP bool only | **IMAP + POP3 entirely** | — | — |
| **D-05 STARTTLS validate** | ✅ VERIFIED | 🔴 **Absent** | **All of §7.2** | — | ⚠️ Pure omission vs. unsupported (§7.2 caveat) |
| D-06 handshake parse | ✅ VERIFIED (cleartext portion) | ⚫ Solved | None | — | TLS 1.3 post-SH ❌ NOT OBSERVABLE |
| D-07 version | ✅ VERIFIED | ⚫ Solved | None | — | — |
| D-08 cipher | ✅ VERIFIED | ⚫ Solved | None | — | — |
| D-09 key exchange | ✅ VERIFIED | ⚫ Solved | None | — | — |
| D-10–14 certificates | 🟡 CONDITIONAL | ⚫ Solved where visible | Provenance typing | Active probe / CT / key log | ❌ **NOT OBSERVABLE**: TLS 1.3, all resumption |
| D-15 weak crypto | ✅ VERIFIED | 🟡 Outdated defaults | **Re-bind to RFC 8996 / NIST** | — | Cert-level weakness limited by D-14 |
| D-16 insecure config | ✅ VERIFIED | 🔴 Absent (email-specific) | Bounded checklist | — | Scope undefined (AMB-06) |
| D-17 forward secrecy | ✅ VERIFIED | 🟡 Derivable | Reporting | — | — |
| D-18 features | ✅ VERIFIED | 🟡 Zeek logs usable | **Observability-aware encoding** | — | — |
| **Q cross-protocol** | ✅ VERIFIED | 🔴 **Impossible today** | **All of it** | — | — |
| A-01–A-05 | — | 🔴 Absent | See Phase 10 | — | — |
| R-01–R-05 | — | 🔴 Absent | All | — | — |

---

## 12. Red team: why SecureMailScope could still be a weak idea

| # | Objection | Response | Status |
|---|---|---|---|
| 1 | **Zeek already solves it** | Partly true and conceded for extraction (§8). But Zeek ships **no imap.log, no pop3.log**, and its SMTP STARTTLS output is one boolean. | 🟢 Answered |
| 2 | **Suricata already solves it** | No. `TLS_REJECTED` structurally cannot fire on capability stripping (§3.2), Suricata has no IMAP parser and no POP3 parser. | 🟢 Answered |
| 3 | **ET rules already cover it** | No. 43 active email rules, **zero** STARTTLS references. Wrong category — they target content threats. | 🟢 Answered |
| 4 | **Wireshark already exposes the evidence** | True, and that is the point: evidence ≠ assessment. Manual inspection is the expertise-gated workflow the PS is complaining about. | 🟢 Answered |
| 5 | **Judges may see it as a Zeek/Suricata wrapper** | ⚠️ **Legitimate risk.** Partly mitigated by the §10.2 baseline table showing what stock tools *fail* to produce. But if we build *on* Zeek (§9), "wrapper" is a fair description of part of the system. Mitigation is honesty plus demonstrated gap-closing, not denial. | 🟠 **Unresolved risk** |
| 6 | **Passive PCAP cannot validate enough certificates** | Confirmed and quantified: TLS 1.3 + all resumption. But only **5 of 22 deliverables** are cert-dependent (01A §5), and the STARTTLS layer is unaffected. | 🟢 Answered |
| 7 | **Crypto scoring is arbitrary** | ⚠️ **Largely valid.** Any weighting is a judgement call. Partially answerable by binding severity to RFC 8996 / NIST rather than inventing weights — but the *aggregation* into a single score remains arbitrary. | 🟠 **Unresolved risk** |
| 8 | **AI is unnecessary here** | ⚠️ **Substantially valid.** §7.2 detections are deterministic state-machine checks; ML would make them worse and less auditable. The PS title mandates AI, so the risk is *shoehorning*. Phase 10 must find where AI genuinely helps or state plainly that it does not. | 🟠 **Unresolved risk** |
| 9 | **STARTTLS attacks are old research** | Fully conceded — RFC 3207 §6 (2002), Durumeric 2015, Poddebniak 2021, NDSS 2025. **We claim no detection novelty.** The gap is that no passive tool implements them. | 🟢 Answered, with concession |
| 10 | **The PS may want something simpler** | ⚠️ Possible. The PS reads as a competent-engineering brief, not a research brief. Over-engineering is a genuine risk; so is under-delivering on its 22 explicit deliverables. | 🟠 **Unresolved risk** |
| 11 | **Prototype complexity exceeds SIH timeline** | ⚠️ Real. Mitigated by reusing Zeek/`striptls` rather than rebuilding, but the corpus work (01A §11, T10/X10 weak-crypto servers) remains the schedule risk. | 🟠 **Unresolved risk** |
| 12 | **A competitor could close the gap in a week** | ⚠️ **Valid and uncomfortable.** §7.2 as Zeek scripts is maybe a week's work for a strong team. Our defensibility rests on completeness + IMAP/POP3 + integration + reporting, not on any single detector. | 🟠 **Unresolved risk** |
| 13 | **Building on Zeek breaks offline/air-gap (A-02)** | Zeek runs fully offline, so the constraint is deployability/packaging, not connectivity. Genuine engineering cost though. | 🟡 Partially answered |
| 14 | **The §7.2 caveat undermines the flagship detection** | Honest: pure omission is indistinguishable from non-support in a single session. Answer is correct typing (`inferred`, multi-session baseline), not a stronger claim. | 🟡 Partially answered |

**Six unresolved risks.** The three most serious — **#5 wrapper perception, #8 AI shoehorning,
#12 easily-copied gap** — are strategic, not technical, and none is resolved by more protocol
research. They are Phase 10/14/15 questions.

---

## 13. Conclusions

**Survives prior-art scrutiny (POTENTIAL DIFFERENTIATION):**
1. **STARTTLS security state reconstruction across SMTP + IMAP + POP3.** Verified absent from all
   inspected tooling; two of three protocols have no log output at all.
2. **Cross-protocol email cryptographic posture** (capability Q). Structurally impossible today.
3. **Analyst-ready posture assessment from PCAP**, as opposed to logs and alerts.

**Rejected:**
1. ❌ Novelty in *detecting* STARTTLS attacks — published 2002–2025.
2. ❌ Evidence tiering as innovation — withdrawn in 01A §6.
3. ❌ Any claim to novelty in PCAP parsing, TCP reassembly, TLS dissection or X.509 validation —
   mature and solved (§8).
4. ❌ "Existing tools can't see this" — they *can see* it; they don't *evaluate* it. The distinction
   is the whole argument and must be stated precisely.

**Confidence: MEDIUM-HIGH.** Zeek, Suricata and ET claims rest on direct source inspection and are
high confidence. Snort, Arkime, NetworkMiner and commercial tools are `INFERRED` — a real hole
(OQ-18). The §10.2 baseline experiment would raise this to HIGH by demonstration.

---

## 14. New open questions

| ID | Question | Owner | Priority |
|---|---|---|---|
| **OQ-17** | Does any existing PCAP analyzer already ship email cleartext-credential / "AUTH without STARTTLS" detection? Conflicting evidence (§3.5) | research | **High** — narrows capability L |
| **OQ-18** | Do Snort 3, NetworkMiner or commercial NSM detect STARTTLS stripping? Not inspected | research | **High** — closes the audit hole |
| **OQ-19** | Does any Zeek community package (`zkg`) implement STARTTLS stripping detection? Searched, none found, but the index was not exhaustively enumerated | research | **High** — falsifier F2 |
| **OQ-20** | Build *on* Zeek or standalone? Trades integrity/effort against the "wrapper" perception (#5) and offline packaging | **team** + Phase 14 | High |
| **OQ-21** | Given §12 #8, where does AI genuinely add value when detections are deterministic? | Phase 10 | **High** |
| OQ-22 | Can pure-omission stripping be soundly inferred via multi-session baselining? | research + experiment | Medium |
