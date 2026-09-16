# 01C — OQ-18/OQ-19 Closure, Tool-Stack Reconstruction, and Competitor Audit

**Purpose:** Falsify the differentiation hypothesis by direct inspection before anything is built on it.
**Status:** Complete (v1) · **Date:** 2026-09-16
**Headline:** OQ-18 and OQ-19 both close **in our favour**. But an unplanned Part H search found
**~10 competing SIH 2026 teams with public repositories**, and **at least one has already implemented
the exact capability we identified as our differentiator.** H1 and H2 are dead.

---

## 1. Verdicts up front

| Question | Verdict |
|---|---|
| **OQ-18** (Snort / NetworkMiner / Arkime) | ✅ **RESOLVED.** None performs STARTTLS stripping detection or email crypto posture assessment. |
| **OQ-19** (Zeek `zkg` ecosystem) | ✅ **RESOLVED.** All **285** indexed packages enumerated: **zero** reference STARTTLS, STLS, IMAP, POP3, downgrade, credential, cipher or posture. |
| **Hypothesis vs. open-source tooling** | ✅ **Survives.** No general-purpose NSM/forensics tool does this. |
| **Hypothesis vs. SIH competitors** | 🔴 **FAILS.** Already built by at least one competing team, with test fixtures and RFC citations. |

> **The hypothesis was falsified — just not by the tools we were auditing.** We were looking in the
> wrong direction. The competition is not Zeek; it is the other ~10 teams answering SIH26159.

---

## 2. OQ-18 — Snort, NetworkMiner, Arkime

### 2.1 Snort 3 — inspected (community ruleset downloaded)

`snort3-community-rules.tar.gz` → `snort3-community.rules`: **4,017 active rules.**

| Search | Result |
|---|---|
| `starttls` / `stls` | **0 matches** |
| smtp / imap / pop3 mentions | 131 / 150 / 138 — **all legacy exploit signatures** |
| ssl / tls mentions | 69 — malware C2 and SSLv2 overflows |

Representative email rule subjects: *"PROTOCOL-POP EXPLOIT qpopper overflow"*, *"SERVER-MAIL
Sendmail 8.6.9 exploit"*, *"SERVER-MAIL ehlo cybercop attempt"*, *"SERVER-MAIL RCPT TO overflow"*.
TLS-adjacent: *"MALWARE-OTHER self-signed SSL certificate with default MyCompany Ltd organization
name"* — a malware IOC, not a posture check.

**Verdict:** Snort's email rules are 1990s–2000s memory-corruption signatures. **Zero cryptographic
posture capability.** Same category error as ET Open (01B §3.3).

### 2.2 NetworkMiner — vendor documentation (closed source)

**The strongest tool found for email *artifact* extraction.** Per Netresec's own page it parses
**SMTP, IMAP, POP3 and the implicit-TLS variants SMTPS, IMAPS, POP3S**; extracts *"email/chat/text
messages from SMTP, IMAP, POP3"*; extracts user credentials; and extracts *"X.509 certificates from
SSL encrypted traffic like HTTPS, SMTPS, IMAPS, POP3S, FTPS"*.

⚠️ **This materially overlaps capabilities L (cleartext credentials) and M (certificates) — more so
than Zeek or Suricata.** It is the best existing answer to "extract email security artifacts from a
PCAP."

**But:** it performs **no** STARTTLS downgrade detection, **no** protocol-tampering detection, and
**no** security scoring or posture assessment. It is an artifact-extraction and passive-asset-
discovery tool by design. Free edition vs. Professional ($1,300); both extract files, emails, certs.

⚠️ **Audit limitation:** closed source, so this rests on vendor documentation — weaker evidence than
the Zeek/Suricata/Arkime source inspection. A capability could exist and be undocumented.

### 2.3 Arkime — inspected (source)

`capture/parsers/` contains **`smtp.c` (1,173 lines), `imap.c` (276), `pop3.c` (147)**, plus
`tls.c`, `certs.c`. **Broader email protocol coverage than Zeek or Suricata.**

**`smtp.c` does recognise STARTTLS:**

```c
} else if (strncasecmp(line->str, "STARTTLS", 8) == 0) {
    arkime_session_add_tag(session, "smtp:starttls");
    *state = EMAIL_TLS;
    email->state[(which + 1) % 2] = EMAIL_TLS_OK;
    return 0;
}
```

Session tags emitted: `smtp:starttls`, `smtp:authlogin`, `smtp:authplain`, `smtp:authntlm`,
`smtp:bad-bdat`, `smtp:line-too-long`, `smtp:missing-subject-space`. It also base64-decodes NTLM
auth — so Arkime has **partial capability L for SMTP**.

🔴 **The decisive observation — and the cleanest illustration of "parsing ≠ detection" in this whole
audit.** In the `EMAIL_TLS` state, when cleartext SMTP continues *after* a STARTTLS exchange:

```c
case EMAIL_TLS: {
    if (remaining > 5 && memcmp(data, "EHLO ", 5) == 0) {
        g_string_truncate(line, 0);
        *state = EMAIL_CMD;                    // ← silently resumes cleartext parsing
        email->state[(which + 1) % 2] = EMAIL_CMD_RETURN;
        continue;
    }
```

**Arkime observes the exact downgrade condition and treats it as a parsing case to be handled
gracefully — not as a security finding.** It normalises the attack into successful parsing. No tag,
no alert, no evidence artifact.

**`imap.c` and `pop3.c`: grep for `starttls|stls|tls|ssl|encrypt` returns ZERO matches in both.**
IMAP extracts subject and folder names and an `imap:line-too-long` tag. POP3 (147 lines) does
essentially nothing security-relevant.

**On the "are we just an Arkime plugin?" question.** Arkime is a full-packet indexing and retrieval
platform — its role is search and pivot, not assessment. It has a plugin API, so *some* of this
could be an Arkime plugin. But that would inherit Arkime's Elasticsearch/OpenSearch deployment
footprint, which is a poor fit for an offline forensic tool on an analyst workstation (constraint
I-01 / A-02). **Considered and not recommended — but honestly, this is a defensible alternative
architecture we are choosing against, not one that is impossible.**

### 2.4 OQ-18 capability matrix

| # | Capability | Snort 3 | NetworkMiner | Arkime |
|---|---|---|---|---|
| A | SMTP parsing | 🟡 rules only | ✅ VERIFIED | ✅ VERIFIED (1,173 ln) |
| B | IMAP parsing | 🟡 rules only | ✅ VERIFIED | ✅ VERIFIED (276 ln) |
| C | POP3 parsing | 🟡 rules only | ✅ VERIFIED | ✅ VERIFIED (147 ln) |
| D | STARTTLS/STLS recognition | ❌ NOT FOUND | 🟡 INFERRED (handles implicit TLS) | ✅ SMTP only; ❌ IMAP/POP3 |
| E | Capability advertisement detection | ❌ | ❌ NOT FOUND | ❌ NOT FOUND |
| F | STARTTLS state-machine reconstruction | ❌ | ❌ | 🟡 **PARTIAL, SMTP only** — states exist, not evaluated |
| G | **Stripping detection** | ❌ | ❌ | ❌ **NOT FOUND** (condition observed, normalised) |
| H | **Downgrade detection** | ❌ | ❌ | ❌ NOT FOUND |
| I | Command injection detection | ❌ | ❌ | ❌ |
| J | Response injection detection | ❌ | ❌ | ❌ |
| K | Plaintext-after-TLS-failure | ❌ | ❌ | ❌ **explicitly normalised** |
| L | Cleartext credentials | ❌ | ✅ **VERIFIED** (all 3 protocols) | 🟡 PARTIAL (SMTP tags + NTLM decode) |
| M | Certificate analysis | ❌ | ✅ **VERIFIED** (incl. SMTPS/IMAPS/POP3S) | ✅ VERIFIED (`certs.c`) |
| N | TLS version analysis | ❌ | 🟡 INFERRED | ✅ VERIFIED (`tls.c`) |
| O | Cipher analysis | ❌ | 🟡 INFERRED | ✅ VERIFIED (`tls-cipher.h`) |
| P | Cross-session correlation | ❌ | 🟡 host-centric | ✅ VERIFIED (search platform) |
| Q | **Cross-protocol correlation** | ❌ | 🟡 PARTIAL (host view) | 🟡 PARTIAL (session search) |
| R | **PCAP → posture assessment** | ❌ | ❌ | ❌ |
| S | **Analyst-ready findings + packet evidence** | 🟡 alerts | ❌ artifacts only | 🟡 sessions, not findings |

---

## 3. OQ-19 — the Zeek package ecosystem

**Method:** downloaded `zeek/packages` → `aggregate.meta`, the canonical zkg index. **285 packages
enumerated in full** — not a name search.

| Keyword | Occurrences across all 285 packages |
|---|---|
| `starttls` | **0** |
| `stls` | **0** |
| `imap` | **0** |
| `pop3` | **0** |
| `downgrade` | **0** |
| `credential` | **0** |
| `cipher` | **0** |
| `posture` | **0** |
| `smtp` | 9 — all phishing-URL analysis and DLP |

**Every TLS/SSL-related package in the ecosystem:**

| Package | Purpose |
|---|---|
| `salesforce/ja3` | JA3 client fingerprints in `ssl.log` |
| `foxio/*` | JA4 fingerprinting |
| `0xxon/zeek-tls-log-alternative` | Richer `tls.log` for protocol-feature research |
| `anthonykasza/ssl-extensions` | PoC scriptland parsing of SSL extensions |
| `chrisanag1985/suppress-ssl-notices` | **Suppresses** `SSL::Invalid_Server_Cert` noise |
| `initconf/LetsEncrypt` | Let's Encrypt cert identification |
| CVE-2020-0601, CVE-2017-15361 checkers | Specific-CVE certificate detection |
| `stratosphereips/detect-DoH`, PQC detection, `sandialabs/gait` | Fingerprinting/classification |

**Verdict: OQ-19 RESOLVED.** The Zeek ecosystem's TLS work is **fingerprinting and logging**, not
posture assessment. There is **no** email-protocol security package. One package exists purely to
*suppress* certificate notices — a telling indicator that the community treats Zeek's existing
certificate detection as noise rather than as assessment.

**Answer to the Part E question — "could an analyst install existing packages and get
SecureMailScope?"** **No.** Not from any combination. The IMAP/POP3 evidence does not exist to
combine, and no package addresses STARTTLS.

---

## 4. Part F — strongest existing-tool stack reconstruction

| # | Stack | Satisfies | Fails | Manual interpretation? | Cross-protocol? | Posture report? | Evidence→finding link? | Deterministic? | Air-gapped? |
|---|---|---|---|---|---|---|---|---|---|
| 1 | **Zeek alone** | D-01/02/03/06–14, D-15 (weak defaults), D-17 | D-04 (bool), D-05, D-16, Q, all R | High | ❌ no imap/pop3 log | ❌ | 🟡 notices→uid | ✅ | ✅ |
| 2 | **Zeek + packages** | Same + JA3/JA4 | **Same — packages add nothing here (§3)** | High | ❌ | ❌ | 🟡 | ✅ | ✅ |
| 3 | **Suricata + ET** | D-01/02/03/06–14 | D-04/05, IMAP, POP3, Q, R | High | ❌ | ❌ | 🟡 alert→packet | ✅ | ✅ |
| 4 | **Zeek + Suricata** | Union of above | D-05, IMAP/POP3 evidence, Q, R | High | ❌ | ❌ | 🟡 | ✅ | ✅ |
| 5 | **Arkime + Zeek/Suricata** | Above + retrieval, SMTP STARTTLS tag, all 3 protocols parsed | D-05, G/H/I/J/K, R | High | 🟡 via search | ❌ | ✅ session pivot | ✅ | 🟡 ES/OS footprint |
| 6 | **tshark + scripts** | Anything, with effort | Nothing structurally — but it is *bespoke scripting*, i.e. building our tool | Very high | 🟡 if scripted | ❌ | manual | ✅ | ✅ |
| 7 | **Security Onion** | Union of Zeek+Suricata+Arkime | Identical gaps — bundles, adds no email TLS logic | High | 🟡 | ❌ | 🟡 | ✅ | 🟡 heavy |

**Strongest existing stack: Option 5 (Arkime + Zeek + Suricata), or Option 7 which bundles it.**

**What even the best stack cannot give an analyst:** a STARTTLS security verdict for any protocol;
any IMAP or POP3 security evidence beyond "a TLS session happened"; any cryptographic posture
assessment; any finding-level report. The analyst gets logs, tags and search — and must supply all
judgement themselves. **This is exactly the root problem from doc 01 §10.1, and it is confirmed.**

---

## 5. Part G — the one-week competitor test

Qualitative estimates, as instructed. No fabricated hours.

| Component | Zeek extension | Standalone (Py/Rust/Go) | Zeek+Suricata orchestration | Arkime plugin | Commodity? |
|---|---|---|---|---|---|
| PCAP handling | **LOW** (free) | **MEDIUM** (dpkt/scapy/pcap libs exist) | LOW | LOW | ⚫ Commodity |
| TCP stream reconstruction | **LOW** (free) | **HIGH** — retransmits, overlap, gaps | LOW | LOW | ⚫ Commodity *(in Zeek)* |
| TLS metadata extraction | **LOW** (free) | **MEDIUM-HIGH** | LOW | LOW | ⚫ Commodity |
| Certificate handling | **LOW** (free) | **MEDIUM** (cryptography libs) | LOW | LOW | ⚫ Commodity |
| SMTP state reconstruction | **LOW** (events exist) | MEDIUM | LOW | LOW | 🟡 Semi |
| **IMAP state reconstruction** | **MEDIUM-HIGH** (no analyzer output) | MEDIUM | MEDIUM-HIGH | MEDIUM | 🟢 Real work |
| **POP3 state reconstruction** | **HIGH** (no analyzer at all) | MEDIUM | HIGH | MEDIUM | 🟢 Real work |
| STARTTLS attack detection | **LOW-MEDIUM** | LOW-MEDIUM | MEDIUM | MEDIUM | 🟡 Semi — *logic is simple once state exists* |
| Cross-session correlation | MEDIUM | MEDIUM | MEDIUM | **LOW** (Arkime's strength) | 🟡 Semi |
| Crypto posture model | **MEDIUM** | MEDIUM | MEDIUM | MEDIUM | 🟢 Real work *(judgement, not code)* |
| **Evidence/observability model** | MEDIUM-HIGH | MEDIUM-HIGH | HIGH | HIGH | 🟢 **Real work — and rare (§7)** |
| Report generation (JSON/PDF/HTML) | HIGH (Zeek is poor at this) | **LOW-MEDIUM** | MEDIUM | MEDIUM | ⚫ Commodity |
| Test corpus | MEDIUM (`striptls` helps) | MEDIUM | MEDIUM | MEDIUM | 🟡 Semi |
| UI/dashboard | HIGH | **LOW-MEDIUM** | HIGH | LOW (inherits Arkime) | ⚫ Commodity |

**Honest conclusion on the objection.** *Partially valid.* A strong team **could** produce a credible
SMTP-only STARTTLS detector on Zeek in about a week — the detection logic is genuinely simple once
protocol state exists. What does **not** fit in a week: **IMAP and POP3 state reconstruction**
(Zeek gives no output; POP3 has no analyzer), a coherent posture model, and the observability model.

**The commodity/real-work split is the actionable finding:** everything in the extraction layer is
commodity. The real work is **IMAP/POP3 coverage, the posture judgement model, and the evidence
model** — which is where effort should go, and which is the opposite of where a typical team will
spend it.

---

## 6. 🔴 Part H — the finding that changes everything

Searching for complete systems, I did not find a mature commercial or FOSS product for this
niche — the space is, as one search result put it, dominated by hackathon-era prototypes.

**It is dominated by our direct competitors.** At least **10 public repositories** answering
SIH26159 exist, all created within the last three weeks:

| Repo | Created | Last push | Size | Lang |
|---|---|---|---|---|
| `soumyajit-cys/CipherPost` | 2026-09-01 | **2026-09-15** | 14.7 MB | Python |
| `fredfe08/SecureMailScope` | 2026-09-05 | 2026-09-07 | 32.8 MB | Python |
| `gouravsehlangia/SecureMailScope` | 2026-09-10 | 2026-09-13 | 926 KB | Python |
| `saravana-rr0411/SecureMailScope` | 2026-09-11 | 2026-09-14 | 1.3 MB | Python |
| `13-saksham/Cryptoscope` | 2026-09-12 | 2026-09-12 | 41 KB | Python |
| `shashwat4130/MailRakhwala` | 2026-09-13 | **2026-09-15** | 80 KB | Python |
| `ArpitSingh-01/Prahari-` | 2026-09-14 | 2026-09-14 | 505 KB | Python |
| `kris-5710/securemailscope` | 2026-09-08 | 2026-09-08 | 71 KB | TypeScript |
| Plus `Daddy-Dagger/SecureMailScope`, `Helishah12/SecureMail`, `priyansh3161/CYBER-Shield`, `Groy416/SecureMail-ML-Backend` | | | | |

### 6.1 CipherPost — source-verified, and it already has our differentiator

65 Python files; `backend/app/` split into `api`, `core`, `live`, `ml`, `models`, `parsing`,
`reporting`. Key modules by size: `rules.py` (19 KB), `reassembly.py` (13 KB), `handshake.py`
(13 KB), `certificates.py` (9 KB), `generate_corpus.py` (**31 KB**), `reporting/generator.py` (9 KB).

**Test fixtures found:** `tests/fixtures/smtp_starttls_strip.json`,
**`tests/fixtures/imap_starttls_strip.json`**, `tests/fixtures/smtp_tls12_starttls.json`.

**The actual rule, from `rules.py`:**

```python
def rule_starttls_strip(sa: SessionAnalysis):
    if sa.saw_starttls_offer and not sa.started_tls and not sa.tls_bytes:
        ...  "starttls-strip-attempt", "Possible STARTTLS stripping",
             "STARTTLS advertised but no handshake followed",
             ... "RFC 3207 §4.1.2; OWASP SMTP Transport Security through STARTTLS"
```

Their `SessionAnalysis` carries `is_starttls`, `saw_starttls_offer`, `started_tls`, `tls_bytes` —
**a multi-fact STARTTLS state model**, which is precisely the "distinguish the four causes of
`tls=F`" insight from 01B §5. They also ship `rule_ssl_in_plaintext` for cleartext mail sessions.

> 🔴 **A competing team has already built, tested and cited what 01B identified as our strongest
> differentiation — including IMAP stripping, which I claimed was uncovered.**

### 6.2 What the README-vs-code check revealed

⚠️ **Not all claims are real, and this matters for calibration.** Search summaries credited
`fredfe08/SecureMailScope` with tracking STARTTLS as *"four separate facts (advertised, attempted,
acknowledged, tls_followed)"* — the idea closest to our own. **Direct inspection of its `models.py`
and `analyze.py` found zero matches for `starttls`, `advertised`, `attempted`, `acknowledged` or
`tls_followed`.** That claim lives in a README, not in code. Its `tls-engine/` contains
`spf_checker.py`, `dkim_checker.py`, `dmarc_checker.py` — i.e. **that team made exactly the
DNS-scope error identified in doc 01 §8.**

**Lesson, and a vindication of the method:** competitor READMEs are marketing. Only source
inspection counts. Several of these repos are likely thinner than they advertise — but **CipherPost
is not**, and it is still being actively developed.

### 6.3 Verified gaps in CipherPost — where white space survives

Grep of `rules.py` (486 lines):

| Concern | Result |
|---|---|
| **POP3 rules** | **1 mention — in a comment.** No POP3/STLS state rules. |
| **Session resumption / PSK** | A `session_id` field exists; **no resumption logic.** Resumed sessions will be mishandled. |
| **Observability / provenance / confidence / coverage** | **ZERO matches** for `provenance`, `inherited`, `confidence`, `coverage`, `unobservable`, `not_observed`. |
| TLS 1.3 | Version constants present, but **no handling of "certificate not observable under TLS 1.3."** |

⚠️ Two likely **correctness defects** visible in their rules, which we should not replicate:
`ALLOWED_TLS_VERSIONS = {0x0303: "deprecated-baseline", 0x0304: "current"}` labels **TLS 1.2 as
deprecated** — more aggressive than NIST SP 800-52r2 supports; and a rule flags TLS 1.3 sessions
that negotiate no ALPN, but **ALPN is not standard practice for SMTP**, so that is a false-positive
generator.

---

## 7. Part I — hypothesis verdicts

| | Hypothesis | Verdict | Reasoning |
|---|---|---|---|
| **H0** | STARTTLS attack detection is novel | ❌ **REJECTED** | RFC 3207 §6 (2002), Durumeric 2015, Poddebniak 2021, NDSS 2025 — *and* CipherPost has shipped it. |
| **H1** | Cross-protocol STARTTLS state reconstruction is missing from common passive tooling | ⚠️ **PARTIALLY SURVIVES — but useless** | **True of general tooling** (verified: Zeek/Suricata/Snort/Arkime/NetworkMiner/285 zkg packages). **False of competitors** — CipherPost covers SMTP + IMAP. Only POP3 remains genuinely uncovered everywhere. A differentiator that competitors already have is not a differentiator. |
| **H2** | Existing tools expose primitives but don't compose them into email crypto posture | ❌ **REJECTED** | True of general tooling; **CipherPost, Prahari and others are precisely this composition.** |
| **H3** | Evidence-linked analyst-ready reporting is the differentiator | ⚠️ **PARTIALLY SURVIVES (weak)** | Competitors ship JSON/HTML/PDF, dashboards, SHAP explanations, compliance mapping. Differentiation would rest on *quality*, which is unprovable in advance and a poor strategic bet. |
| **H4** | Offline/air-gapped PCAP-native assessment is the differentiator | ❌ **REJECTED as differentiator** | Table stakes. Nearly every competitor claims offline-first. It is a *requirement* (I-01), not an edge. |
| **H5** | AI-assisted reasoning over deterministic evidence is the differentiator | 🟡 **UNRESOLVED — and I remain sceptical** | Competitors already ship Isolation Forest, SHAP, LLM recommendations. "We also have AI" differentiates nothing. §8. |

### Surviving differentiation, honestly stated

**None of H0–H5 survives as a headline claim.** What survives is narrower, and is *correctness*
rather than capability:

1. **Evidence-observability discipline.** Verified absent from CipherPost's rules engine (zero
   provenance/confidence/coverage terms) and from every tool audited. **Not novel** — Delgado 2026
   published the method (01A §6) — but **nobody building this PS is doing it.** It is the difference
   between a tool that makes false forensic claims about TLS 1.3 and resumed sessions, and one that
   does not.
2. **POP3/STLS completeness.** The one protocol uncovered by *both* general tooling and the
   strongest competitor. Small, but verifiable and defensible.
3. **Resumption-aware certificate reasoning** (01A §2.2). Absent from competitors; a real source of
   false findings for anyone without it.
4. **Validation against ground truth.** The 01B §10.2 baseline table — *demonstrating* what stock
   tools fail to produce. ⚠️ Contested: CipherPost ships a 31 KB `generate_corpus.py`, so even this
   is not uniquely ours.

**Label: POTENTIAL DIFFERENTIATION, execution-grade.** These are reasons our output would be *more
correct*, not reasons it would be *more capable*. That is a legitimate but much weaker position than
we held this morning, and it should be stated plainly rather than inflated.

---

## 8. Part J — candidate white space, with prior-art checks

| # | Candidate | Prior art | Verdict |
|---|---|---|---|
| 1 | Cross-protocol security state graph | No direct prior art found in email context | 🟡 Worth Phase 11 — but is a graph *useful* or decorative? |
| 2 | Email-session evidence graph | Evidence graphs common in DFIR generally | 🟡 Weak |
| 3 | Posture from heterogeneous PCAP evidence | Delgado 2026 (multi-surface) | ❌ Prior art |
| 4 | Automated forensic timeline reconstruction | Standard DFIR practice (plaso, log2timeline) | ❌ Prior art |
| 5 | Deterministic detection + evidence-grounded AI explanation | CipherPost (SHAP), others (LLM recs) | ❌ Contested |
| 6 | **Protocol downgrade *chain* reconstruction** | Not found — competitors detect *per-session* | 🟢 **Worth investigating** |
| 7 | "Why is this connection insecure?" causal explanation | Adjacent to SHAP/XAI | 🟡 Weak |
| 8 | **Repeated-session posture aggregation** | Not found in competitors (all per-session) | 🟢 **Worth investigating** — also enables OQ-22 |
| 9 | Infrastructure-level posture from multiple captures | Not found | 🟢 Worth investigating |
| 10 | Posture comparison across captures/time | Not found in this niche | 🟢 Worth investigating |
| 11 | **Synthetic PCAP → ground-truth validation framework** | `striptls` exists; CipherPost has a corpus generator | 🟡 Contested but underdeveloped |
| 12 | Analyst decision-support rather than another IDS | Framing, not capability | 🟡 Positioning only |

**Most promising cluster: #6, #8, #9, #10 — all multi-session / longitudinal.** Every competitor
inspected reasons **per-session**. Aggregating across sessions and captures enables things
single-session tools structurally cannot do: distinguishing "server does not support STARTTLS" from
"STARTTLS was stripped on this connection" by baselining the same server elsewhere in the capture
(the 01B §7.2 caveat, and OQ-22), reconstructing downgrade chains, and posture drift over time.

⚠️ **Not yet a claim.** Prior-art checked only by search, not by inspection of every competitor's
code. Phase 11 must verify before this is relied upon — **and given that the last two hypotheses
died on contact with evidence, it should be assumed fragile until checked.**

---

## 9. Answers to the 13 required questions

1. **OQ-18 verdict** — RESOLVED. Snort: 4,017 rules, zero STARTTLS, legacy exploit sigs only.
   NetworkMiner: strong email artifact + certificate extraction, **no** detection or posture.
   Arkime: parses all three protocols, tags `smtp:starttls`, **silently normalises the downgrade
   condition** rather than flagging it; IMAP/POP3 parsers contain zero TLS logic.
2. **OQ-19 verdict** — RESOLVED. All 285 zkg packages enumerated; zero for starttls/stls/imap/pop3/
   downgrade/credential/cipher/posture. Existing TLS packages do fingerprinting and logging; one
   exists to *suppress* certificate notices.
3. **Strongest existing toolchain** — Arkime + Zeek + Suricata (≈ Security Onion). Gives logs, tags,
   search and retrieval. Gives **no** STARTTLS verdict, **no** IMAP/POP3 security evidence, **no**
   posture assessment.
4. **Strongest remaining gap** — evidence-observability discipline, POP3/STLS coverage, and
   multi-session/longitudinal posture. All execution-grade, none novel.
5. **H0–H5** — §7. H0 ❌, H1 ⚠️(true but useless), H2 ❌, H3 ⚠️weak, H4 ❌, H5 🟡unresolved.
6. **Top 3 surviving** — (i) observability/provenance correctness; (ii) POP3/STLS completeness;
   (iii) multi-session posture aggregation *(unverified)*.
7. **Top 3 rejected** — (i) STARTTLS detection novelty; (ii) composability gap; (iii) offline
   operation as an edge.
8. **Wrapper risk?** — 🟡 **Partly yes, and we must stop pretending otherwise.** The extraction layer
   is commodity. If we build on Zeek we *are* partly a wrapper; if we reimplement, we rebuild
   commodity infrastructure worse. **The honest position is that our value is in the judgement and
   evidence layer, and to say so directly.**
9. **Standalone analyzer justified?** — 🟡 Qualified yes, for POP3/IMAP (no upstream to reuse) and
   for offline deployability. Not for TCP reassembly or TLS parsing.
10. **Build on Zeek?** — **Unresolved (OQ-20).** For: correctness, no reinvention, credibility.
    Against: no IMAP/POP3 output to build on — the exact gap we target — plus deployment weight and
    "wrapper" perception. **Provisional lean: hybrid — reuse Zeek/tshark for TLS and certificates,
    implement mail-protocol state ourselves.** To be decided in Phase 14, not here.
11. **Legitimate AI role?** — **Not established.** §7 H5. Every detection identified is a
    deterministic state-machine check; ML would make them worse and less auditable, and competitors
    already ship Isolation Forest + SHAP + LLM recommendations. **OQ-21 is now the single most
    important open question**, because the PS title mandates AI and we currently have no honest
    justification for it. Candidates to evaluate in Phase 10 (none novel): evidence-grounded NL
    explanation, analyst query interface over evidence, anomaly clustering, cross-session
    behavioural summarisation, prioritisation across many findings.
12. **Top unresolved questions** — OQ-21 (legitimate AI role), OQ-20 (Zeek or standalone),
    OQ-23 (does multi-session posture survive competitor inspection?), OQ-01 (deadline), A-01 (PS
    text verification).
13. **Next phase recommendation** — §10.

---

## 10. Recommendation

**Do not begin Phase 3 as originally scoped.** Stakeholder analysis is not the binding constraint;
**differentiation is**, and it just collapsed.

**Recommended next action — a competitor code audit, not more tool research.** We have exhausted the
general-tooling question: Zeek, Suricata, Snort, ET, Arkime, NetworkMiner and all 285 zkg packages
are done, and they all come back the same way. The live uncertainty is now entirely in the
competitor repos, and only CipherPost has been inspected.

Specifically: inspect `Prahari-`, `saravana-rr0411`, `gouravsehlangia` and `MailRakhwala` at source
level — READMEs are demonstrably unreliable (§6.2) — to establish (a) whether any handles POP3/STLS,
(b) whether any implements observability/provenance, (c) whether any reasons across sessions, and
(d) what their AI layers actually do. That directly tests the three surviving hypotheses and OQ-21.

**Then** Phase 10 (AI opportunity), because OQ-21 is unresolved and the PS mandates AI.
**Then** Phase 3.

⚠️ **Standing caution, per the non-negotiable rule.** Everything above is *"I found no public
evidence"*, never *"I verified no tool does this."* The audit covered the strongest candidates by
direct inspection; NetworkMiner is documentation-only, commercial NSM is largely unexamined, and
competitor repos change daily — CipherPost was pushed to yesterday.
