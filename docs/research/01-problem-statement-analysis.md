# 01 — Problem Statement Forensics & Problem Definition

**Covers:** Phase 0 (reconnaissance), Phase 1 (PS forensics), Phase 2 (actual problem definition)
**PS:** SIH26159 · **Organization:** National Technical Research Organisation (NTRO)
**Version:** v1 · **Date:** 2026-09-16

---

## 1. Phase 0 — Repository baseline

### 1.1 What actually exists

Full inspection of the working tree, all git refs, the object database, the reflog, stash, and
`git fsck` unreachable objects:

| Property | Finding |
|---|---|
| Tracked files | **1** — `README.md`, containing the single line `# SecureMailScope` |
| Commits | **1** — `9130b28` "Initial commit", 2026-09-16 10:23 IST, author `Sidd_927 <siddhantpatil.hak@gmail.com>` |
| Branches | `main` only; `origin/main` at the same commit |
| Tags, stashes, unreachable objects, reflog history | None beyond the initial clone |
| Git objects ever created | 3 (1 commit, 1 tree, 1 blob) — no deleted or orphaned work |
| Remote | `git@github.com:Sidd927/SecureMailScope.git` |
| Source code, dependencies, config, datasets, notebooks, prototypes | **None** |
| CI, IDE config, `.cursorrules`, `.github/`, agent instruction files | **None** |

**FACT.** There is no prior implementation, experiment, dataset, or written decision in this
repository. The baseline is genuinely empty.

### 1.2 What this baseline does *not* tell us

The brief correctly warns against assuming an empty repository means nothing has been decided.
It does not. The following remain unknown from repository evidence alone:

- **OQ-10** *(team)* — Decisions made verbally, in chat, in slide decks, or in an SIH idea-submission
  draft that exist outside version control.
- **OQ-11** *(team)* — Whether an idea has already been submitted to the SIH portal for this PS,
  and if so what it committed us to. This constrains everything downstream; an already-submitted
  abstract is effectively a locked requirement.
- **OQ-12** *(team)* — Team composition and skill distribution (network/protocol engineering vs.
  ML vs. frontend). This is the dominant input to feasibility in Phase 15.

I could not inspect the GitHub remote's issues, wiki, or projects: the `gh` CLI is not installed on
this machine (`command not found: gh`). Remote refs were checked directly via `git ls-remote` and
contain only `main` at `9130b28`, so no hidden branches exist. See *Capability gaps* in
`RESEARCH_STATUS.md`.

---

## 2. Provenance of the problem statement

**FACT.** The verbatim PS text was obtained from a mirror of the official portal, not retyped from
the brief. Chain of custody:

| Step | Detail |
|---|---|
| Origin | `https://sih.gov.in/sih2026PS` (official SIH 2026 portal) |
| Mirror | `NoBugNinja/Smart-India-Hackathon-SIH-2026-Problem-Statements`, file `data/sih2026_ps_20260822_211225.json` |
| Mirror scrape timestamp | **2026-08-22T21:12:25** (self-reported by the dataset) |
| Retrieved by us | 2026-09-16 |
| Records in dataset | 226 — matches the independently reported count of 226 PS for SIH 2026 |
| Stored locally | `evidence/SIH26159-official-ps.json`, `evidence/sih2026-all-ps-20260822.json` |

**Cross-check performed.** PS ID, exact title, organization (NTRO), category (Software) and theme
(Blockchain & Cybersecurity) independently agree across the mirror dataset and a second, unrelated
PS browser (`zaidsayyed.in`). The two sources were produced by different people from the same
upstream portal.

**Limitation — read this before trusting §4.** The *full description body* has been verified against
**one** upstream-derived source only. The live portal paginates and renders via JavaScript, so
direct re-fetch of the SIH26159 detail page did not succeed in this session. The mirror is
**25 days old** at time of writing.

> **ASSUMPTION A-01** — The description text in `evidence/SIH26159-official-ps.json` is the current,
> unmodified official text. *Falsifiable; verification is the first action in `RESEARCH_STATUS.md`.*
> **Risk if wrong:** low-to-moderate. PS bodies are rarely edited after publication, but a silent
> edit would invalidate the requirement IDs below.

---

## 3. Official metadata

| Field | Value | Label |
|---|---|---|
| PS Number | SIH26159 | FACT |
| Title | SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications | FACT |
| Organization / Department | National Technical Research Organisation (NTRO) | FACT |
| Category | Software | FACT |
| Theme | Blockchain & Cybersecurity | FACT |
| Dataset | *"Synthetic - Participants May generate IMAPS, POP3S, SMTPS Data using any E-mail server/client of their interest and capture pcap dump"* | FACT |
| YouTube link | *(empty)* | FACT |
| Contact info | *(empty)* | FACT |
| Submitted ideas | `0/500` as of 2026-08-22 (a second source showed `1` in mid-September) | FACT |
| Idea submission deadline | **20 September 2026** per the PS record — but see §9.1, sources conflict | FACT (disputed) |

Three metadata facts carry more weight than they appear to:

- **Empty contact info and no YouTube briefing.** **INFERENCE** — there is no official channel to
  resolve the ambiguities in §7. Every ambiguity must be resolved by *documented, defensible
  interpretation*, not by asking. This raises the value of writing our interpretation down
  explicitly in the submission, which most competing teams will not do.
- **"Synthetic" dataset.** NTRO supplies **no data**. Data generation is our problem, and it is a
  first-class engineering deliverable, not setup work. See §6.3.
- **`0/500` submissions.** **Do not treat low submission count as evidence of a good problem** —
  the brief is right to warn about this. It is equally consistent with the PS being hard, narrow,
  or unattractive. It is weak evidence about competition levels and nothing more.

---

## 4. Verbatim problem statement

Reproduced exactly from `evidence/SIH26159-official-ps.json`. Bullet glyphs and the irregular
spacing of `• Objectives-` are as published.

> • Background Electronic mail remains one of the most critical communication services for
> governments, enterprises, financial institutions, and academic organizations. Despite the
> widespread adoption of Transport Layer Security (TLS), many SMTP, IMAP, and POP3 deployments
> continue to suffer from cryptographic misconfigurations such as obsolete TLS versions, weak
> cipher suites, insecure STARTTLS implementations, expired or improperly configured certificates,
> and non-compliance with modern security standards. These weaknesses expose email infrastructures
> to downgrade attacks, man-in-the-middle attacks, passive interception, and other cryptographic
> threats.
>
> Although existing network analysis tools provide extensive packet-level visibility, they
> primarily focus on protocol decoding and traffic inspection. They do not automatically evaluate
> the overall cryptographic security posture of email communications or provide intelligent risk
> assessment and prioritization for security analysts.
>
> • Description Design and develop an AI-assisted passive network forensic framework capable of
> analyzing captured network traffic (PCAP files) containing SMTP, IMAP, and POP3 communications to
> automatically assess the cryptographic security posture of enterprise email infrastructures.
>
> The proposed solution shall reconstruct complete email communication sessions, identify
> encryption transitions, analyze TLS negotiations, validate digital certificates, detect
> cryptographic weaknesses, and leverage Artificial Intelligence/Machine Learning techniques to
> classify security risks, detect anomalous TLS behavior, and generate actionable security
> recommendations.
>
> The framework should assist Security Operations Centers (SOC), Digital Forensics teams, Incident
> Response teams, and enterprise administrators in rapidly identifying cryptographic
> vulnerabilities, prioritizing remediation efforts, and ensuring compliance with modern
> cryptographic best practices.
>
> • Objectives- The proposed system should be capable of:
> • Passive analysis of encrypted SMTP, IMAP, and POP3 traffic from PCAP files.
> • Automatic identification of application-layer email protocols.
> • Detection of STARTTLS negotiation and encrypted session upgrades.
> • Reconstruction of complete TCP communication streams.
> • Parsing and reconstruction of TLS handshakes.
> • Extraction and validation of X.509 digital certificates.
> • Identification of negotiated TLS versions, cipher suites, and key exchange mechanisms.
> • Detection of deprecated protocols, weak cipher suites, insecure cryptographic algorithms, and
> certificate-related vulnerabilities.
> • Extraction of cryptographic features for intelligent analysis.
> • Application of AI/ML techniques for:
> • Cryptographic risk classification.
> • Detection of anomalous TLS behavior.
> • Security posture scoring.
> • Threat prioritization.
> • Recommendation of mitigation measures.
> • Generation of comprehensive forensic reports and security dashboards.
>
> Expected Solution/Deliverables:
> The solution should provide the following outputs:
> • Automatic identification of SMTP, IMAP, and POP3 protocols.
> • STARTTLS negotiation detection and validation.
> • Complete TCP stream reconstruction.
> • TLS handshake reconstruction.
> • Detection of negotiated TLS versions.
> • Identification of negotiated cipher suites.
> • Identification of key exchange mechanisms.
> • Extraction of X.509 certificates.
> • Certificate chain validation.
> • Certificate expiration analysis.
> • Public key algorithm and key length analysis.
> • Digital signature algorithm identification.
> • Detection of weak cryptographic algorithms and deprecated TLS versions.
> • Identification of insecure protocol configurations.
> • Forward Secrecy assessment.
> • AI-based cryptographic risk scoring.
> • AI-assisted anomaly detection for suspicious TLS sessions.
> • Prioritized security findings.
> • Comprehensive cryptographic security posture assessment.
> • Exportable forensic reports in JSON, PDF, and HTML formats.
> • Interactive visualization dashboard for security monitoring and analysis.

---

## 5. Requirement extraction (traceability baseline)

Stable IDs. All later documents must trace proposals to these rather than inventing scope.

### 5.1 Deterministic pipeline — `D-xx`

| ID | Requirement | Source clause | Notes |
|---|---|---|---|
| D-01 | Ingest PCAP files | Description | Format handling: `.pcap`, `.pcapng`. Truncated/malformed input is an implied case. |
| D-02 | Automatic identification of SMTP, IMAP, POP3 | Objectives + Deliverables | Stated twice → high importance. Implies **port-independent** detection (§6.2). |
| D-03 | Complete TCP stream reconstruction | Objectives + Deliverables | Stated twice. Must handle retransmits, out-of-order, overlap, gaps. |
| D-04 | Detect STARTTLS negotiation and encrypted session upgrade | Objectives | "identify encryption transitions" in the Description. |
| D-05 | **Validate** STARTTLS negotiation | Deliverables | *Stronger than D-04.* "Validation" implies judging correctness, not just presence (§7, AMB-03). |
| D-06 | Parse and reconstruct TLS handshakes | Objectives + Deliverables | |
| D-07 | Identify negotiated TLS version | Objectives + Deliverables | |
| D-08 | Identify negotiated cipher suite | Objectives + Deliverables | |
| D-09 | Identify key exchange mechanism | Objectives + Deliverables | |
| D-10 | Extract X.509 certificates | Objectives + Deliverables | **Blocked for TLS 1.3 — see §6.1.** |
| D-11 | Certificate chain validation | Deliverables | Requires a trust store; which one is unspecified (AMB-05). |
| D-12 | Certificate expiration analysis | Deliverables | Needs a reference time — capture time, not wall-clock (§6.4). |
| D-13 | Public key algorithm and key length analysis | Deliverables | |
| D-14 | Digital signature algorithm identification | Deliverables | Covers SHA-1 signatures, RSA-MD5, etc. |
| D-15 | Detect weak crypto algorithms and deprecated TLS versions | Objectives + Deliverables | Needs an authority for "weak" (AMB-04). |
| D-16 | Identify insecure protocol configurations | Deliverables | Broadest and vaguest deliverable (AMB-06). |
| D-17 | Forward Secrecy assessment | Deliverables | Derivable from D-09 + D-07. |
| D-18 | Extract cryptographic features for intelligent analysis | Objectives | **The deterministic/AI seam.** Feature engineering is explicitly in scope. |

### 5.2 AI/ML components — `A-xx`

| ID | Requirement | Notes |
|---|---|---|
| A-01 | Cryptographic risk **classification** | |
| A-02 | Detection of **anomalous TLS behavior** | The only requirement that is genuinely unsuited to pure rules (§6.5). |
| A-03 | Security posture **scoring** | |
| A-04 | Threat **prioritization** | |
| A-05 | **Recommendation** of mitigation measures | "actionable security recommendations" in the Description. |

### 5.3 Output and reporting — `R-xx`

| ID | Requirement | Notes |
|---|---|---|
| R-01 | Prioritized security findings | |
| R-02 | Comprehensive cryptographic security posture assessment | The headline artifact; the PS never defines its shape (AMB-07). |
| R-03 | Exportable forensic reports in **JSON, PDF, and HTML** | All three named explicitly. Non-negotiable. |
| R-04 | Interactive visualization dashboard | "for security monitoring and analysis". |
| R-05 | Comprehensive **forensic** reports | Word choice matters — see §6.4. |

**INFERENCE.** 18 deterministic requirements vs. 5 AI requirements. The PS is predominantly a
**protocol-engineering problem with an ML layer on top**, not an ML problem. A team that invests
its effort proportionally to the ML buzzwords in the title will build the wrong system.

### 5.4 Implied requirements (not stated, but entailed) — `I-xx`

| ID | Implied requirement | Why it is entailed |
|---|---|---|
| I-01 | **Offline / air-gapped operation** | "Passive network forensic" + NTRO + PCAP input. A forensic tool that phones out to a cloud API contaminates evidence handling and is unusable in a classified environment. **INFERENCE**, not stated. |
| I-02 | **Non-interference with the target** | "Passive" forbids active probing (no connecting to mail servers, no TLS scanning). This is a *hard constraint* that removes many obvious features. |
| I-03 | **Evidence integrity / reproducibility** | The word "forensic" appears three times. Findings must be traceable to specific packets and repeatable. |
| I-04 | **Scale beyond toy captures** | "enterprise email infrastructures" implies multi-session, multi-host captures, not one handshake. |
| I-05 | **Synthetic data generation capability** | NTRO supplies none. Building a capture corpus is our deliverable. |
| I-06 | **Handling of encrypted-and-opaque sessions** | Directly entailed by "passive analysis of *encrypted* traffic" (§6.1). |
| I-07 | **Compliance mapping** | "ensuring compliance with modern cryptographic best practices" — implies findings map to a named standard. |
| I-08 | **Analyst-facing explainability** | "assist ... analysts in rapidly identifying" + "prioritizing". An unexplained score does not assist prioritization. |

---

## 6. Hidden technical requirements

This section contains the findings least likely to be reproduced by competing teams.

### 6.1 The observability paradox (the central technical tension)

> ### ⚠️ AMENDED 2026-09-16 — read [01A-tls-visibility-validation.md](01A-tls-visibility-validation.md) first
>
> A dedicated validation pass revised this section. The **facts below are upheld**; the **framing
> and strategic weight were wrong**. Corrections:
>
> 1. **"Contradiction" overstates it.** The correct term is *conditional achievability*. There is no
>    contradiction in the PS's intent — only a real constraint in practice.
> 2. **The limitation is wider than TLS 1.3, for a different reason.** *Every resumed session* omits
>    the `Certificate` message at *any* TLS version (RFC 8446 §2.2; TLS 1.2 abbreviated handshake).
>    Mail clients resume aggressively, so this may dominate even in a pure TLS 1.2 environment.
> 3. **Scale corrected: only 5 of 22 PS deliverables are certificate-dependent.** The other 17 are
>    fully achievable passively at every TLS version. This section gave a 5/22 sub-problem the
>    status of the defining problem.
> 4. **"The tool sees least when the target is safest" is overstated.** Negotiated version, cipher
>    suite, key-exchange group, SNI, resumption status and 0-RTT all remain visible under TLS 1.3.
>    The blindness is specific, not general.
> 5. **🔴 The differentiator claim below is WITHDRAWN.** Evidence-tiered observability was formalised
>    for TLS in Delgado, *Observability for Post-Quantum TLS Readiness* (arXiv 2605.02978, May 2026),
>    with `unknown`/`not_applicable`/`ambiguous`/`contradictory` as first-class states — and rests on
>    digital-forensics practice dating to Casey's Certainty Scale (2002). It is a **correctness
>    requirement, not an innovation.**
> 6. **Reweighted opportunity:** the **STARTTLS negotiation layer** is cleartext at every TLS
>    version, carries a published attack taxonomy (Poddebniak, USENIX Security 2021; Durumeric,
>    IMC 2015), and is named in the PS Background. See 01A §7.

The PS requires, simultaneously:

- *"Passive analysis of **encrypted** SMTP, IMAP, and POP3 traffic from PCAP files"* (Objectives)
- *"Extraction and validation of X.509 digital certificates"* (D-10, D-11)

**FACT (RFC 8446 §2, §1.2).** In TLS 1.3, *"All handshake messages after the ServerHello are now
encrypted."* `EncryptedExtensions`, `Certificate`, `CertificateVerify` and `Finished` are protected
under handshake traffic keys. `ClientHello` and `ServerHello` remain cleartext.

**INFERENCE.** For any TLS 1.3 session, a passive observer without key material **cannot** extract
the server certificate. Therefore D-10 through D-14 — certificate extraction, chain validation,
expiry, key length, signature algorithm — are **unachievable on TLS 1.3 traffic by passive means**.
TLS 1.3 is also always forward-secret, so possessing the server's private key does not help either;
there is no RSA-key-exchange escape hatch.

This produces the defining property of the problem:

> **The tool's visibility is inversely proportional to the security of the system it inspects.**
> Well-configured (TLS 1.3) email infrastructure yields the least evidence. Badly configured
> (TLS 1.0–1.2, RSA key exchange, cleartext) infrastructure yields the most.

**Why this matters strategically.** Most teams will build against TLS 1.2 captures where the
certificate is in the clear, demo successfully, and never notice. An NTRO evaluator — whose
organization does signals work — is well positioned to ask *"what does your tool output for a
TLS 1.3 session?"* A team that has an honest, designed answer is in a different category from one
that does not. ~~Turning this constraint into a *designed feature* (explicit evidence-availability
tiers ...) is the strongest available differentiation.~~ **← WITHDRAWN 2026-09-16.** Handling this
correctly is table stakes, not differentiation: the limitation is publicly documented by Zeek,
Corelight and NIST NCCoE, and evidence tiering itself is prior art (01A §6). Retained as a
*correctness requirement* and as a prepared answer to the evaluator question above.

> **OQ-02** *(research)* — How much cryptographic posture can be *soundly* inferred from TLS 1.3
> cleartext alone (ClientHello/ServerHello, extensions, `supported_versions`, `key_share` group,
> record sizing)? This needs an experiment, not an opinion.

### 6.2 Port-independent protocol identification

D-02 says "**automatic** identification". **INFERENCE** — if identification were by port number
(25/110/143/465/587/993/995) it would be a lookup table, and the PS would not call it out twice as
a capability. Real forensic captures contain mail services on non-standard ports. Implicit-TLS
sessions (SMTPS/IMAPS/POP3S) begin with a TLS `ClientHello` and carry **no cleartext application
banner at all** — so for those, protocol identification cannot use payload keywords either and
must fall back on SNI, certificate SANs (when visible), port, and behavioural/traffic shape.

This is materially harder than it looks and is a good source of genuine technical depth.

### 6.3 Data generation is a first-class deliverable

**FACT.** The dataset field reads: *"Synthetic - Participants May generate IMAPS, POP3S, SMTPS Data
using any E-mail server /client of their interest and capture pcap dump."*

**INFERENCE.** To exercise D-15 (weak algorithms, deprecated TLS) we must *deliberately stand up
insecure servers* — TLS 1.0/1.1, RC4/3DES, expired and self-signed certificates, SHA-1 signatures,
broken chains. Modern software actively resists this: OpenSSL 3.x disables these at compile/policy
level, and current mail servers will not negotiate them without deliberate downgrading of the
security level. Building the corpus is a real engineering task with real time cost.

**Two methodological traps** that follow, both of which a rigorous evaluator can expose:

- **Trap 1 — decryption masquerading as passive analysis.** Because we generate the traffic, we can
  hold `SSLKEYLOGFILE` and decrypt everything. That makes a demo look spectacular and is
  **scientifically dishonest** if presented as passive capability, because a real forensic analyst
  has no keys. Any use of key material must be explicitly labelled as a separate, optional mode.
- **Trap 2 — circular validation.** Training an anomaly detector on synthetic traffic we generated,
  then evaluating it on synthetic traffic from the same generator, measures the generator, not the
  detector. Reported accuracy from such a setup is meaningless. See §6.5.

### 6.4 "Forensic" is a load-bearing word

The PS says *forensic* three times ("passive network forensic framework", "Digital Forensics
teams", "comprehensive forensic reports"). **INFERENCE** — this implies properties the PS never
spells out but which the named users require: input file hashing and chain of custody, findings
anchored to packet/frame numbers and stream IDs, deterministic and reproducible output, and
**evaluation of certificate expiry against the capture timestamp rather than the current clock**
(D-12). A certificate valid during the capture but expired today is not a finding; reporting it as
one is a false positive that a forensics team would immediately catch.

This also creates direct tension with AI: a non-deterministic LLM writing report prose is
acceptable; a non-deterministic component deciding *findings* undermines the forensic claim.
Phase 10 must resolve where that line sits.

### 6.5 Where AI is actually justified — and where it is not

Pre-assessment, to be tested properly in Phase 10. **The PS title contains "AI-Assisted", which is
a requirement to use AI, not evidence that AI is the right tool for every sub-problem.**

| Requirement | Honest assessment |
|---|---|
| A-01 risk classification | Largely a **deterministic rules** problem. "TLS 1.0 is deprecated" is RFC 8996, not a learned pattern. A classifier here would be a worse, less explainable lookup table. **Likely AI-unnecessary.** |
| A-03 posture scoring | Deterministic weighted scoring is more defensible and auditable than a learned score with no ground truth to learn from. **Likely AI-unnecessary.** |
| A-02 anomaly detection | **Genuinely suited to ML** — "anomalous" is defined relative to a learned baseline of normal TLS behaviour, which no rule enumerates. This is the one strong case. Its weakness is validation (§6.3, Trap 2). |
| A-04 prioritization | Context-dependent ranking; defensible as learned-to-rank *or* as deterministic risk × exposure. **Unresolved.** |
| A-05 recommendations | LLM generation is reasonable **only if** strictly grounded in extracted evidence and cited standards. Ungrounded, it hallucinates plausible-sounding crypto advice, which is a safety problem in a security tool. |

**Deliberate contrarian position to test in Phase 10:** the most defensible architecture may use
*less* AI than competitors, with each use justified — and say so openly. NTRO reviewers assessing a
forensic tool have reason to prefer auditable determinism over an unexplainable score. This is a
hypothesis, not a conclusion.

---

## 7. Ambiguities

| ID | Ambiguity | Competing readings | Impact |
|---|---|---|---|
| AMB-01 | "**Passive**" | (a) offline PCAP analysis only; (b) also live tap/SPAN capture | Changes architecture. Description says "captured network traffic (PCAP files)" → (a) is better supported. |
| AMB-02 | "encrypted ... traffic" | (a) analyze the handshake around encrypted payloads; (b) decrypt payloads | (b) requires keys the PS never mentions → (a) is the defensible reading. Drives §6.1. |
| AMB-03 | STARTTLS "**validation**" (D-05) | (a) confirm it occurred; (b) detect stripping/downgrade/injection attacks | (b) is much stronger and matches the Background's "downgrade attacks". |
| AMB-04 | "weak", "deprecated", "insecure" | Undefined | Must bind to a named authority (RFC 8996, NIST SP 800-52/800-131A, CNSA). Phase 4. |
| AMB-05 | Chain validation trust anchor | (a) OS/Mozilla store; (b) custom; (c) enterprise internal CA | Enterprise mail commonly uses internal CAs; naive validation flags them all as failures. |
| AMB-06 | "insecure protocol configurations" (D-16) | Open-ended | Scope risk. Needs an explicit, bounded checklist. |
| AMB-07 | "comprehensive posture assessment" (R-02) | Score? Grade? Report? Model? | Deliberate opportunity — the PS does not prescribe the artifact, so we may define it. |
| AMB-08 | "enterprise email infrastructures" | Single org's servers vs. arbitrary internet mail | Affects whether we do per-domain or per-server aggregation. |
| AMB-09 | Email **content** analysis | Not mentioned at all | **Out of scope.** No SPF/DKIM/DMARC, no phishing/BEC content analysis. See §8. |

---

## 8. Scope correction — a significant redirection

**This is the most consequential finding for the team.**

The tasking brief that initiated this research directed a deep dive into SPF, DKIM, DMARC, ARC,
MTA-STS, DANE, DNSSEC, BIMI, MX/DNS records, domain reputation, S/MIME, PGP, and a workflow built
around DNS lookup and email-authentication analysis.

**FACT.** None of those terms appear anywhere in the official SIH26159 text. Not once.

Verified by direct search of the verbatim record: the PS vocabulary is **SMTP, IMAP, POP3, PCAP,
TLS, STARTTLS, TCP stream, TLS handshake, X.509, cipher suite, key exchange, Forward Secrecy,
certificate chain**. The problem is at the **transport-security layer observed through packet
capture**, not the **domain-authentication layer observed through DNS**.

| | Brief's assumed problem | Actual PS |
|---|---|---|
| Input | A domain name | A PCAP file |
| Method | Active DNS/TLS querying | Passive offline analysis |
| Layer | Message authentication (DNS/policy) | Transport encryption (TLS) |
| Protects against | Spoofing, phishing, BEC | Interception, downgrade, MITM |
| Core artifacts | TXT/MX records, DKIM keys, DMARC policy | TCP streams, TLS handshakes, X.509 certs |
| Users | Domain owners, email admins | SOC, DFIR, incident response |

These are **different problems with different users**. Building the DNS-posture tool would produce
a competent product that does not answer this problem statement — the most expensive category of
mistake available at this stage, and one that no amount of later polish recovers.

**Why the confusion is understandable.** The title says "Secure Email Communications" and
"Security Posture Assessment", which in common industry usage (and in most commercial tooling)
*does* mean SPF/DKIM/DMARC domain posture. The title is genuinely misleading; only the body
disambiguates. **This is also the most likely error other competing teams will make** — which is an
opportunity, provided we are right. Given the stakes, confirming the body text against the live
portal is action #1 in `RESEARCH_STATUS.md`.

**Bounded exception to consider, not adopt.** MTA-STS and DANE constrain *transport* security and
could appear as corroborating context for a downgrade finding. They remain out of scope for the
core pipeline and would require active DNS lookups, violating I-02 (passive). Revisit in Phase 11
as an optional enrichment only, clearly separated.

---

## 9. Constraints

### 9.1 Timeline — currently the binding constraint

| Source | Stated deadline | Retrieved |
|---|---|---|
| Official PS record (all 226 PS carry this value) | **20 September 2026** | mirror scraped 2026-08-22 |
| Independent institutional/aggregator reporting | **30 September 2026** national nomination + idea deadline | 2026-09-16 |

**Sources conflict and I could not resolve it from primary sources this session.** Today is
**2026-09-16**, so the window is between **4 and 14 days**.

> **OQ-01** *(team / SPOC — urgent)* — Confirm the real idea-submission deadline with your college
> SPOC and the live portal. This single fact determines whether the remaining 18 research phases
> run as specified or must be compressed. It cannot be resolved by further web research.

Additional timeline facts: **FACT** — each PS locks at 500 submitted ideas; SIH26159 was at 0–1.
Grand Finale is reported as December 2026, so the build window after selection is substantial —
the near-term deliverable is an *idea*, not a system.

### 9.2 Other constraints

- **C-01 Passive-only (I-02).** No active scanning. Removes an entire class of otherwise obvious features.
- **C-02 No supplied data (I-05).** Corpus construction is on us, with the traps in §6.3.
- **C-03 Offline operation (I-01).** **ASSUMPTION A-02** — NTRO deployment context is air-gapped or
  restricted-network. If true, no cloud LLM APIs at inference time, which forces local models and
  materially changes the AI architecture. *Needs verification; high impact.*
- **C-04 Category is Software.** No hardware deliverable.
- **C-05 Student team, fixed size and skills.** OQ-12.
- **C-06 No clarification channel.** Empty contact/YouTube fields (§3).
- **C-07 Forensic integrity (I-03).** Constrains where non-determinism is acceptable.

---

## 10. Phase 2 — What is the actual problem?

### 10.1 Beyond paraphrase

The PS's own framing of the gap is in its second Background paragraph: existing tools *"provide
extensive packet-level visibility"* but *"do not automatically evaluate the overall cryptographic
security posture"* or *"provide intelligent risk assessment and prioritization."*

Stated plainly: **Wireshark can already show an analyst everything. That is precisely the problem.**

The root problem is therefore **not** missing data and **not** missing protocol decoding. Both
exist and are mature. The root problem is an **interpretation and judgement gap**:

> Cryptographic posture assessment of email infrastructure currently requires a scarce expert who
> can hold RFC-level knowledge of TLS, X.509 and mail protocols in their head, apply it manually
> across thousands of sessions, and convert the result into prioritized action. The evidence is
> present in the capture; the **judgement** does not scale.

**INFERENCE.** This reframing matters because it tells us what "winning" looks like. The deliverable
is not a better packet decoder — competing with Wireshark on decoding is unwinnable and
misdirected. The deliverable is **automated expert judgement over decoded evidence, with its
reasoning exposed**.

### 10.2 Is this one problem or several?

**Four connected problems**, and conflating them is a design error:

1. **P1 — Extraction.** Get reliable structured crypto evidence out of raw packets. *Hard
   engineering, well-defined, deterministic.*
2. **P2 — Judgement.** Decide what that evidence means for security. *Requires an authority for
   "weak"; mostly deterministic; the PS's actual centre of gravity.*
3. **P3 — Prioritization.** Rank findings across an enterprise-scale capture. *Context-dependent;
   the genuine analyst pain point; where "intelligent" earns its place.*
4. **P4 — Communication.** Make findings actionable and auditable for four different audiences.
   *Product/UX problem, consistently underrated by technical teams.*

P1 is where effort goes. P3 is where value is. P4 is where demos are won. **INFERENCE** — teams
will over-invest in P1 (it feels like the real work), under-invest in P3, and treat P4 as "add a
dashboard". Deliberately inverting that allocation is a strategic option to evaluate in Phase 14.

### 10.3 Problem tree

```
ROOT: Cryptographic posture of email infrastructure cannot be assessed at scale,
      because expert judgement over packet evidence does not scale.
│
├── TECHNICAL CAUSES
│   ├── Evidence is buried in binary formats needing protocol expertise to read
│   ├── Existing tools decode but do not evaluate (PS Background, explicit)
│   ├── TLS 1.3 encrypts the handshake → evidence availability varies per session (§6.1)
│   ├── "Weak" is a moving target tracked across many standards documents
│   └── Enterprise captures contain thousands of sessions; manual review is infeasible
│
├── ORGANIZATIONAL CAUSES
│   ├── Mail servers are long-lived, inherit legacy config, and are rarely re-baselined
│   ├── Backward compatibility is prioritized over crypto hygiene (a working inbox outranks a good cipher)
│   ├── Ownership is split: mail admins own servers, security owns policy, neither owns crypto posture
│   └── Compliance checks are periodic and point-in-time, so drift goes unnoticed
│
├── HUMAN CAUSES
│   ├── TLS/X.509 expertise is scarce and concentrated in few analysts
│   ├── Alert fatigue: undifferentiated finding lists are ignored
│   └── Admins lack a credible severity signal to justify the risk of changing production mail config
│
└── DETECTION / DECISION GAPS
    ├── No baseline of "normal" TLS behaviour for a given environment
    ├── Downgrade and STARTTLS-stripping are visible in capture but nobody is looking
    ├── No link from an observed weakness to a concrete, ranked remediation
    └── No way to verify a fix actually took effect in traffic
```

### 10.4 Current → desired state

| Stage | Content |
|---|---|
| **CURRENT STATE** | An analyst holding a PCAP of enterprise mail traffic opens Wireshark, filters by port, manually inspects handshakes, eyeballs cipher suites, exports certificates by hand, and checks them against knowledge they may or may not have. |
| **PAIN** | Slow, expertise-gated, non-repeatable, unprioritized, and incomplete. Practically, it does not happen at all — so posture goes unassessed. |
| **CAUSE** | Tools stop at decoding. Judgement is manual. "Weak" is spread across dozens of RFCs. Evidence volume exceeds human review capacity. Under TLS 1.3, some evidence is not there at all. |
| **CONSEQUENCE** | Obsolete TLS, weak ciphers and broken certificates persist unnoticed in production mail infrastructure, leaving it open to downgrade, MITM and passive interception — with mail content, credentials and org-wide communications as the exposed asset. |
| **DESIRED STATE** | An analyst supplies a capture and receives a prioritized, evidence-anchored posture assessment: what is weak, in which sessions, why it matters, how confident the tool is, what to change, and how to verify the change — auditable back to specific packets, without ever touching the production mail servers. |

### 10.5 The question that should govern every later decision

> Would a SOC analyst with a 2 GB capture and 30 minutes genuinely reach for this instead of
> Wireshark — and be able to defend its output to their CISO?

Any feature that does not serve that sentence is decoration. This is the test to apply in Phases
11 and 14, where the temptation to add impressive-sounding capability will be strongest.

---

## 11. Evidence register

### FACT
- F-01 — Repository contains exactly one commit and one file; no prior work exists. *(direct inspection)*
- F-02 — PS SIH26159 is an NTRO problem, Software category, Blockchain & Cybersecurity theme. *(two independent sources)*
- F-03 — The PS scopes the work to passive analysis of PCAP files containing SMTP/IMAP/POP3 traffic. *(verbatim text)*
- F-04 — The PS names JSON, PDF and HTML report export, and an interactive dashboard, as deliverables. *(verbatim text)*
- F-05 — No dataset is provided; participants generate synthetic IMAPS/POP3S/SMTPS captures. *(verbatim text)*
- F-06 — SPF, DKIM, DMARC, DANE, MTA-STS, BIMI, DNSSEC and DNS appear **nowhere** in the PS. *(direct search of verbatim record)*
- F-07 — In TLS 1.3 all handshake messages after ServerHello are encrypted, including `Certificate`. *(RFC 8446 §2)*
- F-08 — TLS 1.0 and TLS 1.1 MUST NOT be used; negotiation MUST NOT be permitted. *(RFC 8996 §4, §5, BCP 195, March 2021)*
- F-09 — The PS record states an idea submission deadline of 20 September 2026. *(PS record; disputed, see OQ-01)*
- F-10 — NTRO contributed 22 PS to SIH 2026, 9 in Blockchain & Cybersecurity, several adjacent to this one (SIH26160 IPsec analyzer, SIH26164 Enterprise Cryptographic Discovery, SIH26155 Network Security Compliance Auditor). *(dataset analysis)*

### INFERENCE
- N-01 — The PS is predominantly a protocol-engineering problem (18 deterministic vs. 5 AI requirements) despite an AI-forward title. *(from §5)*
- N-02 — Passive certificate extraction is impossible for TLS 1.3 sessions, so D-10…D-14 are conditionally unachievable. *(from F-07)*
- N-03 — Evidence availability is inversely proportional to target security — the observability paradox. *(from F-07, N-02)*
- N-04 — Offline/air-gapped operation is required, constraining AI to locally-runnable models. *(from F-03, NTRO context; depends on A-02)*
- N-05 — There is no official channel to resolve ambiguities; documented interpretation is required instead. *(from F-02 metadata)*
- N-06 — Deterministic rules are more defensible than ML for A-01 and A-03; A-02 is the strongest genuine ML case. *(from §6.5)*
- N-07 — NTRO's cluster of adjacent PS (F-10) indicates a portfolio interest in cryptographic inventory/posture across protocols, not a one-off. Reusable, protocol-agnostic architecture may therefore read as more valuable than an email-only point tool. *(speculative; test in Phase 14)*

### ASSUMPTION
- A-01 — The mirrored description text is current and unmodified. *(verification is action #1)*
- A-02 — Deployment context is offline/restricted-network. *(high impact on AI architecture)*
- A-03 — "PCAP" includes `.pcapng`. *(low risk; both are standard capture formats)*
- A-04 — Evaluation is by technical reviewers able to probe protocol-level claims. *(shapes Phases 15–17)*
- A-05 — The team can stand up mail servers and generate captures in a lab. *(blocks the entire data strategy if false)*

### OPEN QUESTION
| ID | Question | Owner |
|---|---|---|
| OQ-01 | Actual idea-submission deadline: 20 or 30 September 2026? | **team/SPOC — urgent** |
| OQ-02 | How much posture is soundly inferable from TLS 1.3 cleartext alone? | research + experiment |
| OQ-03 | Which authority defines "weak"/"deprecated" — RFC 8996, NIST SP 800-52r2, CNSA, or an Indian standard (CERT-In / MeitY)? | research (Phase 4) |
| OQ-04 | Which trust store for chain validation, and how are enterprise internal CAs handled? | research + team |
| OQ-05 | Is anomaly detection defensible without real-world labelled TLS data? | research (Phase 10) |
| OQ-06 | Does "passive" permit live tap capture, or PCAP files only? | interpretation (AMB-01) |
| OQ-07 | What does a "cryptographic security posture assessment" artifact concretely look like? | design (AMB-07) |
| OQ-08 | Is any Indian government cryptographic policy directly applicable and citable? | research (Phase 4) |
| OQ-09 | What realistic capture scale must be handled — MB or GB? | team decision (I-04) |
| OQ-10 | Do decisions exist outside version control? | **team** |
| OQ-11 | Has an idea already been submitted for this PS? | **team** |
| OQ-12 | Team size and skill distribution? | **team** |

---

## 12. Adversarial review of this document

Applying the brief's critical-thinking rule to my own output.

**What a very smart competitor would also find:** the PCAP-not-DNS scope (it is in the first line of
the Description), the deterministic/AI split, the need to generate their own data.

**What they would likely overlook:** the TLS 1.3 certificate-visibility contradiction (§6.1) and its
consequence that the tool sees least when the target is safest; expiry evaluated against capture
time rather than wall-clock (§6.4); the circular-validation trap in synthetic ML evaluation (§6.3);
and that "STARTTLS validation" is a stronger requirement than "STARTTLS detection" (AMB-03).

**Where this document could be wrong:**
- If A-01 fails and the live PS text differs, §5 and §8 need rework. *Mitigation: verification is action #1.*
- §6.1's impact depends on how much real mail traffic is TLS 1.3. If most captured enterprise mail
  is still TLS 1.2, the paradox is real but less commercially significant — it remains a
  correctness issue and a strong evaluator-facing answer either way. **Needs measurement, not
  assertion (OQ-02).**
- §6.5's "less AI may be better" is a *hypothesis I am deliberately arguing against the grain*. It
  could be wrong in the SIH context if evaluation rewards visible AI ambition. Phase 15 must test
  this rather than assume my preference.
- §10.2's claim that competing teams will misallocate effort is **unverified speculation** about
  people I have not observed. It is reasoning, not evidence, and is not a basis for strategy on its own.

**Novelty claims made here:** none. §6.1 is labelled as a candidate differentiator requiring
prior-art search in Phase 12. It is not yet claimed as novel.
