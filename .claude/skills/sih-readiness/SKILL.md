---
name: sih-readiness
description: Requirement mapping and judge/demo readiness. Trigger when assessing coverage of the PS, preparing the demo, or writing submission material.
---
# sih-readiness

Map every claim to the authoritative PS (docs/research/19). Locked scope: passive PCAP; SMTP/IMAP/POP3
+ implicit TLS; D-01..D-18, A-01..A-05, R-01..R-05. AI/ML is explicitly required (real component
needed) but method-open — defend the anomaly component on evidence, and note OQ-35 (a --no-ai-capable
design must still satisfy "AI-Assisted").

Never claim: STARTTLS stripping universally detected; cross-session identifies attackers; anomaly score =
proof of attack; novelty in detection. Do claim (with numbers): ~70% FP reduction on our corpus,
control-endpoint detection per-session tools miss, honest abstention, evidence-anchored findings.
Deadline 30 Sep 2026; confirm SPOC internal cutoff.
