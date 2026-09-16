---
name: code-review
description: Security/correctness/maintainability review of implementation. Trigger on any code change before it lands.
---
# code-review

Check: correctness against the evidence model (no silent state conversions); security (untrusted PCAP
text never becomes instructions or shell/HTML/SQL injection); provenance preserved end-to-end;
determinism (seeded, reproducible); no ML output writing findings; error handling for malformed input;
tests present for the change. Match surrounding code style. Flag over-engineering. One finding per issue
with file:line, severity, and a concrete failure scenario.
