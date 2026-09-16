---
name: token-efficiency
description: Reduce waste WITHOUT reducing reasoning quality. Trigger before reading files, running commands, or tests — i.e. constantly.
---
# token-efficiency

Goal: less waste, not less intelligence. Never skip verification to save tokens.

Before reading: name the exact fact needed, then read only that. Prefer `rg pattern path`, headings,
line ranges, `head`/`tail`/`sed`/`jq`, hashes/metadata over dumping files. Never dump repos, whole
PCAPs, node_modules, .venv, build dirs, lockfiles, huge logs, or generated datasets into context.

Don't re-verify already-verified facts unless the source/requirement changed or a contradiction
appeared. Tests: targeted → relevant integration → full regression only when justified; don't rerun
full suites after every tiny change. Prefer bounded command output.
