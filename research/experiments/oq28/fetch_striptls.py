"""
Regenerate the py3-runnable copy of tintinweb/striptls used by the OQ-33 experiment.

striptls is GPLv2. We deliberately do NOT vendor it into this repository (that would
impose copyleft obligations on this project). Instead this script fetches it and applies
the same mechanical fix documented in docs/research/02B §15: `except X, e:` -> `except X as e:`
(36 sites). No logic is changed.

Usage:  python3 research/experiments/oq28/fetch_striptls.py
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "striptls_py3_exceptfix.py")
REPO = "https://github.com/tintinweb/striptls.git"


def main() -> int:
    if os.path.exists(OUT):
        print(f"already present: {OUT}")
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        print(f"cloning {REPO} ...")
        r = subprocess.run(["git", "clone", "--depth", "1", "-q", REPO, tmp],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("clone failed:", r.stderr.strip(), file=sys.stderr)
            return 1
        src_path = os.path.join(tmp, "striptls", "striptls.py")
        if not os.path.isfile(src_path):
            print("unexpected upstream layout: striptls/striptls.py not found", file=sys.stderr)
            return 1
        src = open(src_path, encoding="utf-8", errors="replace").read()

    fixed, n = re.subn(r"except\s+([\w.]+)\s*,\s*(\w+)\s*:", r"except \1 as \2:", src)
    header = (
        "# Third-party: tintinweb/striptls (GPLv2). Fetched and mechanically fixed for\n"
        "# Python 3 by fetch_striptls.py -- `except X, e:` -> `except X as e:` only.\n"
        "# NOT part of SecureMailScope's licensed source. Do not commit this file.\n"
    )
    open(OUT, "w", encoding="utf-8").write(header + fixed)
    print(f"wrote {OUT} ({n} except-clauses fixed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
