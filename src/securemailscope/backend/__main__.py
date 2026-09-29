"""
Launch the backend:  PYTHONPATH=src python3 -m securemailscope.backend [--port 8000]

Binds to 127.0.0.1 by default. The prototype has no authentication (ADR-0011, doc 21
§19), so it must not be exposed on a network interface without one; binding elsewhere
is possible but requires saying so explicitly.
"""
from __future__ import annotations

import argparse
import logging
import sys


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="securemailscope.backend")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default: loopback; there is no auth)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--data-dir", default="./securemailscope-data")
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    try:
        import uvicorn
    except ImportError:
        print("backend extra is not installed: pip install 'securemailscope[backend]'",
              file=sys.stderr)
        return 2

    from securemailscope.backend.api import create_app

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        logging.warning(
            "binding to %s: this prototype has no authentication", args.host)

    uvicorn.run(create_app(data_dir=args.data_dir), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
