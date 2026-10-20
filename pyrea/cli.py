"""PyREA command line.

Usage:
    python -m pyrea analyze <target> [--out report.md] [--json]

The analyzer is chosen from the file itself: Python sources are parsed
with `ast`, JavaScript with pattern matching, and everything else is
treated as a binary/container and examined at the byte level.
"""

import argparse
import json
import os
import sys

from .analyze_python import analyze_python
from .analyze_js import analyze_js
from .analyze_binary import analyze_binary
from .report import to_markdown, to_console

JS_EXTS = {".js", ".mjs", ".cjs", ".ts"}


def pick_analyzer(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".py":
        return analyze_python
    if ext in JS_EXTS:
        return analyze_js
    with open(path, "rb") as fh:
        head = fh.read(4096)
    if head.startswith(b"#!") and b"python" in head.split(b"\n", 1)[0]:
        return analyze_python
    return analyze_binary


def main(argv=None):
    parser = argparse.ArgumentParser(prog="pyrea",
                                     description="Reverse engineer anything — with evidence.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze a target file")
    a.add_argument("target")
    a.add_argument("--out", help="write the Markdown report to this file")
    a.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.target):
        print(f"error: no such file: {args.target}", file=sys.stderr)
        return 2

    rep = pick_analyzer(args.target)(args.target)

    if args.json:
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        print(to_console(rep))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(rep))
        print(f"\nReport written to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
