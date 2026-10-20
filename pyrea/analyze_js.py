"""Light static analysis of JavaScript files.

JavaScript has no stdlib parser in Python, so this analyzer works with
careful pattern matching. Every claim still carries line evidence, and
anything pattern matching cannot prove is reported as an inference or
an unknown — never as a fact.
"""

import hashlib
import re

from .findings import Report, OBSERVATION, DERIVATION, INFERENCE, UNKNOWN

FUNC_RE = re.compile(r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)")
ARROW_RE = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>")
CONST_NUM_RE = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(-?\d+(?:\.\d+)?)\s*;")
URL_RE = re.compile(r"https?://[^\s\"'`)]+")
RETURN_MATH_RE = re.compile(r"return\s+([^;{}]*[+\-*/%][^;{}]*);")
STRING_RE = re.compile(r"[\"'`]([^\"'`]{12,})[\"'`]")


def analyze_js(path):
    data = open(path, "rb").read()
    text = data.decode("utf-8", errors="replace")
    rep = Report(target=str(path), target_type="javascript-source")
    rep.add(OBSERVATION, f"File size: {len(data)} bytes",
            evidence=f"sha256:{hashlib.sha256(data).hexdigest()[:16]}")

    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        m = FUNC_RE.search(line)
        if m:
            rep.add(OBSERVATION, f"Function `{m.group(1)}({m.group(2)})`",
                    evidence=f"line {i}")
        m = ARROW_RE.search(line)
        if m:
            rep.add(OBSERVATION, f"Arrow function `{m.group(1)}`", evidence=f"line {i}")
        m = CONST_NUM_RE.search(line)
        if m:
            rep.add(OBSERVATION, f"Value {m.group(1)} = {m.group(2)}",
                    evidence=f"line {i}")
        m = RETURN_MATH_RE.search(line)
        if m:
            rep.add(DERIVATION, f"Computes: return {m.group(1).strip()}",
                    evidence=f"line {i}")
        for u in URL_RE.findall(line):
            rep.add(OBSERVATION, f"URL: {u}", evidence=f"line {i}")

    # long string literals often hold messages, keys or endpoints
    seen = set()
    for i, line in enumerate(lines, start=1):
        for s in STRING_RE.findall(line):
            if s not in seen and (" " in s or "/" in s):
                seen.add(s)
                rep.add(OBSERVATION, f"Text string: \"{s[:80]}\"", evidence=f"line {i}")

    names = " ".join(m.group(1) for m in FUNC_RE.finditer(text)).lower()
    if "speed" in names or "velocity" in names:
        rep.add(INFERENCE, "Contains speed-related logic (from function names)",
                evidence="function names", confidence="low")
    if "price" in names or "total" in names or "cart" in names:
        rep.add(INFERENCE, "Contains pricing/cart logic (from function names)",
                evidence="function names", confidence="low")

    rep.add(UNKNOWN, "Pattern-based analysis: control flow and runtime behaviour not proven")
    return rep
