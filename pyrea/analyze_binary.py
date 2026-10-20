"""Analysis of compiled / binary targets (no source available).

This is where reverse engineering really starts: identify the file,
pull out every readable string, and flag the interesting ones (URLs,
endpoints, keys). Compiled code is NOT disassembled in v1 — the report
says so honestly as an unknown instead of pretending.
"""

import hashlib
import math
import re

from .findings import Report, OBSERVATION, INFERENCE, UNKNOWN

MAGICS = [
    (b"MZ", "Windows program (PE executable)"),
    (b"\x7fELF", "Linux program (ELF executable)"),
    (b"PK\x03\x04", "ZIP archive — could be an APK, JAR or Office file"),
    (b"\xfe\xed\xfa\xce", "macOS program (Mach-O, 32-bit)"),
    (b"\xfe\xed\xfa\xcf", "macOS program (Mach-O, 64-bit)"),
    (b"\xcf\xfa\xed\xfe", "macOS program (Mach-O, 64-bit, little-endian)"),
    (b"%PDF", "PDF document"),
    (b"\x00asm", "WebAssembly module"),
    (b"\x1f\x8b", "gzip archive"),
]

INTERESTING = ("http://", "https://", "api", "token", "secret", "password",
               "key", ".com", ".io", ".net", "login", "auth")

STRING_RE = re.compile(rb"[\x20-\x7e]{5,}")


def _entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    for c in counts:
        if c:
            p = c / len(data)
            ent -= p * math.log2(p)
    return round(ent, 2)


def analyze_binary(path):
    data = open(path, "rb").read()
    rep = Report(target=str(path), target_type="binary")
    rep.add(OBSERVATION, f"File size: {len(data)} bytes",
            evidence=f"sha256:{hashlib.sha256(data).hexdigest()[:16]}")

    kind = None
    for magic, label in MAGICS:
        if data.startswith(magic):
            kind = label
            break
    if kind:
        rep.add(OBSERVATION, f"File type: {kind}", evidence="magic bytes at offset 0")
        if "APK" in kind or "ZIP" in kind:
            rep.add(INFERENCE, "ZIP-based container: contents can be listed and extracted",
                    evidence="magic bytes", confidence="medium")
    else:
        rep.add(UNKNOWN, "File type not recognised from magic bytes")

    ent = _entropy(data)
    rep.add(OBSERVATION, f"Byte entropy: {ent} / 8.0", evidence="whole file")
    if ent > 7.2:
        rep.add(INFERENCE, "Very high entropy: likely compressed or encrypted content",
                evidence=f"entropy {ent}", confidence="medium")

    strings = [(m.start(), m.group().decode("ascii")) for m in STRING_RE.finditer(data)]
    rep.add(OBSERVATION, f"Readable strings found: {len(strings)}", evidence="whole file")

    shown = 0
    for offset, s in strings:
        low = s.lower()
        if any(k in low for k in INTERESTING) and shown < 25:
            rep.add(OBSERVATION, f"Interesting string: \"{s[:90]}\"",
                    evidence=f"offset {offset}")
            shown += 1

    rep.add(UNKNOWN, "Compiled code was not disassembled in v1 — behaviour inside "
                     "functions is not proven (planned: Ghidra/radare2 bridge)")
    return rep
