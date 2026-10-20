# PyREA — Reverse Engineer Anything, in Python

Point PyREA at a program you have **no source code for** and it takes the
target apart and explains how it works — with one rule borrowed from the
viral [REA](https://github.com/morluto/rea) project: **every claim is
labelled**. Observations (seen directly), derivations (computed from
evidence), inferences (likely, not proven) and unknowns (not determined)
are kept separate, so a report never dresses a guess up as a fact.

Pure Python standard library. No dependencies, no code execution — the
analysis is fully static and safe to run on untrusted files.

## Quick start

```bash
git clone https://github.com/mustaph333/pyrea.git
cd pyrea
python -m pyrea analyze samples/pricing.py
python -m pyrea analyze samples/runner.js --out report.md
python -m pyrea analyze some-program.exe --json
```

## What it analyzes

| Target | How |
|---|---|
| Python source (`.py`) | Parsed with `ast`: imports, functions, constants, URLs, and arithmetic rules derived from return statements |
| JavaScript (`.js`, `.ts`) | Pattern analysis: functions, named values, URLs, text strings, computed returns |
| Binaries & containers | Magic-byte file-type detection, byte entropy, string extraction with offsets, flagging of URLs / endpoints / key-like strings |

## Example finding

From `samples/pricing.py`, PyREA derives the pricing rule instead of
guessing it:

> **Derivation:** `total_with_tax` computes: `amount + amount * TAX_RATE / 100` — evidence: line 17

And it is honest about its limits:

> **Unknown:** Runtime behaviour was not executed — analysis is static only

## Tests

```bash
python -m unittest discover -s tests -v
```

## Roadmap

- [ ] Bridge to Ghidra / radare2 for real disassembly of native binaries
- [ ] APK analysis (manifest + DEX strings) via zip inspection
- [ ] Optional AI summary layer (bring your own API key) that explains
      the evidence report in plain language — findings stay evidence-first
- [ ] MCP server mode, so AI coding agents can call PyREA as a tool

## Legal

Analyze only software you own or are allowed to examine. Reverse
engineering rules differ by country and license.

## License

MIT
