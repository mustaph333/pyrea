"""Static analysis of Python source files (stdlib `ast` only).

No code is executed. Everything reported is read from the syntax tree,
so every observation can point at an exact line as evidence.
"""

import ast
import hashlib

from .findings import Report, OBSERVATION, DERIVATION, INFERENCE, UNKNOWN


def _is_number(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, (int, float))


def analyze_python(path):
    data = open(path, "rb").read()
    text = data.decode("utf-8", errors="replace")
    rep = Report(target=str(path), target_type="python-source")
    rep.add(OBSERVATION, f"File size: {len(data)} bytes",
            evidence=f"sha256:{hashlib.sha256(data).hexdigest()[:16]}")

    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        rep.add(UNKNOWN, f"File does not parse as Python: {e}", evidence=f"line {e.lineno}")
        return rep

    lines = text.splitlines()

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names]
            rep.add(OBSERVATION, f"Imports: {', '.join(names)}",
                    evidence=f"line {node.lineno}")

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [a.arg for a in node.args.args]
            rep.add(OBSERVATION,
                    f"Function `{node.name}({', '.join(args)})`",
                    evidence=f"line {node.lineno}")
            # a return of an arithmetic expression is a derivation we can show
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and isinstance(sub.value, ast.BinOp):
                    rep.add(DERIVATION,
                            f"`{node.name}` computes: {ast.unparse(sub.value)}",
                            evidence=f"line {sub.lineno}")
            low = node.name.lower()
            if any(w in low for w in ("total", "price", "calc", "sum")):
                rep.add(INFERENCE,
                        f"`{node.name}` likely computes a money/total value (from its name)",
                        evidence=f"line {node.lineno}", confidence="low")
        elif isinstance(node, ast.ClassDef):
            rep.add(OBSERVATION, f"Class `{node.name}`", evidence=f"line {node.lineno}")
        elif isinstance(node, ast.Assign) and _is_number(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    rep.add(OBSERVATION,
                            f"Constant {t.id} = {node.value.value}",
                            evidence=f"line {node.lineno}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.startswith(("http://", "https://")):
                rep.add(OBSERVATION, f"URL string: {node.value}",
                        evidence="string literal")

    if not rep.by_kind(DERIVATION):
        rep.add(UNKNOWN, "No arithmetic return statements found to derive rules from")
    rep.add(UNKNOWN, "Runtime behaviour was not executed — analysis is static only")
    _ = lines
    return rep
