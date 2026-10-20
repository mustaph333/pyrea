"""Render a Report as Markdown (or plain console text)."""

from .findings import OBSERVATION, DERIVATION, INFERENCE, UNKNOWN

SECTIONS = [
    (OBSERVATION, "Observations — seen directly in the target"),
    (DERIVATION, "Derivations — computed from the observations"),
    (INFERENCE, "Inferences — likely, but not proven"),
    (UNKNOWN, "Unknowns — what this analysis could not determine"),
]


def to_markdown(rep):
    out = [f"# PyREA report: {rep.target}", f"Target type: {rep.target_type}", ""]
    for kind, title in SECTIONS:
        items = rep.by_kind(kind)
        out.append(f"## {title} ({len(items)})")
        if not items:
            out.append("- (none)")
        for f in items:
            ev = f" — evidence: {f.evidence}" if f.evidence else ""
            conf = "" if f.confidence == "high" else f" [confidence: {f.confidence}]"
            out.append(f"- {f.claim}{ev}{conf}")
        out.append("")
    return "\n".join(out)


def to_console(rep):
    counts = {k: len(rep.by_kind(k)) for k, _ in SECTIONS}
    head = (f"{rep.target} ({rep.target_type}): "
            f"{counts[OBSERVATION]} observations, {counts[DERIVATION]} derivations, "
            f"{counts[INFERENCE]} inferences, {counts[UNKNOWN]} unknowns")
    return head + "\n\n" + to_markdown(rep)
