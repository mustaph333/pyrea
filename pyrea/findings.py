"""Findings: the heart of PyREA's method.

Every claim PyREA makes is a Finding with a kind:

- observation : directly seen in the target (with evidence)
- derivation  : computed from observations (the math is shown)
- inference   : a likely explanation, NOT proven (labelled as such)
- unknown     : something the analysis could not determine

This separation — evidence first, guesses labelled — is what makes a
reverse-engineering report trustworthy instead of a hallucination.
"""

from dataclasses import dataclass, field, asdict

OBSERVATION = "observation"
DERIVATION = "derivation"
INFERENCE = "inference"
UNKNOWN = "unknown"

KINDS = (OBSERVATION, DERIVATION, INFERENCE, UNKNOWN)


@dataclass
class Finding:
    kind: str
    claim: str
    evidence: str = ""        # file:line, byte offset, or the literal value seen
    confidence: str = "high"  # high / medium / low — inferences are never "high"

    def __post_init__(self):
        if self.kind not in KINDS:
            raise ValueError(f"bad finding kind: {self.kind}")
        if self.kind == INFERENCE and self.confidence == "high":
            self.confidence = "medium"  # an inference is never certain

    def to_dict(self):
        return asdict(self)


@dataclass
class Report:
    target: str
    target_type: str
    findings: list = field(default_factory=list)

    def add(self, kind, claim, evidence="", confidence="high"):
        f = Finding(kind=kind, claim=claim, evidence=evidence, confidence=confidence)
        self.findings.append(f)
        return f

    def by_kind(self, kind):
        return [f for f in self.findings if f.kind == kind]

    def to_dict(self):
        return {
            "target": self.target,
            "target_type": self.target_type,
            "findings": [f.to_dict() for f in self.findings],
        }
