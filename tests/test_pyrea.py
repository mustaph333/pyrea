"""Run with:  python -m unittest discover -s tests -v"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pyrea.analyze_python import analyze_python
from pyrea.analyze_js import analyze_js
from pyrea.analyze_binary import analyze_binary
from pyrea.findings import OBSERVATION, DERIVATION, INFERENCE

HERE = os.path.dirname(__file__)
SAMPLES = os.path.join(HERE, "..", "samples")


def claims(rep, kind=None):
    items = rep.findings if kind is None else rep.by_kind(kind)
    return " | ".join(f.claim for f in items)


class TestPythonAnalyzer(unittest.TestCase):
    def test_pricing_sample(self):
        rep = analyze_python(os.path.join(SAMPLES, "pricing.py"))
        self.assertEqual(rep.target_type, "python-source")
        self.assertIn("TAX_RATE = 20", claims(rep, OBSERVATION))
        self.assertIn("total_with_tax", claims(rep, DERIVATION))
        self.assertIn("api.example-shop.com", claims(rep, OBSERVATION))

    def test_inferences_are_never_high_confidence(self):
        rep = analyze_python(os.path.join(SAMPLES, "pricing.py"))
        for f in rep.by_kind(INFERENCE):
            self.assertNotEqual(f.confidence, "high")


class TestJsAnalyzer(unittest.TestCase):
    def test_runner_sample(self):
        rep = analyze_js(os.path.join(SAMPLES, "runner.js"))
        self.assertIn("START_SPEED = 6", claims(rep, OBSERVATION))
        self.assertIn("MAX_SPEED = 13", claims(rep, OBSERVATION))
        self.assertIn("updateSpeed", claims(rep, OBSERVATION))


class TestBinaryAnalyzer(unittest.TestCase):
    def test_fake_pe(self):
        path = os.path.join(HERE, "fake.bin")
        with open(path, "wb") as fh:
            fh.write(b"MZ" + b"\x00" * 64 + b"GET https://api.secret.io/login HTTP/1.1" + b"\x00" * 32)
        try:
            rep = analyze_binary(path)
            self.assertIn("Windows program", claims(rep, OBSERVATION))
            self.assertIn("api.secret.io", claims(rep, OBSERVATION))
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
