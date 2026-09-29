#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeb4/heldout_templates.py  --  examiner item A-2 (b)
========================================================
"Strictly separate development templates from held-out test templates."

RealisticAttackGenerator expands each tier into a flat pool of base strings
(self._attack_tiers). This splits every tier's pool deterministically into a
DEV half and a TEST half by SHA-1 of the string, and returns a generator that
draws only from one side.

What this does and does not establish, stated plainly so the write-up cannot
overstate it:
  - it DOES show whether detection holds on base strings that are structurally
    distinct from the ones the rules were iterated against;
  - it does NOT prove the rules never saw the TEST half during development,
    because both halves come from pools the same author wrote. The independent
    evidence for that is the third-party sets in build_public_eval.py
    (Tensor Trust attacks are written by unrelated players of a public game).
"""
from __future__ import annotations

import hashlib
import random
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _side(s: str, salt: str = "changeb4") -> int:
    return int(hashlib.sha1((salt + s).encode("utf-8")).hexdigest(), 16) % 2


class SplitAttackGenerator:
    """Wraps RealisticAttackGenerator, keeping only one half of every tier."""

    def __init__(self, half: str = "test", salt: str = "changeb4"):
        from src.attacks.generator import RealisticAttackGenerator
        assert half in ("dev", "test")
        self.half = half
        self._g = RealisticAttackGenerator()
        want = 1 if half == "test" else 0
        self.tiers = []
        self.sizes = {}
        for name, pool, weight in self._g._attack_tiers:
            kept = [p for p in pool if _side(p, salt) == want]
            self.sizes[name] = {"full": len(pool), "kept": len(kept)}
            if kept:
                self.tiers.append((name, kept, weight))

    def generate_batch(self, count: int, seed: int = 42) -> List[Dict]:
        """Same tier weighting and without-replacement draw as the original,
        restricted to the retained half. Obfuscation variants are applied with
        the generator's own encoders so the two sides stay comparable."""
        random.seed(seed)
        total_w = sum(w for _, _, w in self.tiers)
        out, idx = [], 0
        for name, pool, weight in self.tiers:
            n = min(int(round(count * weight / total_w)), len(pool))
            for base in random.sample(pool, n):
                payload, variant = self._maybe_obfuscate(base)
                idx += 1
                out.append({"id": f"{self.half}-{idx}", "type": name,
                            "payload": payload, "original": base,
                            "variant": variant, "is_attack": True})
        random.shuffle(out)
        return out

    def _maybe_obfuscate(self, base: str):
        r = random.random()
        if r < 0.12:
            return self._g._encode_base64(base), "base64"
        if r < 0.22:
            return self._g._add_zero_width(base), "zwsp"
        if r < 0.30:
            return self._g._unicode_homoglyphs(base), "homoglyph"
        if r < 0.35:
            return self._g._wrap_in_context(base), "context_wrap"
        return base, "plain"


def split_report(salt: str = "changeb4") -> Dict:
    dev = SplitAttackGenerator("dev", salt)
    test = SplitAttackGenerator("test", salt)
    return {"salt": salt,
            "per_tier": {k: {"full": v["full"], "dev": dev.sizes[k]["kept"],
                             "test": test.sizes[k]["kept"]}
                         for k, v in dev.sizes.items()},
            "totals": {"full": sum(v["full"] for v in dev.sizes.values()),
                       "dev": sum(v["kept"] for v in dev.sizes.values()),
                       "test": sum(v["kept"] for v in test.sizes.values())}}
