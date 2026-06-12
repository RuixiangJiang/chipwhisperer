#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np


KYBER_Q = 3329


def centered_mod_q(x: np.ndarray | int) -> np.ndarray | int:
    y = np.asarray(x) % KYBER_Q
    y = np.where(y > KYBER_Q // 2, y - KYBER_Q, y)
    return y


def load_secret_txt(path: Path) -> np.ndarray:
    """
    Expected format:
        512 integers, whitespace/comma/semicolon separated,
        centered in {-3,-2,-1,0,1,2,3}.
    """
    text = path.read_text().replace(",", " ").replace(";", " ")
    vals = [int(x) for x in text.split()]
    if len(vals) != 512:
        raise RuntimeError(f"expected 512 secret coefficients, got {len(vals)}")
    s = np.array(vals, dtype=np.int16)
    print("secret shape:", s.shape)
    print("secret min/max:", s.min(), s.max())
    print("secret counts:", {int(v): int((s == v).sum()) for v in sorted(set(s.tolist()))})
    return s


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--npz", required=True)
    ap.add_argument("--secret", required=True)
    args = ap.parse_args()

    d = np.load(args.npz)
    A = d["A"].astype(np.int32)
    b = d["b"].astype(np.int32)
    lower = d["lower"].astype(np.int32)
    upper = d["upper"].astype(np.int32)

    s = load_secret_txt(Path(args.secret))

    raw = b - A @ s.astype(np.int32)
    centered = centered_mod_q(raw).astype(np.int32)

    ok = (centered >= lower) & (centered <= upper)

    print("\n===== Inequality check =====")
    print("rows:", len(ok))
    print("satisfied:", int(ok.sum()))
    print("satisfied rate:", float(ok.mean()))

    print("\ncentered residual stats:")
    print("min/max:", int(centered.min()), int(centered.max()))
    print("mean/std:", float(centered.mean()), float(centered.std()))
    print("percentiles:", np.percentile(centered, [0, 1, 5, 25, 50, 75, 95, 99, 100]))

    print("\ninside interval [-832, -1]:", int(ok.sum()))
    print("below lower:", int((centered < lower).sum()))
    print("above upper:", int((centered > upper).sum()))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())