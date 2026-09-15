#!/usr/bin/env python3
"""Measure CYC|CPI|LSU for a set of (outer, inner) loop-bound configurations.

Both loop bounds are compile-time constants, so each configuration needs its own
firmware image. Changing a bound alters ONLY the immediate in the corresponding
compare:

    cmp.w r2, #768  ->  cmp.w r2, #760      (KYBER_SYMBYTES 96 -> 95)
    cmp   r4, #8    ->  cmp   r4, #7        (POLY_TOMSG_INNER 8 -> 7)

Same instruction, same encoding, same register allocation, same cycle cost -- so
the difference between two builds is exactly the cost of the removed iterations,
measured on silicon with the loop body provably unchanged. That is why the bounds
are constants and not runtime parameters: as parameters they raise register
pressure inside the loop, the compiler spills, and the body gets ~3 cycles per
iteration slower, destroying the thing being measured.

For each configuration this script patches the two #define defaults, rebuilds,
flashes, and runs the plain 'g' command --repeats times per seed with NO glitch,
recording cyccnt, cpicnt and lsucnt. The source file is restored afterwards.

Every run is validated against the firmware's own report: the response echoes
KYBER_SYMBYTES and the final loop indices, so a stale flash or a mis-patched build
is caught immediately rather than silently producing wrong numbers.

Example
-------
    python3 sweep_loop_bounds.py
    python3 sweep_loop_bounds.py --seeds 0x1,0x2 --repeats 3
    python3 sweep_loop_bounds.py --configs 96:8,95:8,96:7
"""

from __future__ import annotations

import argparse
import csv
import re
import shutil
import struct
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

try:
    import chipwhisperer as cw
except Exception:  # noqa: BLE001
    cw = None

RESPONSE_MAGIC = 0x33435054
RESPONSE_LEN = 42

DEFAULT_CONFIGS = [
    (94, 8), (95, 8), (96, 8), (97, 8), (98, 8),     # outer sweep
    (96, 6), (96, 7), (96, 9), (96, 10),             # inner sweep (96,8 above)
    (1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6), (1, 7), (1, 8), (1, 9), (1, 10),   # inner sweep (1,8 above)
    (2, 1), (2, 2), (2, 3), (2, 4), (2, 5), (2, 6), (2, 7), (2, 8), (2, 9), (2, 10),
    (3, 1), (3, 2), (3, 3), (3, 4), (3, 5), (3, 6), (3, 7), (3, 8), (3, 9), (3, 10),
    (4, 1), (4, 2), (4, 3), (4, 4), (4, 5), (4, 6), (4, 7), (4, 8), (4, 9), (4, 10),
]


def patch_source(path: Path, n_outer: int, n_inner: int) -> None:
    src = path.read_text()
    new, k1 = re.subn(r"(#define\s+KYBER_SYMBYTES\s+)\d+U?", rf"\g<1>{n_outer}U", src)
    new, k2 = re.subn(r"(#define\s+POLY_TOMSG_INNER\s+)\d+U?", rf"\g<1>{n_inner}U", new)
    if k1 != 1 or k2 != 1:
        raise RuntimeError(f"expected one #define each, patched {k1} SYMBYTES / "
                           f"{k2} INNER -- check the source")
    path.write_text(new)


def build(project_dir: Path, platform: str, ss_ver: str) -> Path:
    # The ChipWhisperer makefile requires PLATFORM (and SS_VER) even for `clean`;
    # invoking it bare aborts with a "no platform" error.
    common = [f"PLATFORM={platform}", f"SS_VER={ss_ver}"]
    for stage in (["clean"], ["-j"]):
        r = subprocess.run(["make", *common, *stage], cwd=project_dir,
                           capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write((r.stdout or "")[-3000:])
            sys.stderr.write((r.stderr or "")[-3000:])
            raise RuntimeError(f"make {' '.join(stage)} failed "
                               f"(exit {r.returncode}) in {project_dir}")
        out = r.stdout or ""
    hexes = sorted(project_dir.glob(f"*{platform}.hex"))
    if not hexes:
        raise RuntimeError(f"no *{platform}.hex produced in {project_dir}")
    # report the text size so a non-rebuild is visible
    m = re.search(r"^\s*(\d+)\s+\d+\s+\d+\s+\d+\s+[0-9a-f]+\s", out, re.M)
    if m:
        print(f" text={m.group(1)}", end="")
    return hexes[0]


def connect():
    if cw is None:
        raise RuntimeError("chipwhisperer not importable; run on the CW host")
    scope = cw.scope()
    scope.default_setup()
    try:
        target = cw.target(scope, cw.targets.SimpleSerial2)
    except Exception:  # noqa: BLE001
        target = cw.target(scope, cw.targets.SimpleSerial)
    scope.clock.adc_src = "clkgen_x1"
    scope.adc.samples = 24000
    return scope, target


def reset_target(scope, settle=0.2):
    try:
        scope.io.nrst = "low"
        time.sleep(0.05)
        scope.io.nrst = "high_z"
        time.sleep(settle)
    except Exception:  # noqa: BLE001
        pass


def measure(scope, target, seed: int, timeout=2000):
    for m in ("reset_comms", "flush"):
        fn = getattr(target, m, None)
        if fn:
            try:
                fn()
                break
            except Exception:  # noqa: BLE001
                continue
    target.simpleserial_write("g", struct.pack("<IB", seed & 0xFFFFFFFF, 0))
    raw = target.simpleserial_read("r", RESPONSE_LEN, timeout=timeout)
    if raw is None or len(raw) < RESPONSE_LEN:
        return None
    raw = bytes(raw)
    if struct.unpack_from("<I", raw, 0)[0] != RESPONSE_MAGIC:
        return None
    cyc, i, j = struct.unpack_from("<III", raw, 4)
    cpi, lsu = raw[28], raw[31]
    symbytes = struct.unpack_from("<H", raw, 36)[0]
    crc = struct.unpack_from("<I", raw, 38)[0]
    return dict(cycles=cyc, i=i, j=j, cpicnt=cpi, lsucnt=lsu,
                symbytes=symbytes, msg_crc=crc)


def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--project-dir", type=Path, default=Path.cwd())
    p.add_argument("--source", type=Path, default=Path("simpleserial-polytomsg-hpc.c"))
    p.add_argument("--platform", default="CWLITEARM")
    p.add_argument("--ss-ver", default="SS_VER_2_1")
    p.add_argument("--seeds", type=lambda s: [int(x, 0) for x in s.split(",")],
                   default=[1, 2])
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--configs", default=None,
                   help="comma-separated outer:inner pairs (default: the 9-point sweep)")
    p.add_argument("-o", "--output", type=Path, default=Path("loop_bound_sweep.csv"))
    return p.parse_args()


def main() -> int:
    args = parse_args()
    src = (args.project_dir / args.source).resolve()
    if not src.is_file():
        raise FileNotFoundError(src)

    configs = DEFAULT_CONFIGS
    if args.configs:
        configs = [tuple(int(v) for v in c.split(":")) for c in args.configs.split(",")]

    backup = src.with_suffix(src.suffix + ".sweepbak")
    shutil.copy2(src, backup)
    print(f"source backed up to {backup.name}\n")

    rows: list[dict] = []
    scope = target = None
    try:
        scope, target = connect()
        for n_outer, n_inner in configs:
            print(f"[{n_outer:>3},{n_inner:>2}] patching + building ...", end="", flush=True)
            patch_source(src, n_outer, n_inner)
            hexfile = build(args.project_dir, args.platform, args.ss_ver)
            print(" flashing ...", end="", flush=True)
            cw.program_target(scope, cw.programmers.STM32FProgrammer, str(hexfile))
            reset_target(scope)
            try:
                target.reset_comms()
            except Exception:  # noqa: BLE001
                pass
            print(" measuring")

            for seed in args.seeds:
                got = []
                for rep in range(args.repeats):
                    d = measure(scope, target, seed)
                    if d is None:
                        raise RuntimeError(
                            f"no valid response at ({n_outer},{n_inner}) seed {seed:#x}")
                    # the firmware echoes its own build config: catches a stale flash
                    if d["symbytes"] != n_outer:
                        raise RuntimeError(
                            f"firmware reports KYBER_SYMBYTES={d['symbytes']} but this "
                            f"build should be {n_outer}. Stale flash or bad patch.")
                    if d["i"] != n_outer or d["j"] != n_inner:
                        raise RuntimeError(
                            f"loop exited at i={d['i']}, j={d['j']}; expected "
                            f"{n_outer}, {n_inner}. Bounds did not take effect.")
                    got.append(d)
                    rows.append({
                        "n_outer": n_outer, "n_inner": n_inner,
                        "seed": f"0x{seed:08x}", "rep": rep,
                        "cycles": d["cycles"], "cpicnt": d["cpicnt"], "lsucnt": d["lsucnt"],
                        "CYC|CPI|LSU": f"{d['cycles']}|{d['cpicnt']}|{d['lsucnt']}",
                        "final_i": d["i"], "final_j": d["j"],
                        "msg_crc": f"0x{d['msg_crc']:08x}",
                    })
                trip = {(g["cycles"], g["cpicnt"], g["lsucnt"]) for g in got}
                tag = "" if len(trip) == 1 else "   <-- NOT STABLE across repeats"
                t = got[0]
                print(f"    seed 0x{seed:08x}: "
                      f"{t['cycles']}|{t['cpicnt']}|{t['lsucnt']}{tag}")
    finally:
        shutil.copy2(backup, src)
        backup.unlink(missing_ok=True)
        print("\nsource restored")
        try:
            if scope:
                scope.dis()
            if target:
                target.dis()
        except Exception:  # noqa: BLE001
            pass

    if not rows:
        return 2
    with args.output.open("w", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} rows -> {args.output}\n")

    # ---- summary table ----
    key = {}
    for r in rows:
        key.setdefault((r["n_outer"], r["n_inner"], r["seed"]),
                       (r["cycles"], r["cpicnt"], r["lsucnt"]))
    seeds = [f"0x{s:08x}" for s in args.seeds]
    print(f"{'outer':>6}{'inner':>6}   " + "   ".join(f"{s:>18}" for s in seeds))
    for n_outer, n_inner in configs:
        cells = []
        for s in seeds:
            v = key.get((n_outer, n_inner, s))
            cells.append(f"{v[0]}|{v[1]}|{v[2]}" if v else "-")
        print(f"{n_outer:>6}{n_inner:>6}   " + "   ".join(f"{c:>18}" for c in cells))

    # ---- derived per-iteration costs ----
    print("\nderived costs (per seed):")
    for s in seeds:
        def cyc(o, i):
            v = key.get((o, i, s))
            return v[0] if v else None
        outs = [(o, cyc(o, 8)) for o in (94, 95, 96, 97, 98) if cyc(o, 8) is not None]
        inns = [(i, cyc(96, i)) for i in (6, 7, 8, 9, 10) if cyc(96, i) is not None]
        print(f"  {s}")
        if len(outs) > 1:
            d = [outs[k + 1][1] - outs[k][1] for k in range(len(outs) - 1)]
            print(f"    outer +1 iteration: {d}  " +
                  ("uniform" if len(set(d)) == 1 else "NOT uniform"))
        if len(inns) > 1:
            d = [inns[k + 1][1] - inns[k][1] for k in range(len(inns) - 1)]
            per = [round(x / 96, 3) for x in d]
            print(f"    inner +1 iteration: total {d}, per outer iteration {per}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"build command failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
