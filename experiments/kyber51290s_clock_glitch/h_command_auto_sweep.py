#!/usr/bin/env python3
"""
Automated H-command glitch sweep for ChipWhisperer-Lite.

Searches parameters that make H return h=0 while target still responds to P.
Normal H return is 1664 (0x680). h=0 is the direct load-skip candidate.

Example:
  python scripts/h_command_auto_sweep.py --hours 12 --out-dir data/analysis/h_command_auto_sweep_12h
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import chipwhisperer as cw

NORMAL_H = 1664
PING_VALUE = b"\x42"


@dataclass(frozen=True)
class Point:
    width: float
    offset: float
    ext_offset: int
    repeat: int

    @property
    def key(self) -> str:
        return f"w={self.width:g},off={self.offset:g},ext={self.ext_offset},rep={self.repeat}"


def parse_float_list(s: str) -> List[float]:
    return [float(x.strip()) for x in s.split(",") if x.strip()]


def parse_int_list(s: str) -> List[int]:
    return [int(x.strip()) for x in s.split(",") if x.strip()]


def payload_bytes(x: Any) -> bytes:
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    try:
        return bytes(x)  # CWbytearray
    except Exception:
        pass
    if isinstance(x, str):
        return x.encode("latin-1", errors="replace")
    return b""


def response_text(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    try:
        return bytes(x).decode("latin-1", errors="replace")
    except Exception:
        return repr(x)


def response_payload_hex(resp: Any) -> str:
    if not isinstance(resp, dict):
        return ""
    return payload_bytes(resp.get("payload")).hex()


def response_full_repr(resp: Any, max_len: int = 180) -> str:
    if not isinstance(resp, dict):
        return repr(resp)[:max_len]
    full = resp.get("full_response")
    text = response_text(full)
    if not text:
        text = repr(full)
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    return text[:max_len]


def reset_target(scope: Any, delay: float = 1.5) -> None:
    scope.io.nrst = "low"
    time.sleep(0.1)
    scope.io.nrst = "high_z"
    time.sleep(delay)


def setup_scope(args: argparse.Namespace) -> Any:
    scope = cw.scope()
    scope.default_setup()
    scope.clock.clkgen_freq = args.clkgen_freq
    scope.clock.adc_src = args.adc_src

    # CW-Lite: route target clock through glitch module.
    # Do NOT use scope.glitch.enabled; that is CW-Husky only.
    scope.io.hs2 = "glitch"
    scope.io.tio1 = "serial_rx"
    scope.io.tio2 = "serial_tx"

    scope.trigger.triggers = "tio4"
    scope.adc.basic_mode = "rising_edge"
    scope.adc.samples = args.samples
    scope.adc.timeout = args.adc_timeout

    scope.glitch.clk_src = "clkgen"
    scope.glitch.output = "clock_xor"
    scope.glitch.trigger_src = "ext_single"
    return scope


def setup_target(scope: Any, args: argparse.Namespace) -> Any:
    target = cw.target(scope, cw.targets.SimpleSerial2)
    try:
        target.ser.baud(args.baud)
    except Exception:
        pass
    return target


def apply_point(scope: Any, p: Point) -> None:
    scope.glitch.width = p.width
    scope.glitch.offset = p.offset
    scope.glitch.ext_offset = p.ext_offset
    scope.glitch.repeat = p.repeat
    scope.io.hs2 = "glitch"


def ping_target(scope: Any, target: Any, args: argparse.Namespace) -> Tuple[bool, str]:
    old_hs2 = scope.io.hs2
    try:
        scope.io.hs2 = "clkgen"
        time.sleep(args.post_ping_settle)
        target.flush()
        target.simpleserial_write("P", bytearray([]))
        resp = target.simpleserial_read_witherrors("P", 1, glitch_timeout=args.ping_timeout)
        payload = payload_bytes(resp.get("payload") if isinstance(resp, dict) else None)
        ok = bool(resp.get("valid")) and payload == PING_VALUE if isinstance(resp, dict) else False
        return ok, response_full_repr(resp)
    except Exception as e:
        return False, "PING_EXCEPTION:" + repr(e)
    finally:
        try:
            scope.io.hs2 = old_hs2
        except Exception:
            pass


def no_glitch_sanity(scope: Any, target: Any, args: argparse.Namespace) -> None:
    print("[sanity] reset and test P/H without glitch...")
    scope.io.hs2 = "clkgen"
    reset_target(scope, args.reset_delay)

    target.flush()
    target.simpleserial_write("P", bytearray([]))
    presp = target.simpleserial_read_witherrors("P", 1, glitch_timeout=2.0)
    ppayload = payload_bytes(presp.get("payload") if isinstance(presp, dict) else None)
    if not (isinstance(presp, dict) and presp.get("valid") and ppayload == PING_VALUE):
        raise RuntimeError(f"P sanity failed: {presp!r}")

    for i in range(args.sanity_h_trials):
        target.flush()
        scope.arm()
        target.simpleserial_write("H", bytearray([]))
        cap_timeout = scope.capture()
        resp = target.simpleserial_read_witherrors("H", 4, glitch_timeout=5.0)
        payload = payload_bytes(resp.get("payload") if isinstance(resp, dict) else None)
        h = int.from_bytes(payload, "little") if len(payload) == 4 else None
        trig = getattr(scope.adc, "trig_count", None)
        if cap_timeout or not (isinstance(resp, dict) and resp.get("valid")) or h != NORMAL_H or not trig:
            raise RuntimeError(
                f"H sanity failed at {i}: cap_timeout={cap_timeout}, h={h}, trig={trig}, resp={resp!r}"
            )
    print("[sanity] OK: P responds and H returns 1664 without glitch.")
    scope.io.hs2 = "glitch"


def classify_h_trial(scope: Any, target: Any, args: argparse.Namespace) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "classification": "", "h": "", "valid": "", "payload_hex": "",
        "full_response": "", "capture_timeout": "", "trigger_count": "",
        "ping_after_h0": "", "need_reset": False, "error": "",
    }
    try:
        target.flush()
        scope.arm()
        target.simpleserial_write("H", bytearray([]))
        cap_timeout = bool(scope.capture())
        resp = target.simpleserial_read_witherrors("H", 4, glitch_timeout=args.read_timeout)

        trig = getattr(scope.adc, "trig_count", None)
        row["capture_timeout"] = int(cap_timeout)
        row["trigger_count"] = trig if trig is not None else ""
        row["full_response"] = response_full_repr(resp)
        row["payload_hex"] = response_payload_hex(resp)

        full_text = response_text(resp.get("full_response") if isinstance(resp, dict) else resp)
        payload = payload_bytes(resp.get("payload") if isinstance(resp, dict) else None)
        valid = bool(resp.get("valid")) if isinstance(resp, dict) else False
        row["valid"] = int(valid)

        if cap_timeout:
            row["classification"] = "scope_timeout"
            row["need_reset"] = True
            return row
        if "HARDFAULT" in full_text:
            row["classification"] = "hardfault"
            row["need_reset"] = True
            return row
        if (not valid) or len(payload) != 4:
            row["classification"] = "invalid_response"
            row["need_reset"] = True
            return row

        h = int.from_bytes(payload, "little")
        row["h"] = h
        if h == NORMAL_H:
            row["classification"] = "normal_1664"
            row["need_reset"] = False
            return row
        if h == 0:
            ok, ping_repr = ping_target(scope, target, args)
            row["ping_after_h0"] = "ok" if ok else "fail"
            row["full_response"] = row["full_response"] + " | post_ping=" + ping_repr
            row["classification"] = "target_load_skip_h0_ping_ok" if ok else "target_load_skip_h0_ping_fail"
            row["need_reset"] = True
            return row

        row["classification"] = f"other_h_{h}"
        row["need_reset"] = True
        return row
    except Exception as e:
        row["classification"] = "exception"
        row["error"] = repr(e)
        row["need_reset"] = True
        return row


def generate_points(args: argparse.Namespace) -> List[Point]:
    widths = parse_float_list(args.widths)
    offsets = parse_float_list(args.offsets)
    repeats = parse_int_list(args.repeats)
    exts = list(range(args.ext_start, args.ext_stop + 1, args.ext_step))
    points = [Point(w, o, e, r) for w in widths for o in offsets for e in exts for r in repeats]
    if args.prioritize_current:
        current = Point(args.current_width, args.current_offset, args.current_ext_offset, args.current_repeat)
        points = [current] + [p for p in points if p != current]
    return points


def summarize_one(p: Point, c: Counter, n: int) -> Dict[str, Any]:
    h0ok = c.get("target_load_skip_h0_ping_ok", 0)
    h0fail = c.get("target_load_skip_h0_ping_fail", 0)
    normal = c.get("normal_1664", 0)
    hard = c.get("hardfault", 0)
    invalid = c.get("invalid_response", 0)
    timeout = c.get("scope_timeout", 0)
    exc = c.get("exception", 0)
    other = sum(v for k, v in c.items() if k.startswith("other_h_"))
    bad = h0fail + hard + invalid + timeout + exc + other
    h0ok_rate = h0ok / n if n else 0.0
    bad_rate = bad / n if n else 0.0
    score = 100.0 * h0ok_rate - 25.0 * bad_rate
    return {
        "point_key": p.key, "width": p.width, "offset": p.offset, "ext_offset": p.ext_offset,
        "repeat": p.repeat, "trials": n, "normal_1664": normal,
        "h0_ping_ok": h0ok, "h0_ping_fail": h0fail, "hardfault": hard,
        "invalid_response": invalid, "scope_timeout": timeout, "exception": exc,
        "other_h_total": other, "bad_non_target_total": bad,
        "h0_ping_ok_rate": h0ok_rate,
        "h0_total_rate": (h0ok + h0fail) / n if n else 0.0,
        "normal_rate": normal / n if n else 0.0,
        "hardfault_rate": hard / n if n else 0.0,
        "invalid_rate": invalid / n if n else 0.0,
        "scope_timeout_rate": timeout / n if n else 0.0,
        "other_h_rate": other / n if n else 0.0,
        "bad_non_target_rate": bad_rate,
        "score": score,
    }


def update_summary_csv(summary_path: Path, stats: Dict[Point, Counter], trials_by_point: Dict[Point, int]) -> None:
    fieldnames = [
        "point_key", "width", "offset", "ext_offset", "repeat", "trials",
        "normal_1664", "h0_ping_ok", "h0_ping_fail", "hardfault",
        "invalid_response", "scope_timeout", "exception", "other_h_total",
        "bad_non_target_total", "h0_ping_ok_rate", "h0_total_rate", "normal_rate",
        "hardfault_rate", "invalid_rate", "scope_timeout_rate", "other_h_rate",
        "bad_non_target_rate", "score",
    ]
    rows = [summarize_one(p, c, trials_by_point.get(p, 0)) for p, c in stats.items() if trials_by_point.get(p, 0) > 0]
    rows.sort(key=lambda r: (r["score"], r["h0_ping_ok_rate"], -r["bad_non_target_rate"]), reverse=True)
    tmp = summary_path.with_suffix(".tmp")
    with tmp.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    tmp.replace(summary_path)


def load_existing_rows(rows_path: Path) -> Tuple[Dict[Point, Counter], Dict[Point, int], int]:
    stats: Dict[Point, Counter] = defaultdict(Counter)
    trials_by_point: Dict[Point, int] = defaultdict(int)
    global_trial = 0
    if not rows_path.exists():
        return stats, trials_by_point, global_trial
    with rows_path.open("r", newline="") as f:
        for row in csv.DictReader(f):
            try:
                p = Point(float(row["width"]), float(row["offset"]), int(row["ext_offset"]), int(row["repeat"]))
                stats[p][row["classification"]] += 1
                trials_by_point[p] += 1
                global_trial = max(global_trial, int(row.get("global_trial", 0)))
            except Exception:
                continue
    return stats, trials_by_point, global_trial


def top_points(stats: Dict[Point, Counter], trials_by_point: Dict[Point, int], k: int, min_trials: int = 1) -> List[Point]:
    scored = []
    for p, c in stats.items():
        n = trials_by_point.get(p, 0)
        if n < min_trials:
            continue
        s = summarize_one(p, c, n)
        scored.append((s["h0_ping_ok"] > 0, s["score"], s["h0_ping_ok_rate"], -s["bad_non_target_rate"], s["h0_ping_ok"], p))
    scored.sort(key=lambda x: x[:-1], reverse=True)
    return [x[-1] for x in scored[:k]]


def print_top(summary_path: Path, limit: int = 12) -> None:
    if not summary_path.exists():
        return
    try:
        import pandas as pd
        s = pd.read_csv(summary_path)
        cols = [
            "width", "offset", "ext_offset", "repeat", "trials", "h0_ping_ok",
            "h0_ping_ok_rate", "hardfault_rate", "invalid_rate", "other_h_rate",
            "bad_non_target_rate", "score",
        ]
        print("\n[top candidates]")
        print(s[cols].head(limit).to_string(index=False))
    except Exception:
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=12.0)
    ap.add_argument("--out-dir", type=Path, default=Path("data/analysis/h_command_auto_sweep_12h"))
    ap.add_argument("--widths", default="0.25,0.30,0.35,0.40")
    ap.add_argument("--offsets", default="-44,-40,-36,-32")
    ap.add_argument("--ext-start", type=int, default=18)
    ap.add_argument("--ext-stop", type=int, default=23)
    ap.add_argument("--ext-step", type=int, default=1)
    ap.add_argument("--repeats", default="1")
    ap.add_argument("--initial-trials", type=int, default=200)
    ap.add_argument("--extend-trials", type=int, default=200)
    ap.add_argument("--top-k", type=int, default=12)
    ap.add_argument("--summary-interval", type=int, default=50)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--prioritize-current", action="store_true", default=True)
    ap.add_argument("--current-width", type=float, default=0.3)
    ap.add_argument("--current-offset", type=float, default=-40.0)
    ap.add_argument("--current-ext-offset", type=int, default=20)
    ap.add_argument("--current-repeat", type=int, default=1)
    ap.add_argument("--clkgen-freq", type=float, default=7372800)
    ap.add_argument("--adc-src", default="clkgen_x4")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--samples", type=int, default=5000)
    ap.add_argument("--adc-timeout", type=float, default=0.2)
    ap.add_argument("--read-timeout", type=float, default=2.0)
    ap.add_argument("--ping-timeout", type=float, default=2.0)
    ap.add_argument("--post-ping-settle", type=float, default=0.05)
    ap.add_argument("--reset-delay", type=float, default=1.5)
    ap.add_argument("--sanity-h-trials", type=int, default=3)
    ap.add_argument("--skip-sanity", action="store_true")
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    rows_path = args.out_dir / "h_rows.csv"
    summary_path = args.out_dir / "h_summary.csv"
    metadata_path = args.out_dir / "metadata.json"
    points = generate_points(args)
    end_time = time.time() + args.hours * 3600.0

    args_json = {}
    for k, v in vars(args).items():
        if isinstance(v, Path):
            args_json[k] = str(v)
        else:
            args_json[k] = v

    metadata = {
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hours": args.hours,
        "out_dir": str(args.out_dir),
        "points": [p.__dict__ for p in points],
        "args": args_json,
        "normal_h": NORMAL_H,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"[info] out_dir={args.out_dir}")
    print(f"[info] total grid points={len(points)}")
    print(f"[info] time budget={args.hours} hours")
    for p in points[:10]:
        print("  ", p.key)

    if args.resume:
        stats, trials_by_point, global_trial = load_existing_rows(rows_path)
        print(f"[resume] global_trial={global_trial}, points_with_data={len(trials_by_point)}")
    else:
        stats, trials_by_point, global_trial = defaultdict(Counter), defaultdict(int), 0
        if rows_path.exists():
            backup = rows_path.with_suffix(f".bak_{int(time.time())}.csv")
            rows_path.rename(backup)
            print(f"[info] old rows backed up to {backup}")

    scope = setup_scope(args)
    target = setup_target(scope, args)
    stop_requested = False

    def handle_signal(signum, frame):
        nonlocal stop_requested
        stop_requested = True
        print("\n[signal] stop requested; finishing current trial and writing summary...")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    row_fields = [
        "timestamp", "global_trial", "phase", "point_key", "width", "offset",
        "ext_offset", "repeat", "trial_in_point", "classification", "h", "valid",
        "capture_timeout", "trigger_count", "ping_after_h0", "payload_hex",
        "full_response", "error", "actual_hs2", "actual_glitch_width",
        "actual_glitch_offset", "actual_glitch_ext_offset", "actual_glitch_repeat",
        "actual_glitch_output", "actual_glitch_clk_src", "actual_glitch_trigger_src",
    ]

    try:
        if not args.skip_sanity:
            no_glitch_sanity(scope, target, args)

        write_header = not rows_path.exists()
        with rows_path.open("a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=row_fields)
            if write_header:
                writer.writeheader()
                f.flush()

            def run_trial(p: Point, phase: str) -> None:
                nonlocal global_trial
                apply_point(scope, p)
                row = classify_h_trial(scope, target, args)
                global_trial += 1
                trials_by_point[p] += 1
                stats[p][row["classification"]] += 1
                out = {
                    "timestamp": time.time(), "global_trial": global_trial, "phase": phase,
                    "point_key": p.key, "width": p.width, "offset": p.offset,
                    "ext_offset": p.ext_offset, "repeat": p.repeat,
                    "trial_in_point": trials_by_point[p], "classification": row["classification"],
                    "h": row["h"], "valid": row["valid"], "capture_timeout": row["capture_timeout"],
                    "trigger_count": row["trigger_count"], "ping_after_h0": row["ping_after_h0"],
                    "payload_hex": row["payload_hex"], "full_response": row["full_response"],
                    "error": row["error"], "actual_hs2": getattr(scope.io, "hs2", ""),
                    "actual_glitch_width": getattr(scope.glitch, "width", ""),
                    "actual_glitch_offset": getattr(scope.glitch, "offset", ""),
                    "actual_glitch_ext_offset": getattr(scope.glitch, "ext_offset", ""),
                    "actual_glitch_repeat": getattr(scope.glitch, "repeat", ""),
                    "actual_glitch_output": getattr(scope.glitch, "output", ""),
                    "actual_glitch_clk_src": getattr(scope.glitch, "clk_src", ""),
                    "actual_glitch_trigger_src": getattr(scope.glitch, "trigger_src", ""),
                }
                writer.writerow(out)
                if row["need_reset"]:
                    reset_target(scope, args.reset_delay)
                if global_trial % args.summary_interval == 0:
                    f.flush(); os.fsync(f.fileno())
                    update_summary_csv(summary_path, stats, trials_by_point)
                    c = stats[p]
                    print(
                        f"[progress] t={time.strftime('%H:%M:%S')} global={global_trial} "
                        f"phase={phase} {p.key} trial_in_point={trials_by_point[p]} "
                        f"cls={row['classification']} h0ok={c.get('target_load_skip_h0_ping_ok',0)} "
                        f"hard={c.get('hardfault',0)}"
                    )

            print("\n[phase1] full-grid initial pass")
            for p in points:
                while trials_by_point[p] < args.initial_trials:
                    if stop_requested or time.time() >= end_time:
                        raise TimeoutError("time budget reached during phase1")
                    run_trial(p, "initial_grid")

            f.flush(); os.fsync(f.fileno())
            update_summary_csv(summary_path, stats, trials_by_point)
            print_top(summary_path)

            round_id = 0
            while not stop_requested and time.time() < end_time:
                round_id += 1
                candidates = top_points(stats, trials_by_point, k=args.top_k, min_trials=max(10, min(args.initial_trials, 50)))
                if not candidates:
                    candidates = points[:args.top_k]
                print(f"\n[phase2] extension round {round_id}; candidates:")
                for p in candidates:
                    print(f"  {p.key}: trials={trials_by_point[p]}, counts={dict(stats[p])}")
                for p in candidates:
                    target_trials = trials_by_point[p] + args.extend_trials
                    while trials_by_point[p] < target_trials:
                        if stop_requested or time.time() >= end_time:
                            raise TimeoutError("time budget reached during extension")
                        run_trial(p, f"extend_round_{round_id}")
                    f.flush(); os.fsync(f.fileno())
                    update_summary_csv(summary_path, stats, trials_by_point)
                    print_top(summary_path, limit=8)

    except TimeoutError as e:
        print(f"\n[done] {e}")
    except KeyboardInterrupt:
        print("\n[done] KeyboardInterrupt")
    finally:
        try:
            update_summary_csv(summary_path, stats, trials_by_point)
            print_top(summary_path, limit=20)
        except Exception as e:
            print("[warn] failed to write final summary:", repr(e))
        try:
            scope.io.hs2 = "clkgen"
        except Exception:
            pass
        try:
            target.dis()
        except Exception:
            pass
        try:
            scope.dis()
        except Exception:
            pass
        print(f"\n[final] rows: {rows_path}")
        print(f"[final] summary: {summary_path}")
        print(f"[final] metadata: {metadata_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
