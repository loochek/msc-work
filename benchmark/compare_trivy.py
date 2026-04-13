#!/usr/bin/env python3
"""
Compare trivy vs trivy-estargz vuln counts from results.json.

For each image that was scanned by both scanners, diffs the severity counts.
Exit code: 0 if all match, 1 if any mismatch.

"""

import argparse
import json
import sys
from pathlib import Path


def normalize_ref(ref: str, suffix: str) -> str:
    return ref[:-len(suffix)] if ref.endswith(suffix) else ref


def fmt_vulns(v: dict) -> str:
    return (f"C={v['critical']} H={v['high']} M={v['medium']} "
            f"L={v['low']} O={v['other']}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--results", type=Path, required=True,
                   help="results.json from run_benchmark.py")
    p.add_argument("--suffix", default="-estargz",
                   help="Tag suffix used for eStargz images (default: -estargz)")
    args = p.parse_args()

    data = json.loads(args.results.read_text())

    # Index: base_ref → scanner → row
    by_ref: dict[str, dict[str, dict]] = {}
    for r in data["results"]:
        if r.get("error"):
            continue
        scanner = r["scanner"]
        ref = r["image_ref"]
        base = normalize_ref(ref, args.suffix)
        by_ref.setdefault(base, {})[scanner] = r

    ok = mismatch = skipped = 0
    for base_ref, scanners in sorted(by_ref.items()):
        t = scanners.get("trivy")
        e = scanners.get("trivy-estargz")
        if not t or not e:
            skipped += 1
            continue

        tv, ev = t["vulns"], e["vulns"]
        if tv == ev:
            ok += 1
            print(f"OK   {base_ref}  {fmt_vulns(tv)}")
        else:
            mismatch += 1
            diff = {k: ev[k] - tv[k] for k in tv if ev[k] != tv[k]}
            diff_str = "  ".join(f"{k.upper()}:{'+' if d>0 else ''}{d}"
                                 for k, d in diff.items())
            print(f"DIFF {base_ref}")
            print(f"     trivy:         {fmt_vulns(tv)}")
            print(f"     trivy-estargz: {fmt_vulns(ev)}")
            print(f"     delta:         {diff_str}")

    print(f"\n{ok} match, {mismatch} mismatch, {skipped} skipped (missing one scanner)")
    return 0 if mismatch == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
