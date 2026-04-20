#!/usr/bin/env python3
"""
Makes analytic plots from results.

Usage:
    python3 benchmark/analyze.py \
        --results results-trivy.json results-grype.json \
                  results-clair.json results-trivy-estargz.json \
        --output charts.png
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

BASE_ORDER = ["ubuntu", "alpine", "fedora", "python", "node", "golang"]

SCANNER_COLORS = {
    "trivy":         "#4c78a8",
    "grype":         "#f58518",
    "clair":         "#54a24b",
    "trivy-estargz": "#e45756",
}

ESTARGZ_COLORS = {
    "fetched":  "#e45756",
    "estargz":  "#72b7b2",
    "original": "#b279a2",
}


def base_type(image_ref: str) -> str:
    name = image_ref.split("/")[-1].split(":")[0]  # ubuntu-os-deps-000
    return name.split("-")[0]  # ubuntu


def load_results(paths: list[Path]) -> list[dict]:
    results = []
    for p in paths:
        data = json.loads(p.read_text())
        results.extend(data.get("results", []))
    return results


def group_by_base(results, scanner, value_fn) -> dict[str, list]:
    groups: dict[str, list] = defaultdict(list)
    for result in results:
        if result["scanner"] != scanner or result.get("error"):
            continue
        value = value_fn(result)
        if value is not None:
            groups[base_type(result["image_ref"])].append(value)
    return groups


def base_means(groups: dict[str, list]) -> list[float]:
    return [float(np.mean(groups[b])) if groups.get(b) else 0.0 for b in BASE_ORDER]


def bar_labels(ax, bars, fmt="{:.0f}"):
    for bar in bars:
        h = bar.get_height()
        if h > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2, h,
                fmt.format(h), ha="center", va="bottom", fontsize=6.5,
            )


# ── Chart 1: Performance ────────────────────────────────────────────────────

def plot_performance(ax, results):
    scanners = sorted(
        {r["scanner"] for r in results if not r.get("error")},
        key=lambda s: list(SCANNER_COLORS).index(s) if s in SCANNER_COLORS else 99,
    )
    x = np.arange(len(BASE_ORDER))
    n = len(scanners)
    width = 0.7 / n

    for i, scanner in enumerate(scanners):
        groups = group_by_base(results, scanner, lambda r: r["wall_time"])
        heights = base_means(groups)
        offset = (i - n / 2 + 0.5) * width
        bars = ax.bar(
            x + offset, heights, width,
            label=scanner, color=SCANNER_COLORS.get(scanner, f"C{i}"), alpha=0.88,
        )
        bar_labels(ax, bars, "{:.0f}s")

    ax.set_xticks(x)
    ax.set_xticklabels(BASE_ORDER)
    ax.set_ylabel("Avg wall time (s)")
    ax.set_title("Scanner performance by base image type")
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=0.3)


# ── Chart 2: Fetch ratio ─────────────────────────────────────────────────────

def _estargz_triples(results, suffix="-estargz") -> dict[str, list[tuple[int, int, int]]]:
    # base -> [(bytes_fetched, estargz_layer_size, original_manifest_size)].

    original_size: dict[str, int] = {}
    for r in results:
        if r["scanner"] == "trivy" and r.get("manifest_layer_size"):
            original_size[r["image_ref"]] = r["manifest_layer_size"]

    groups: dict[str, list] = defaultdict(list)
    for r in results:
        if r["scanner"] != "trivy-estargz" or r.get("error") or not r.get("estargz_layers"):
            continue
        fetched = sum(l["bytes_fetched"] for l in r["estargz_layers"].values())
        estargz = r.get("manifest_layer_size") or sum(l["layer_size"] for l in r["estargz_layers"].values())
        base_ref = r["image_ref"][:-len(suffix)] if r["image_ref"].endswith(suffix) else r["image_ref"]
        orig = original_size.get(base_ref, 0)
        if estargz > 0:
            groups[base_type(r["image_ref"])].append((fetched, estargz, orig))

    return groups


def plot_fetch_ratio(ax, results):
    """
        - fetched / estargz total
        - fetched / original size
    """
    triples = _estargz_triples(results)
    x = np.arange(len(BASE_ORDER))
    width = 0.35

    ratio_e, ratio_o = [], []
    for b in BASE_ORDER:
        ts = triples.get(b, [(0, 1, 1)])
        avg_f = float(np.mean([t[0] for t in ts]))
        avg_e = float(np.mean([t[1] for t in ts]))
        avg_o = float(np.mean([t[2] for t in ts])) or avg_e  # fallback to estargz
        ratio_e.append(avg_f / avg_e * 100 if avg_e else 0.0)
        ratio_o.append(avg_f / avg_o * 100 if avg_o else 0.0)

    bars1 = ax.bar(x - width / 2, ratio_e, width,
                   label="fetched data size / estargz image size",
                   color=ESTARGZ_COLORS["fetched"], alpha=0.88)
    bars2 = ax.bar(x + width / 2, ratio_o, width,
                   label="fetched data size / original image size",
                   color=ESTARGZ_COLORS["original"], alpha=0.88)

    bar_labels(ax, bars1, "{:.0f}%")
    bar_labels(ax, bars2, "{:.0f}%")

    ax.set_xticks(x)
    ax.set_xticklabels(BASE_ORDER)
    ax.set_ylim(0, 115)
    ax.axhline(100, color="gray", linestyle="--", linewidth=0.8, alpha=0.5)
    ax.set_ylabel("Fetch ratio (%)")
    ax.set_title("trivy-estargz: fetch ratio by base image type")
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=0.3)


# ── Chart 3: Trivy image size ─────────────────────────────────────────────────

def plot_image_size(ax, results):
    """
        - estargz fetched
        - estargz total image size
        - original image size
    """
    MB = 1024 ** 2
    triples = _estargz_triples(results)
    x = np.arange(len(BASE_ORDER))
    width = 0.25

    fetched_mb, estargz_mb, original_mb = [], [], []
    for b in BASE_ORDER:
        ts = triples.get(b, [(0, 0, 0)])
        fetched_mb.append(float(np.mean([t[0] for t in ts])) / MB)
        estargz_mb.append(float(np.mean([t[1] for t in ts])) / MB)
        original_mb.append(float(np.mean([t[2] for t in ts])) / MB)

    bars1 = ax.bar(x - width, fetched_mb, width,
                   label="estargz fetched data size",  color=ESTARGZ_COLORS["fetched"],  alpha=0.88)
    bars2 = ax.bar(x,         estargz_mb, width,
                   label="estargz image size",    color=ESTARGZ_COLORS["estargz"],  alpha=0.88)
    bars3 = ax.bar(x + width, original_mb, width,
                   label="original image size",    color=ESTARGZ_COLORS["original"], alpha=0.88)

    for bars in (bars1, bars2, bars3):
        bar_labels(ax, bars, "{:.0f}")

    ax.set_xticks(x)
    ax.set_xticklabels(BASE_ORDER)
    ax.set_ylabel("Avg data size (MB)")
    ax.set_title("trivy-estargz: fetched data size by base image type")
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=0.3)


# ── Chart 4: Time vs image size ─────────────────────────────────────────────

def plot_time_to_image_size(ax, results):
    MB = 1024 ** 2
    base_colors = {b: f"C{i}" for i, b in enumerate(BASE_ORDER)}
    handles = {}

    for r in results:
        if r["scanner"] != "trivy-estargz" or r.get("error") or not r.get("estargz_layers"):
            continue
        fetched = sum(l["bytes_fetched"] for l in r["estargz_layers"].values()) / MB
        t = r["wall_time"]
        b = base_type(r["image_ref"])
        color = base_colors.get(b, "gray")
        sc = ax.scatter(fetched, t, color=color, alpha=0.65, s=30, zorder=3)
        if b not in handles:
            handles[b] = sc

    ax.set_xlabel("Fetched data size (MB)")
    ax.set_ylabel("Wall time (s)")
    ax.set_title("trivy-estargz: time to image size")
    ax.legend(
        [handles[b] for b in BASE_ORDER if b in handles],
        [b for b in BASE_ORDER if b in handles],
        fontsize=8, title="base",
    )
    ax.grid(alpha=0.3)


# ── Main ─────────────────────────────────────────────────────────────────────

CHARTS = {
    "performance":     (plot_performance,    (9, 5)),
    "fetch-ratio":     (plot_fetch_ratio,    (9, 5)),
    "image-size":          (plot_image_size,(9, 5)),
    "time-to-image-size":  (plot_time_to_image_size, (7, 5)),
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--results", type=Path, action="append", required=True,
                   help="results.json files from run_benchmark.py")
    p.add_argument("--outdir", type=Path, default=Path("."),
                   help="Directory for output PNGs (default: current dir)")
    p.add_argument("--dpi", type=int, default=150)
    return p.parse_args()


def main():
    args = parse_args()
    args.outdir.mkdir(parents=True, exist_ok=True)
    results = load_results(args.results)

    for name, (plot_fn, figsize) in CHARTS.items():
        fig, ax = plt.subplots(figsize=figsize)
        plot_fn(ax, results)
        plt.tight_layout()
        out = args.outdir / f"chart-{name}.png"
        fig.savefig(out, dpi=args.dpi, bbox_inches="tight")
        plt.close(fig)
        print(f"Saved: {out}")


if __name__ == "__main__":
    main()
