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
import matplotlib.colors as mcolors
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


# ── Chart 5: File stats pie charts ──────────────────────────────────────────

NOT_REQUIRED_LABEL = "(not required)"
NOT_REQUIRED_COLOR = "#d0d0d0"

# Colors for analyzer types actually observed in benchmark data.
ANALYZER_PALETTE = {
    # secret scanning (appears in all image types, ~7-10%)
    "secret":       "#e45756",
    # dpkg-family (debian-based: ubuntu, python, node)
    "dpkg-license": "#4c78a8",
    "dpkg":         "#2e5c8a",
    "debian":       "#1a3f6b",
    "ubuntu":       "#2a4f7b",
    # apk-family (alpine)
    "apk":          "#54a24b",
    "apk-repo":     "#3a8433",
    "alpine":       "#2a6424",
    # rpm-family (fedora)
    "rpm":          "#c0392b",
    "fedora":       "#922b21",
    # language analyzers
    "node-pkg":     "#e9c46a",
    "python-pkg":   "#f58518",
    # os metadata (appears as 1-2 files per image)
    "os-release":   "#999999",
}


def load_stats_dir(stats_dir: Path) -> dict[str, list[dict]]:
    """Load all stats JSON files from stats_dir, grouped by base image type."""
    groups: dict[str, list] = defaultdict(list)
    for path in sorted(stats_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
            btype = base_type(data.get("image", path.stem))
            if btype in BASE_ORDER:
                groups[btype].append(data)
        except Exception:
            pass
    return groups


def _sum_files_by_analyzer(stats_list: list[dict]) -> tuple[dict[str, int], dict[str, int]]:
    """Sum file counts and bytes per required_by category across all stats JSONs.

    Each file is counted exactly once:
      - under its first required_by analyzer if required_by is non-empty,
      - under NOT_REQUIRED_LABEL otherwise.
    Cached layers are skipped (no file list available).
    Returns (counts, sizes_bytes).
    """
    counts: dict[str, int] = defaultdict(int)
    sizes:  dict[str, int] = defaultdict(int)
    for stats_data in stats_list:
        for layer in stats_data.get("layers", []):
            if layer.get("cached"):
                continue
            for f in layer.get("files") or []:
                rb  = f.get("required_by") or []
                key = rb[0] if rb else NOT_REQUIRED_LABEL
                counts[key] += 1
                sizes[key]  += f.get("size", 0)
    return dict(counts), dict(sizes)


def _fmt_bytes(n: int) -> str:
    if n >= 1024 ** 3:
        return f"{n / 1024**3:.1f} GB"
    if n >= 1024 ** 2:
        return f"{n / 1024**2:.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def _build_color_map(stats_groups: dict[str, list]) -> dict[str, str]:
    """Assign a stable color to every analyzer type seen across all groups."""
    all_analyzers = sorted({
        k
        for g in stats_groups.values()
        for s in g
        for k in _sum_files_by_analyzer([s])[0]
        if k != NOT_REQUIRED_LABEL
    })
    tab10 = list(plt.cm.tab10.colors)
    palette_colors = set(ANALYZER_PALETTE.values())
    fallback = [c for c in tab10 if c not in palette_colors]
    fb_idx = 0
    color_map: dict[str, str] = {NOT_REQUIRED_LABEL: NOT_REQUIRED_COLOR}
    for name in all_analyzers:
        if name in ANALYZER_PALETTE:
            color_map[name] = ANALYZER_PALETTE[name]
        else:
            color_map[name] = fallback[fb_idx % len(fallback)]
            fb_idx += 1
    return color_map


def _draw_pie(ax, values: dict[str, int | float], color_map: dict,
              title: str, legend_fmt):
    """Draw a single pie chart on ax. legend_fmt(key, val) → legend label string."""
    if not values:
        ax.text(0.5, 0.5, "no data", ha="center", va="center", fontsize=10)
        ax.set_title(title, fontweight="bold")
        ax.axis("off")
        return

    ordered = [NOT_REQUIRED_LABEL] + sorted(
        [k for k in values if k != NOT_REQUIRED_LABEL],
        key=lambda k: values[k], reverse=True,
    )
    ordered = [k for k in ordered if k in values]

    sizes  = [values[k] for k in ordered]
    colors = [color_map.get(k, "#999999") for k in ordered]
    total  = sum(sizes)

    wedges, _, autotexts = ax.pie(
        sizes, colors=colors,
        autopct=lambda pct: f"{pct:.1f}%" if pct >= 1.5 else "",
        pctdistance=0.78, startangle=90,
        wedgeprops={"linewidth": 0.4, "edgecolor": "white"},
    )
    for at in autotexts:
        at.set_fontsize(7)

    ax.legend(
        wedges, [legend_fmt(k, values[k]) for k in ordered],
        loc="center left", bbox_to_anchor=(1.02, 0.5),
        fontsize=7, title=legend_fmt(None, total), title_fontsize=7,
    )
    ax.set_title(title, fontweight="bold")


def _make_pies_figure(stats_groups: dict[str, list], use_bytes: bool) -> plt.Figure:
    """2-row × 3-col grid of pie charts.

    use_bytes=False → slice size = file count
    use_bytes=True  → slice size = total bytes
    """
    ncols, nrows = 3, 2
    metric = "file size (bytes)" if use_bytes else "file count"
    fig, axes = plt.subplots(nrows, ncols, figsize=(15, 10))
    fig.suptitle(
        f"File distribution by Trivy analyzer requirement — {metric}\n",
        fontsize=12,
    )

    color_map = _build_color_map(stats_groups)

    for i, base in enumerate(BASE_ORDER):
        stats  = stats_groups.get(base, [])
        counts, sizes = _sum_files_by_analyzer(stats)
        values = sizes if use_bytes else counts

        if use_bytes:
            legend_fmt = lambda k, v: f"total: {_fmt_bytes(v)}" if k is None \
                                      else f"{k}  ({_fmt_bytes(v)})"
        else:
            legend_fmt = lambda k, v: f"total: {v:,} files" if k is None \
                                      else f"{k}  ({v:,})"

        _draw_pie(
            axes.flat[i], values, color_map,
            title=f"{base}",
            legend_fmt=legend_fmt,
        )

    for i in range(len(BASE_ORDER), nrows * ncols):
        axes.flat[i].axis("off")

    return fig


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
    p.add_argument("--stats-dir", type=Path, default=None,
                   help="Directory with trivy --stats-file JSON outputs; "
                        "enables chart-file-stats.png")
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

    if args.stats_dir and args.stats_dir.is_dir():
        stats_groups = load_stats_dir(args.stats_dir)
        for use_bytes, name in [(False, "chart-file-stats-count.png"),
                                (True,  "chart-file-stats-bytes.png")]:
            fig = _make_pies_figure(stats_groups, use_bytes=use_bytes)
            plt.tight_layout()
            out = args.outdir / name
            fig.savefig(out, dpi=args.dpi, bbox_inches="tight")
            plt.close(fig)
            print(f"Saved: {out}")


if __name__ == "__main__":
    main()
