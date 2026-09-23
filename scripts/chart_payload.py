#!/usr/bin/env python3
"""Render honest radar coverage and a complete Shamir comparison from Pilot data."""

import argparse
import csv
import json
import math
from pathlib import Path
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

LABELS = {
    "shamir": "Shamir",
    "blakley": "Blakley",
    "kothari": "Kothari",
    "karchmer_wigderson": "Karchmer–\nWigderson",
    "brickell": "Brickell",
    "massey": "Massey",
    "ramp": "Ramp",
    "yamamoto": "Yamamoto",
    "blakley_meadows": "Blakley–\nMeadows",
    "kgh": "KGH",
    "vss": "VSS",
    "cgma_vss": "CGMA VSS",
    "mignotte": "Mignotte",
    "asmuth_bloom": "Asmuth–\nBloom",
    "trivial": "Additive\n5-of-5",
    "trivial_xor": "XOR\n5-of-5",
    "ito": "Ito",
    "benaloh_leichter": "Benaloh–\nLeichter",
    "bytes": "Shamir\nbyte API",
    "ida": "IDA",
    "visual": "Visual\n3-of-3",
}
COLORS = {"rust": "#2378BC", "cpp": "#E67722"}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("results", type=Path)
    ap.add_argument("output", type=Path)
    a = ap.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    rows = json.loads((a.results / "results.json").read_text())
    for row in rows:
        if row["status"] != "ok":
            continue
        label = f"{row['method']}-{row['bytes']}-{row['phase']}-{row['implementation']}"
        exported = a.results / label / "pi_results.csv"
        if exported.exists():
            item = next(csv.DictReader(exported.open()))
            row["mean_ms"] = float(item["readings_mean"])
            row["ci_full_width_ms"] = float(item["readings_subsession_ci"])
            row["rounds"] = int(item["readings_num"])
    (a.output / "measurements.json").write_text(json.dumps(rows, indent=2) + "\n")
    keys = [
        "method",
        "bytes",
        "phase",
        "implementation",
        "status",
        "mean_ms",
        "ci_full_width_ms",
        "rounds",
    ]
    with (a.output / "measurements.csv").open("w") as out:
        writer = csv.DictWriter(
            out, fieldnames=keys, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)
    values = {
        (r["method"], r["bytes"], r["phase"], r["implementation"]): r for r in rows
    }
    methods = list(dict.fromkeys(r["method"] for r in rows))
    means = [r["mean_ms"] for r in rows if r["status"] == "ok"]
    bottom = math.floor(math.log10(min(means)))
    top = math.ceil(math.log10(max(means)))
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 11,
            "axes.titleweight": "bold",
            "savefig.facecolor": "#FAFBFD",
            "figure.facecolor": "#FAFBFD",
        }
    )
    theta = np.linspace(0, 2 * np.pi, len(methods), endpoint=False)
    closed = np.r_[theta, theta[0]]

    def tick(v):
        ms = 10.0**v
        if ms < 1:
            return f"{ms*1000:g} µs"
        if ms >= 1000:
            return f"{ms/1000:g} s"
        return f"{ms:g} ms"

    for size in [64, 1024]:
        fig, axes = plt.subplots(
            1, 2, figsize=(19, 11), subplot_kw={"projection": "polar"}
        )
        for ax, phase in zip(axes, ["split", "reconstruct"]):
            ax.set_theta_offset(np.pi / 2)
            ax.set_theta_direction(-1)
            ax.set_xticks(theta, [LABELS[m] for m in methods], fontsize=10)
            ax.tick_params(axis="x", pad=16)
            ax.set_ylim(0, top - bottom + 1)
            ticks = list(range(bottom, top + 1, 2))
            ax.set_yticks(
                [v - bottom + 1 for v in ticks],
                [tick(v) for v in ticks],
                fontsize=9,
                color="#5C6470",
            )
            ax.set_rlabel_position(185)
            ax.grid(color="#DCE2EB", linewidth=0.8)
            ax.spines["polar"].set_color("#DCE2EB")
            ax.set_facecolor("white")
            for language in ["rust", "cpp"]:
                y = []
                for method in methods:
                    row = values.get((method, size, phase, language), {})
                    y.append(
                        math.log10(row["mean_ms"]) - bottom + 1
                        if row.get("status") == "ok"
                        else np.nan
                    )
                label = "Rust" if language == "rust" else "C++ — Shamir only"
                if language == "rust":
                    ax.plot(
                        closed,
                        np.r_[y, y[0]],
                        color=COLORS[language],
                        lw=2,
                        marker="o",
                        ms=3,
                        label=label,
                    )
                    if all(np.isfinite(y)):
                        ax.fill(
                            closed, np.r_[y, y[0]], color=COLORS[language], alpha=0.07
                        )
                else:
                    ax.scatter(
                        theta,
                        y,
                        color=COLORS[language],
                        s=90,
                        marker="D",
                        zorder=6,
                        label=label,
                        edgecolors="white",
                    )
            ax.set_title(
                "Split" if phase == "split" else "Reconstruct", pad=50, fontsize=18
            )
        label = "64 bytes" if size == 64 else "1 KiB (1,024 bytes)"
        fig.suptitle(
            f"Dennard · {label} per secret", fontsize=23, y=0.97, fontweight="bold"
        )
        fig.text(
            0.5,
            0.915,
            "Latency per complete payload · logarithmic scale · closer to the center is faster",
            ha="center",
            fontsize=13,
            color="#4E5969",
        )
        handles, labels = axes[0].get_legend_handles_labels()
        fig.legend(
            handles,
            labels,
            loc="lower center",
            bbox_to_anchor=(0.5, 0.10),
            ncol=2,
            frameon=False,
            fontsize=13,
        )
        fig.text(
            0.5,
            0.066,
            "C++ has no implementation for the other 20 methods; missing values are not zero.",
            ha="center",
            fontsize=12,
        )
        fig.text(
            0.5,
            0.035,
            "Pilot normal preset · one pinned CPU · actual confidence intervals and scheme parameters in the accompanying report",
            ha="center",
            fontsize=10,
            color="#5C6470",
        )
        fig.subplots_adjust(left=0.07, right=0.93, top=0.79, bottom=0.24, wspace=0.35)
        for ext in ["png", "svg"]:
            fig.savefig(a.output / f"radar-{size}.{ext}", dpi=180)
        plt.close(fig)
    # This radar has four real, shared measurements, so both polygons are meaningful.
    cases = [(64, "split"), (64, "reconstruct"), (1024, "reconstruct"), (1024, "split")]
    angles = np.linspace(0, 2 * np.pi, 4, endpoint=False)
    angles = np.r_[angles, angles[0]]
    fig, ax = plt.subplots(figsize=(9, 9), subplot_kw={"projection": "polar"})
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_xticks(
        angles[:-1],
        ["64 B\nsplit", "64 B\nreconstruct", "1 KiB\nreconstruct", "1 KiB\nsplit"],
        fontsize=12,
    )
    ax.tick_params(axis="x", pad=18)
    ax.set_ylim(0, 1.05)
    ax.set_yticks([0.25, 0.5, 0.75, 1], ["25%", "50%", "75%", "100%"], fontsize=10)
    ax.grid(color="#DCE2EB")
    ax.spines["polar"].set_color("#DCE2EB")
    ax.set_facecolor("white")
    for language in ["rust", "cpp"]:
        scores = []
        for size, phase in cases:
            mine = values[("shamir", size, phase, language)]
            other = values[
                ("shamir", size, phase, "cpp" if language == "rust" else "rust")
            ]
            if mine["status"] != "ok" or other["status"] != "ok":
                scores.append(np.nan)
            else:
                scores.append(min(mine["mean_ms"], other["mean_ms"]) / mine["mean_ms"])
        scores = np.r_[scores, scores[0]]
        ax.plot(
            angles,
            scores,
            color=COLORS[language],
            lw=2.5,
            marker="o",
            label="Rust" if language == "rust" else "C++",
        )
        ax.fill(angles, scores, color=COLORS[language], alpha=0.12)
    fig.suptitle(
        "Shamir · Rust vs C++ on Dennard", fontsize=19, fontweight="bold", y=0.97
    )
    fig.text(
        0.5,
        0.915,
        "Relative throughput · faster implementation = 100% on each axis",
        ha="center",
        fontsize=11,
    )
    fig.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 0.08),
        ncol=2,
        frameon=False,
        fontsize=13,
    )
    fig.text(
        0.5,
        0.045,
        "3-of-5 · GF(2¹²⁷−1) · larger is faster · absolute times in the report",
        ha="center",
        fontsize=10,
    )
    fig.subplots_adjust(top=0.80, bottom=0.22, left=0.18, right=0.82)
    for ext in ["png", "svg"]:
        fig.savefig(a.output / f"radar-shamir.{ext}", dpi=180)
    plt.close(fig)
    # Matplotlib emits trailing spaces inside multiline SVG path attributes.
    for path in a.output.glob("radar-*.svg"):
        path.write_text(
            "\n".join(line.rstrip() for line in path.read_text().splitlines()) + "\n"
        )
    print(f"Wrote charts and {len(rows)} measurement/coverage rows to {a.output}")


if __name__ == "__main__":
    main()
