#!/usr/bin/env python3
"""plot_figs.py — render the paper's Figs. 2-4 from the measured CSVs.

  Fig. 2  exp1_authz_throughput.csv       -> fig/exp1_batch_throughput.{png,pdf}
  Fig. 3  exp2_scoped_revocation.csv      -> fig/exp2_revocation_overhead.{png,pdf}
  Fig. 4  exp3_unaffected_continuity.csv  -> fig/exp3_unaffected_continuity.{png,pdf}

It only READS the CSVs the drivers wrote; it never generates numbers. A figure
whose CSV is missing is skipped. If exp1_authz_throughput.csv is absent, the
Fig. 2 data measured in V2 (results_v2_exp1/) is plotted instead and said so.

Same identity as every other figure of the paper set:
  Ref [20] blue circle, Ref [24] orange square, Ref [28] green triangle,
  FLEX-DIAM red diamond; solid lines; no in-plot title (captions live in LaTeX).

Env: FIG2_CSV, FIG3_CSV, FIG4_CSV override the inputs;
     FIG3_LOGY / FIG4_LOGY = 0 switches that figure to a linear y axis.
"""

import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({
    "font.size": 13, "axes.titlesize": 15, "axes.labelsize": 14,
    "xtick.labelsize": 12, "ytick.labelsize": 12, "legend.fontsize": 12,
    "axes.grid": True, "grid.linestyle": "--", "grid.alpha": 0.5,
    "savefig.bbox": "tight",
})

SERIES = [  # (label, color, marker)
    ("FLEX-DIAM", "#d62728", "D"),
    ("Ref [20]",  "#1f77b4", "o"),
    ("Ref [24]",  "#ff7f0e", "s"),
    ("Ref [28]",  "#2ca02c", "^"),
]


def read_csv(path):
    with open(path, newline="") as f:
        rows = list(csv.reader(f))
    header, data = rows[0], rows[1:]
    xs = [float(r[0]) for r in data]
    cols = {h: [float(r[i]) for r in data] for i, h in enumerate(header) if i > 0}
    return xs, cols


def render(xs, cols, xlabel, ylabel, out, logy=False, legend_loc="best",
           legend_anchor=None, legend_ncol=1):
    fig, ax = plt.subplots(figsize=(8, 6))
    for label, color, marker in SERIES:
        if label not in cols:
            print(f"  WARNING: column {label!r} missing")
            continue
        ax.plot(xs, cols[label], label=label, color=color, marker=marker,
                linestyle="-", linewidth=1.8, markersize=8,
                markeredgecolor="white", markeredgewidth=0.6)
    if logy:
        ax.set_yscale("log")
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.legend(loc=legend_loc, bbox_to_anchor=legend_anchor, ncol=legend_ncol,
              framealpha=0.95, edgecolor="#888")
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(out + ".png", dpi=300)
    fig.savefig(out + ".pdf")
    plt.close(fig)
    print(f"saved {out}.png / .pdf")


def main():
    os.makedirs("fig", exist_ok=True)

    f2 = os.environ.get("FIG2_CSV", "exp1_authz_throughput.csv")
    if not os.path.exists(f2):
        fallback = os.path.join("results_v2_exp1", "exp_fig2_authz_throughput.csv")
        if os.path.exists(fallback):
            print(f"Fig. 2: {f2} not found — plotting the V2 measurement ({fallback})")
            f2 = fallback
    if os.path.exists(f2):
        xs, cols = read_csv(f2)
        render(xs, cols,
               "Number of Concurrent Authorization Requests",
               "Authorization Throughput (requests/s)",
               "fig/exp1_batch_throughput")
    else:
        print(f"skip Fig. 2 ({f2} not found)")

    f3 = os.environ.get("FIG3_CSV", "exp2_scoped_revocation.csv")
    if os.path.exists(f3):
        xs, cols = read_csv(f3)
        render(xs, cols,
               "Number of Revoked Users",
               "End-to-End Revocation Latency (ms)",
               "fig/exp2_revocation_overhead",
               logy=os.environ.get("FIG3_LOGY", "1") != "0")
    else:
        print(f"skip Fig. 3 ({f3} not found)")

    f4 = os.environ.get("FIG4_CSV", "exp3_unaffected_continuity.csv")
    if os.path.exists(f4):
        xs, cols = read_csv(f4)
        render(xs, cols,
               "Number of Revoked Users",
               "Unaffected-User Access Latency (ms)",
               "fig/exp3_unaffected_continuity",
               logy=os.environ.get("FIG4_LOGY", "1") != "0",
               # four nearly horizontal lines: automatic placement lands on
               # one of them, so the legend is pinned in the empty band
               # between the top two
               legend_loc="center", legend_anchor=(0.5, 0.77), legend_ncol=2)
    else:
        print(f"skip Fig. 4 ({f4} not found)")


if __name__ == "__main__":
    main()
