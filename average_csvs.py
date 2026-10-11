#!/usr/bin/env python3
"""average_csvs.py — average several result CSVs cell-by-cell.

Usage: python average_csvs.py OUT.csv run1.csv run2.csv ...
Writes OUT.csv (per-cell mean) and OUT_std.csv (per-cell population stdev, for
error bars). All inputs must share the same header and first column (the N axis).
"""
import csv
import statistics
import sys


def read(path):
    with open(path, newline="") as f:
        rows = list(csv.reader(f))
    return rows[0], rows[1:]


def main():
    out = sys.argv[1]
    files = sys.argv[2:]
    if not files:
        sys.exit("need at least one input CSV")

    header, first = read(files[0])
    runs = [first] + [read(f)[1] for f in files[1:]]

    # sanity: same shape + same N column
    for r in runs:
        if len(r) != len(first):
            sys.exit("row count mismatch across runs")

    mean_rows, std_rows = [], []
    for ri in range(len(first)):
        n_val = first[ri][0]
        mrow, srow = [n_val], [n_val]
        for ci in range(1, len(header)):
            vals = [float(run[ri][ci]) for run in runs if run[ri][ci] != ""]
            mrow.append(f"{statistics.mean(vals):.2f}" if vals else "")
            srow.append(f"{statistics.pstdev(vals):.2f}" if vals else "")
        mean_rows.append(mrow)
        std_rows.append(srow)

    with open(out, "w", newline="") as f:
        w = csv.writer(f); w.writerow(header); w.writerows(mean_rows)
    std_path = out.replace(".csv", "_std.csv")
    with open(std_path, "w", newline="") as f:
        w = csv.writer(f); w.writerow(header); w.writerows(std_rows)

    print(f"Averaged {len(files)} runs -> {out}  (+ {std_path} for error bars)")


if __name__ == "__main__":
    main()
