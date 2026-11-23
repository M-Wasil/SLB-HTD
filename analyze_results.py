#!/usr/bin/env python3
"""Summarize measured SLB-HTD runs captured by run_experiments.bash and generate E1-E4 figures."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
from pathlib import Path
import re
import statistics

FIELDS = [
    "exp_id", "proxy", "policy", "loss_pct", "concurrency", "duration_s", "run",
    "rps", "p50_ms", "p95_ms", "p99_ms", "total_requests", "failed_requests",
    "error_rate_pct", "b1_requests", "b2_requests", "b3_requests",
    "detection_time_s", "recovery_time_s",
]
TAG = re.compile(r"^(E[1-4])_(slb|haproxy)_(rr|lc)_loss(0|2|5)_c(50|200|500)_r([123])$")


def expected_tags() -> set[str]:
    tags = {f"E1_slb_{policy}_loss0_c50_r{run}" for policy in ("rr", "lc") for run in range(1, 4)}
    tags |= {f"{exp}_{proxy}_rr_loss{loss}_c50_r{run}"
             for exp in ("E2", "E3") for proxy in ("slb", "haproxy")
             for loss in (0, 2, 5) for run in range(1, 4)}
    tags |= {f"E4_{proxy}_rr_loss0_c{conns}_r{run}"
             for proxy in ("slb", "haproxy") for conns in (50, 200, 500)
             for run in range(1, 4)}
    return tags


def parse_hey(path: Path) -> dict[str, float | int]:
    content = path.read_text(encoding="utf-8", errors="replace")

    def metric(pattern: str) -> float:
        match = re.search(pattern, content, flags=re.MULTILINE)
        if not match:
            raise ValueError(f"Missing metric {pattern!r} in {path}")
        return float(match.group(1))

    rps = metric(r"^\s*Requests/sec:\s+([0-9.]+)")
    p50 = metric(r"^\s*50%\s+in\s+([0-9.]+)\s+secs") * 1000
    p95 = metric(r"^\s*95%\s+in\s+([0-9.]+)\s+secs") * 1000
    p99 = metric(r"^\s*99%\s+in\s+([0-9.]+)\s+secs") * 1000
    statuses = [(int(code), int(count)) for code, count in re.findall(
        r"^\s*\[(\d{3})\]\s+(\d+)\s+responses", content, re.MULTILINE)]
    if not statuses:
        raise ValueError(f"No HTTP status distribution in {path}")
    connection_errors = sum(int(count) for count in re.findall(
        r"^\s*\[(\d+)\]\s+(?:Get|Post|Put|Head|Delete|Patch)\s+", content, re.MULTILINE))
    total = sum(count for _, count in statuses) + connection_errors
    failed = sum(count for code, count in statuses if code != 200) + connection_errors
    if total == 0:
        raise ValueError(f"No completed or failed requests in {path}")
    return {"rps": round(rps, 2), "p50_ms": round(p50, 2), "p95_ms": round(p95, 2),
            "p99_ms": round(p99, 2), "total_requests": total, "failed_requests": failed,
            "error_rate_pct": round(100 * failed / total, 3)}


def backend_requests(path: Path) -> tuple[int, list[float]]:
    if not path.is_file():
        raise FileNotFoundError(path)
    times = [float(t) for t in re.findall(r"\[RECV_EPOCH=([0-9.]+)\].*?\[TYPE=PROXY\]",
                                           path.read_text(encoding="utf-8", errors="replace"))]
    return len(times), times


def event_times(path: Path) -> tuple[float, float]:
    if not path.is_file():
        raise FileNotFoundError(path)
    content = path.read_text(encoding="utf-8")
    stop = re.search(r"^STOP_EPOCH=([0-9.]+)$", content, re.MULTILINE)
    restart = re.search(r"^RESTART_EPOCH=([0-9.]+)$", content, re.MULTILINE)
    if not stop or not restart:
        raise ValueError(f"Missing stop/restart event in {path}")
    return float(stop.group(1)), float(restart.group(1))


def down_time(path: Path, stop: float) -> float | None:
    if not path.is_file():
        raise FileNotFoundError(path)
    content = path.read_text(encoding="utf-8", errors="replace")
    for line in content.splitlines():
        if "B2" not in line and "/b2" not in line:
            continue
        if "marked DOWN" not in line and " is DOWN" not in line:
            continue
        epoch = re.search(r"\[EPOCH=([0-9.]+)\]", line)
        if epoch:
            return float(epoch.group(1))
        stamp = re.search(r"\b([A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\b", line)
        if stamp:
            dt = datetime.strptime(f"{datetime.fromtimestamp(stop).year} {stamp.group(1)}", "%Y %b %d %H:%M:%S")
            return dt.timestamp()
    return None


def parse_run(raw_dir: Path, tag: str) -> dict[str, object]:
    match = TAG.fullmatch(tag)
    if not match:
        raise ValueError(f"Unexpected run tag: {tag}")
    exp, proxy, policy, loss, conns, run = match.groups()
    result: dict[str, object] = {
        "exp_id": exp, "proxy": "SLB" if proxy == "slb" else "HAProxy",
        "policy": "Least-Connections" if policy == "lc" else "Round-Robin",
        "loss_pct": int(loss), "concurrency": int(conns),
        "duration_s": 60 if exp == "E3" else 30, "run": int(run),
        **parse_hey(raw_dir / f"{tag}_hey.txt"),
    }
    backend_times: dict[str, list[float]] = {}
    for name in ("b1", "b2", "b3"):
        count, times = backend_requests(raw_dir / f"{tag}_{name}.log")
        result[f"{name}_requests"] = count
        backend_times[name] = times
    result["detection_time_s"] = ""
    result["recovery_time_s"] = ""
    if exp == "E3":
        stop, restart = event_times(raw_dir / f"{tag}_events.txt")
        down = down_time(raw_dir / f"{tag}_proxy.log", stop)
        if down is not None and down >= stop:
            result["detection_time_s"] = round(down - stop, 3)
        after_restart = [t for t in backend_times["b2"] if t >= restart]
        if after_restart:
            result["recovery_time_s"] = round(min(after_restart) - restart, 3)
    return result


def summarize(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    groups: dict[tuple[object, ...], list[dict[str, object]]] = {}
    for row in rows:
        key = tuple(row[k] for k in ("exp_id", "proxy", "policy", "loss_pct", "concurrency"))
        groups.setdefault(key, []).append(row)
    summary = []
    measures = ("rps", "p50_ms", "p95_ms", "p99_ms", "error_rate_pct", "failed_requests",
                "b1_requests", "b2_requests", "b3_requests", "detection_time_s", "recovery_time_s")
    for key, group in sorted(groups.items()):
        item: dict[str, object] = dict(zip(("exp_id", "proxy", "policy", "loss_pct", "concurrency"), key))
        item["runs"] = len(group)
        for measure in measures:
            values = [float(row[measure]) for row in group if row[measure] != ""]
            item[f"{measure}_mean"] = round(statistics.mean(values), 3) if values else ""
            item[f"{measure}_sd"] = round(statistics.stdev(values), 3) if len(values) > 1 else (0 if values else "")
            item[f"{measure}_min"] = round(min(values), 3) if values else ""
            item[f"{measure}_max"] = round(max(values), 3) if values else ""
        summary.append(item)
    return summary


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def generate_measured_plots(summary: list[dict[str, object]], fig_dir: Path) -> bool:
    """Generates E1-E4 Matplotlib charts directly from measured summary statistics."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        return False

    fig_dir.mkdir(parents=True, exist_ok=True)
    NAVY, TEAL, CORAL, AMBER, SLATE = "#6B1D2F", "#2D4F3E", "#A63A2B", "#C07A28", "#7A7067"

    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Bitstream Charter", "DejaVu Serif", "Noto Serif"],
        "figure.facecolor": "#FAF8F5",
        "axes.facecolor": "#FAF8F5",
        "axes.spines.top": False,
        "axes.spines.right": False,
        "font.size": 9.5,
        "axes.titlesize": 10.5,
        "axes.titleweight": "bold",
        "axes.labelsize": 9.5,
        "axes.labelweight": "bold",
        "axes.edgecolor": "#CBD5E1",
        "axes.grid": True,
        "grid.alpha": 0.3,
        "grid.linestyle": "--",
    })

    def find_row(exp_id: str, proxy: str, policy: str, loss_pct: int, conns: int) -> dict[str, object] | None:
        for r in summary:
            if (r["exp_id"] == exp_id and r["proxy"] == proxy and r["policy"] == policy
                    and int(r["loss_pct"]) == loss_pct and int(r["concurrency"]) == conns):
                return r
        return None

    width = 0.34

    # --- Figure E1: Round-Robin vs Least-Connections ---
    e1_rr = find_row("E1", "SLB", "Round-Robin", 0, 50)
    e1_lc = find_row("E1", "SLB", "Least-Connections", 0, 50)
    if e1_rr and e1_lc:
        fig, axes = plt.subplots(1, 2, figsize=(11.4, 4.2), dpi=200)
        x = np.arange(2)
        ax1 = axes[0]
        ax1_lat = ax1.twinx()
        ax1_lat.grid(False)

        b_rps = ax1.bar(x - width / 2, [e1_rr["rps_mean"], e1_lc["rps_mean"]], width,
                        yerr=[e1_rr["rps_sd"], e1_lc["rps_sd"]], capsize=4, color=NAVY, label="Throughput (Req/s)")
        b_p95 = ax1_lat.bar(x + width / 2, [e1_rr["p95_ms_mean"], e1_lc["p95_ms_mean"]], width,
                            yerr=[e1_rr["p95_ms_sd"], e1_lc["p95_ms_sd"]], capsize=4, color=TEAL, label="p95 Latency (ms)")
        ax1.set_xticks(x)
        ax1.set_xticklabels(["Round-Robin", "Least-Connections"])
        ax1.set_ylabel("Throughput (Req/s)", color=NAVY)
        ax1_lat.set_ylabel("p95 Latency (ms)", color=TEAL)
        ax1.set_ylim(0, max(float(e1_rr["rps_mean"]) + float(e1_rr["rps_sd"]),
                            float(e1_lc["rps_mean"]) + float(e1_lc["rps_sd"])) * 1.25)
        ax1_lat.set_ylim(0, max(float(e1_rr["p95_ms_mean"]) + float(e1_rr["p95_ms_sd"]),
                                float(e1_lc["p95_ms_mean"]) + float(e1_lc["p95_ms_sd"])) * 1.25)
        ax1.set_title("E1(a): Measured Throughput & p95 (0% Loss, 50c)")
        for bar, sd in zip(b_rps, [float(e1_rr["rps_sd"]), float(e1_lc["rps_sd"])]):
            h = bar.get_height()
            ax1.annotate(f"{h:.1f}", (bar.get_x() + bar.get_width() / 2, h + sd + 18), ha="center", va="bottom", fontsize=8.5, fontweight="bold", color=NAVY)
        for bar, sd in zip(b_p95, [float(e1_rr["p95_ms_sd"]), float(e1_lc["p95_ms_sd"])]):
            h = bar.get_height()
            ax1_lat.annotate(f"{h:.1f} ms", (bar.get_x() + bar.get_width() / 2, h + sd + 7), ha="center", va="bottom", fontsize=8.5, fontweight="bold", color=TEAL)

        ax2 = axes[1]
        bx = np.arange(3)
        rr_b = [float(e1_rr["b1_requests_mean"]), float(e1_rr["b2_requests_mean"]), float(e1_rr["b3_requests_mean"])]
        lc_b = [float(e1_lc["b1_requests_mean"]), float(e1_lc["b2_requests_mean"]), float(e1_lc["b3_requests_mean"])]
        rr_tot = sum(rr_b) or 1.0
        lc_tot = sum(lc_b) or 1.0
        rr_pct = [100 * v / rr_tot for v in rr_b]
        lc_pct = [100 * v / lc_tot for v in lc_b]
        b1 = ax2.bar(bx - width / 2, rr_pct, width, color=SLATE, label="Round-Robin")
        b2 = ax2.bar(bx + width / 2, lc_pct, width, color=AMBER, label="Least-Connections")
        ax2.set_xticks(bx)
        ax2.set_xticklabels(["B1 (0 ms)", "B2 (50 ms)", "B3 (150 ms)"])
        ax2.set_ylabel("Share of Completed Requests (%)")
        ax2.set_ylim(0, 80)
        ax2.set_title("E1(b): Measured Backend Traffic Distribution")
        ax2.legend(loc="upper right", frameon=True)
        for bar in b1:
            h = bar.get_height()
            ax2.annotate(f"{h:.1f}%", (bar.get_x() + bar.get_width() / 2, h + 1.5), ha="center", va="bottom", fontsize=8, fontweight="bold", color=SLATE)
        for bar in b2:
            h = bar.get_height()
            ax2.annotate(f"{h:.1f}%", (bar.get_x() + bar.get_width() / 2, h + 1.5), ha="center", va="bottom", fontsize=8, fontweight="bold", color="#8C5314")

        fig.tight_layout()
        fig.savefig(fig_dir / "fig_e1_rr_vs_lc.png", bbox_inches="tight")
        plt.close(fig)

    # --- Figure E2: SLB vs HAProxy under Transit Link Packet Loss ---
    losses = [0, 2, 5]
    slb_e2 = [find_row("E2", "SLB", "Round-Robin", l, 50) for l in losses]
    hap_e2 = [find_row("E2", "HAProxy", "Round-Robin", l, 50) for l in losses]
    if all(slb_e2) and all(hap_e2):
        fig, axes = plt.subplots(1, 3, figsize=(13.0, 4.0), dpi=200)
        lx = np.arange(3)
        axes[0].bar(lx - width / 2, [r["rps_mean"] for r in slb_e2], width, yerr=[r["rps_sd"] for r in slb_e2], capsize=4, color=NAVY, label="Python SLB")
        axes[0].bar(lx + width / 2, [r["rps_mean"] for r in hap_e2], width, yerr=[r["rps_sd"] for r in hap_e2], capsize=4, color=TEAL, label="HAProxy 2.x")
        axes[0].set_xticks(lx)
        axes[0].set_xticklabels(["0% Loss", "2% Loss", "5% Loss"])
        axes[0].set_ylabel("Throughput (Req/s)")
        axes[0].set_title("E2(a): Throughput vs Transit Loss")
        axes[0].legend(loc="upper right")

        axes[1].bar(lx - width / 2, [r["p95_ms_mean"] for r in slb_e2], width, yerr=[r["p95_ms_sd"] for r in slb_e2], capsize=4, color=NAVY, label="Python SLB")
        axes[1].bar(lx + width / 2, [r["p95_ms_mean"] for r in hap_e2], width, yerr=[r["p95_ms_sd"] for r in hap_e2], capsize=4, color=TEAL, label="HAProxy 2.x")
        axes[1].set_xticks(lx)
        axes[1].set_xticklabels(["0% Loss", "2% Loss", "5% Loss"])
        axes[1].set_ylabel("p95 Latency (ms)")
        axes[1].set_title("E2(b): p95 Latency vs Transit Loss")
        axes[1].legend(loc="upper left")

        axes[2].bar(lx - width / 2, [r["error_rate_pct_mean"] for r in slb_e2], width, yerr=[r["error_rate_pct_sd"] for r in slb_e2], capsize=4, color=CORAL, label="Python SLB")
        axes[2].bar(lx + width / 2, [r["error_rate_pct_mean"] for r in hap_e2], width, yerr=[r["error_rate_pct_sd"] for r in hap_e2], capsize=4, color=AMBER, label="HAProxy 2.x")
        axes[2].set_xticks(lx)
        axes[2].set_xticklabels(["0% Loss", "2% Loss", "5% Loss"])
        axes[2].set_ylabel("Error Rate (%)")
        axes[2].set_title("E2(c): Error Rate vs Transit Loss")
        axes[2].legend(loc="upper right")

        fig.tight_layout()
        fig.savefig(fig_dir / "fig_e2_loss_comparison.png", bbox_inches="tight")
        plt.close(fig)

    # --- Figure E3: Failure Detection & Recovery Time ---
    slb_e3 = [find_row("E3", "SLB", "Round-Robin", l, 50) for l in losses]
    hap_e3 = [find_row("E3", "HAProxy", "Round-Robin", l, 50) for l in losses]
    if all(slb_e3) and all(hap_e3):
        fig, axes = plt.subplots(1, 2, figsize=(11.4, 4.1), dpi=200)
        lx = np.arange(3)
        slb_det = [float(r["detection_time_s_mean"]) if r["detection_time_s_mean"] != "" else 0.0 for r in slb_e3]
        slb_det_sd = [float(r["detection_time_s_sd"]) if r["detection_time_s_sd"] != "" else 0.0 for r in slb_e3]
        hap_det = [float(r["detection_time_s_mean"]) if r["detection_time_s_mean"] != "" else None for r in hap_e3]
        slb_rec = [float(r["recovery_time_s_mean"]) for r in slb_e3]
        slb_rec_sd = [float(r["recovery_time_s_sd"]) for r in slb_e3]
        hap_rec = [float(r["recovery_time_s_mean"]) for r in hap_e3]
        hap_rec_sd = [float(r["recovery_time_s_sd"]) for r in hap_e3]

        axes[0].bar(lx - 0.25, slb_det, 0.24, yerr=slb_det_sd, capsize=3, color=NAVY, label="SLB Detection (fall=3)")
        if all(v is not None for v in hap_det):
            hap_det_sd = [float(r["detection_time_s_sd"]) for r in hap_e3]
            axes[0].bar(lx + 0.0, hap_det, 0.24, yerr=hap_det_sd, capsize=3, color=TEAL, label="HAProxy Detection (fall=3)")
            axes[0].bar(lx + 0.25, slb_rec, 0.24, yerr=slb_rec_sd, capsize=3, color=CORAL, label="SLB Recovery (rise=2)")
        else:
            axes[0].bar(lx + 0.0, slb_rec, 0.24, yerr=slb_rec_sd, capsize=3, color=CORAL, label="SLB Recovery (rise=2)")
            axes[0].bar(lx + 0.25, hap_rec, 0.24, yerr=hap_rec_sd, capsize=3, color=AMBER, label="HAProxy Recovery (rise=2)")
        axes[0].set_xticks(lx)
        axes[0].set_xticklabels(["0% Loss", "2% Loss", "5% Loss"])
        axes[0].set_ylabel("Time (seconds)")
        axes[0].set_ylim(0, 3.8)
        axes[0].set_title("E3(a): Measured Detection & Recovery Time")
        axes[0].legend(loc="upper right", fontsize=8.2)

        axes[1].bar(lx - width / 2, [r["error_rate_pct_mean"] for r in slb_e3], width, yerr=[r["error_rate_pct_sd"] for r in slb_e3], capsize=4, color=CORAL, label="Python SLB")
        axes[1].bar(lx + width / 2, [r["error_rate_pct_mean"] for r in hap_e3], width, yerr=[r["error_rate_pct_sd"] for r in hap_e3], capsize=4, color=AMBER, label="HAProxy 2.x")
        axes[1].set_xticks(lx)
        axes[1].set_xticklabels(["0% Loss", "2% Loss", "5% Loss"])
        axes[1].set_ylabel("Overall 60 s Error Rate (%)")
        axes[1].set_title("E3(b): Error Rate During Failover & Recovery")
        axes[1].legend(loc="upper right")

        fig.tight_layout()
        fig.savefig(fig_dir / "fig_e3_failover_recovery.png", bbox_inches="tight")
        plt.close(fig)

    # --- Figure E4: Concurrency Scaling ---
    conns_list = [50, 200, 500]
    slb_e4 = [find_row("E4", "SLB", "Round-Robin", 0, c) for c in conns_list]
    hap_e4 = [find_row("E4", "HAProxy", "Round-Robin", 0, c) for c in conns_list]
    if all(slb_e4) and all(hap_e4):
        fig, axes = plt.subplots(1, 2, figsize=(11.4, 4.1), dpi=200)
        cx = np.arange(3)
        axes[0].bar(cx - width / 2, [r["rps_mean"] for r in slb_e4], width, yerr=[r["rps_sd"] for r in slb_e4], capsize=4, color=NAVY, label="Python SLB")
        axes[0].bar(cx + width / 2, [r["rps_mean"] for r in hap_e4], width, yerr=[r["rps_sd"] for r in hap_e4], capsize=4, color=TEAL, label="HAProxy 2.x")
        axes[0].set_xticks(cx)
        axes[0].set_xticklabels(["50 Conns", "200 Conns", "500 Conns"])
        axes[0].set_ylabel("Throughput (Req/s)")
        axes[0].set_title("E4(a): Measured Throughput vs Concurrency")
        axes[0].legend(loc="upper left")

        axes[1].bar(cx - width / 2, [r["p95_ms_mean"] for r in slb_e4], width, yerr=[r["p95_ms_sd"] for r in slb_e4], capsize=4, color=NAVY, label="Python SLB")
        axes[1].bar(cx + width / 2, [r["p95_ms_mean"] for r in hap_e4], width, yerr=[r["p95_ms_sd"] for r in hap_e4], capsize=4, color=TEAL, label="HAProxy 2.x")
        axes[1].set_xticks(cx)
        axes[1].set_xticklabels(["50 Conns", "200 Conns", "500 Conns"])
        axes[1].set_ylabel("p95 Latency (ms)")
        axes[1].set_title("E4(b): Measured p95 Latency vs Concurrency")
        axes[1].legend(loc="upper left")

        fig.tight_layout()
        fig.savefig(fig_dir / "fig_e4_concurrency_scaling.png", bbox_inches="tight")
        plt.close(fig)

    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=Path("experiments/raw_runs"))
    parser.add_argument("--out-dir", type=Path, default=Path("experiments"))
    parser.add_argument("--allow-partial", action="store_true", help="Analyze an incomplete set of trial logs")
    parser.add_argument("--no-plots", action="store_true", help="Skip generating Matplotlib figures")
    args = parser.parse_args()
    found = {p.name[:-8] for p in args.raw_dir.glob("*_hey.txt")}
    expected = expected_tags()
    if not found:
        parser.error(f"No *_hey.txt files found in {args.raw_dir}")
    if not args.allow_partial and found != expected:
        parser.error(f"Expected 60 trials; missing {len(expected - found)}, unexpected {len(found - expected)}")
    if found - expected:
        parser.error(f"Unexpected run tags: {sorted(found - expected)}")
    rows = [parse_run(args.raw_dir, tag) for tag in sorted(found)]
    write_csv(args.out_dir / "raw_60_runs.csv", rows, FIELDS)
    summary = summarize(rows)
    write_csv(args.out_dir / "summary_tables_E1_to_E4.csv", summary, list(summary[0]))
    print(f"Analyzed {len(rows)} measured trials from {args.raw_dir}")
    print(f"Wrote CSV tables to {args.out_dir}")
    if not args.no_plots:
        fig_dir = args.out_dir / "figures"
        if generate_measured_plots(summary, fig_dir):
            print(f"Generated measured E1-E4 figures in {fig_dir}")
        else:
            print("Skipped figure generation (matplotlib/numpy not installed)")


if __name__ == "__main__":
    main()
