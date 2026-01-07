#!/usr/bin/env python3
"""
ZDPI Benchmark Result Plotter

Reads a CSV results file and generates plots for:
- Compile time distribution (single/multi DFA)
- Compile time scaling (stress test)
- Traverse throughput by payload type
- PCAP traffic throughput and latency
- State/EC count vs rule count
- Fuzz test summary
"""

import argparse
import os
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def plot_compile_times(df, output_dir):
    """Box plot of compile times for single and multi DFA."""
    single = df[(df["test"] == "single_dfa") &
                (df["description"] == "compile")]
    multi = df[(df["test"] == "multi_dfa") &
               (df["description"].str.contains("compile"))]

    if single.empty and multi.empty:
        return

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    if not single.empty:
        axes[0].hist(single["value"].astype(float), bins=50,
                     color="steelblue", edgecolor="black")
        mean = single["value"].astype(float).mean()
        axes[0].axvline(mean, color="red", linestyle="--",
                        label=f"mean={mean:.2f}ms")
        axes[0].set_xlabel("Time (ms)")
        axes[0].set_ylabel("Count")
        axes[0].set_title("Single-Rule DFA Compile Time")
        axes[0].legend()

    if not multi.empty:
        variants = sorted(multi["variant"].unique())
        data = [multi[multi["variant"] == v]["value"].astype(float).values
                for v in variants]
        axes[1].boxplot(data, labels=variants)
        axes[1].set_ylabel("Time (ms)")
        axes[1].set_title("Multi-Rule DFA Compile Time")
        axes[1].grid(True, alpha=0.3)

    fig.tight_layout()
    fig.savefig(os.path.join(output_dir, "compile_times.png"), dpi=150)
    plt.close(fig)
    print("  compile_times.png")


def plot_stress_scaling(df, output_dir):
    """Compile time and state count vs number of rules."""
    stress_compile = df[df["test"] == "stress_compile"]
    if stress_compile.empty:
        return

    fig, axes = plt.subplots(1, 3, figsize=(18, 5))

    # Compile time vs rules
    compile_data = stress_compile[
        stress_compile["description"].str.startswith("compile_")]
    if not compile_data.empty:
        variants = sorted(compile_data["variant"].unique(),
                          key=lambda v: int(v.replace("n", "")))
        means = []
        ns = []
        for v in variants:
            vdf = compile_data[compile_data["variant"] == v]
            means.append(vdf["value"].astype(float).mean())
            ns.append(int(v.replace("n", "")))
        axes[0].plot(ns, means, "o-", color="steelblue", linewidth=2)
        axes[0].set_xlabel("Number of Rules")
        axes[0].set_ylabel("Compile Time (ms)")
        axes[0].set_title("Compile Time vs Rule Count")
        axes[0].grid(True, alpha=0.3)

    # States vs rules
    states_data = stress_compile[
        stress_compile["description"].str.startswith("states_")]
    if not states_data.empty:
        variants = sorted(states_data["variant"].unique(),
                          key=lambda v: int(v.replace("n", "")))
        means = []
        ns = []
        for v in variants:
            vdf = states_data[states_data["variant"] == v]
            means.append(vdf["value"].astype(float).mean())
            ns.append(int(v.replace("n", "")))
        axes[1].plot(ns, means, "s-", color="green", linewidth=2)
        axes[1].set_xlabel("Number of Rules")
        axes[1].set_ylabel("DFA States")
        axes[1].set_title("DFA States vs Rule Count")
        axes[1].grid(True, alpha=0.3)

    # ECs vs rules
    ec_data = stress_compile[
        stress_compile["description"].str.startswith("ec_")]
    if not ec_data.empty:
        variants = sorted(ec_data["variant"].unique(),
                          key=lambda v: int(v.replace("n", "")))
        means = []
        ns = []
        for v in variants:
            vdf = ec_data[ec_data["variant"] == v]
            means.append(vdf["value"].astype(float).mean())
            ns.append(int(v.replace("n", "")))
        axes[2].plot(ns, means, "^-", color="orange", linewidth=2)
        axes[2].set_xlabel("Number of Rules")
        axes[2].set_ylabel("Equivalence Classes")
        axes[2].set_title("EC Count vs Rule Count")
        axes[2].grid(True, alpha=0.3)

    fig.tight_layout()
    fig.savefig(os.path.join(output_dir, "stress_scaling.png"), dpi=150)
    plt.close(fig)
    print("  stress_scaling.png")


def plot_pcap_throughput(df, output_dir):
    """Bar chart of PCAP traffic throughput and latency."""
    throughput = df[df["test"] == "pcap_throughput"]
    latency = df[df["test"] == "pcap_latency"]

    if throughput.empty:
        return

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))

    # Throughput
    variants = sorted(throughput["variant"].unique())
    means = []
    labels = []
    for v in variants:
        vdf = throughput[throughput["variant"] == v]
        means.append(vdf["value"].astype(float).mean())
        labels.append(v.replace("_MBps", ""))
    colors = plt.cm.Set2(np.linspace(0, 1, len(labels)))
    bars = axes[0].barh(range(len(labels)), means, color=colors)
    axes[0].set_yticks(range(len(labels)))
    axes[0].set_yticklabels(labels, fontsize=8)
    axes[0].set_xlabel("Throughput (MB/s)")
    axes[0].set_title("DFA Traversal Throughput by Traffic Type")
    axes[0].grid(True, alpha=0.3, axis="x")
    for bar, m in zip(bars, means):
        axes[0].text(bar.get_width() + 5, bar.get_y() + bar.get_height()/2,
                     f"{m:.0f}", va="center", fontsize=8)

    # Latency
    if not latency.empty:
        variants = sorted(latency["variant"].unique())
        means = []
        labels = []
        for v in variants:
            vdf = latency[latency["variant"] == v]
            means.append(vdf["value"].astype(float).mean())
            labels.append(v.replace("_ns_per_pkt", ""))
        bars = axes[1].barh(range(len(labels)), means, color=colors)
        axes[1].set_yticks(range(len(labels)))
        axes[1].set_yticklabels(labels, fontsize=8)
        axes[1].set_xlabel("Latency (ns/pkt)")
        axes[1].set_title("Per-Packet Latency by Traffic Type")
        axes[1].grid(True, alpha=0.3, axis="x")
        for bar, m in zip(bars, means):
            axes[1].text(bar.get_width() + 5,
                         bar.get_y() + bar.get_height()/2,
                         f"{m:.0f}", va="center", fontsize=8)

    fig.tight_layout()
    fig.savefig(os.path.join(output_dir, "pcap_throughput.png"), dpi=150)
    plt.close(fig)
    print("  pcap_throughput.png")


def plot_pcap_detection(df, output_dir):
    """Bar chart of detection rates for different traffic types."""
    drop_rate = df[df["test"] == "pcap_drop_rate"]
    if drop_rate.empty:
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    variants = sorted(drop_rate["variant"].unique())
    rates = []
    labels = []
    for v in variants:
        vdf = drop_rate[drop_rate["variant"] == v]
        rates.append(vdf["value"].astype(float).values[0])
        labels.append(v.replace("_drop_pct", ""))

    colors = ["#d32f2f" if r > 0 else "#4caf50" for r in rates]
    bars = ax.barh(range(len(labels)), rates, color=colors)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlabel("Drop Rate (%)")
    ax.set_title("Detection Rate by Traffic Type (10 rules)")
    ax.set_xlim(0, 100)
    ax.grid(True, alpha=0.3, axis="x")
    for bar, r in zip(bars, rates):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                f"{r:.1f}%", va="center", fontsize=9)

    fig.tight_layout()
    fig.savefig(os.path.join(output_dir, "pcap_detection.png"), dpi=150)
    plt.close(fig)
    print("  pcap_detection.png")


def plot_pcap_pps(df, output_dir):
    """Packets per second by traffic type."""
    pps = df[df["test"] == "pcap_pps"]
    if pps.empty:
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    variants = sorted(pps["variant"].unique())
    means = []
    labels = []
    for v in variants:
        vdf = pps[pps["variant"] == v]
        means.append(vdf["value"].astype(float).mean() / 1e6)
        labels.append(v.replace("_pkts_per_sec", ""))

    colors = plt.cm.viridis(np.linspace(0.2, 0.8, len(labels)))
    bars = ax.barh(range(len(labels)), means, color=colors)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlabel("Mpps (million packets/sec)")
    ax.set_title("Packet Processing Rate by Traffic Type")
    ax.grid(True, alpha=0.3, axis="x")
    for bar, m in zip(bars, means):
        ax.text(bar.get_width() + 0.1,
                bar.get_y() + bar.get_height()/2,
                f"{m:.1f}M", va="center", fontsize=9)

    fig.tight_layout()
    fig.savefig(os.path.join(output_dir, "pcap_pps.png"), dpi=150)
    plt.close(fig)
    print("  pcap_pps.png")


def main():
    parser = argparse.ArgumentParser(
        description="Plot ZDPI benchmark results")
    parser.add_argument("csv_file", help="Path to results CSV")
    parser.add_argument("-o", "--output", default="perf_tests/results",
                        help="Output directory for plots")
    args = parser.parse_args()

    df = pd.read_csv(args.csv_file)
    os.makedirs(args.output, exist_ok=True)

    print("Generating plots...")
    plot_compile_times(df, args.output)
    plot_stress_scaling(df, args.output)
    plot_pcap_throughput(df, args.output)
    plot_pcap_detection(df, args.output)
    plot_pcap_pps(df, args.output)
    print("Done.")


if __name__ == "__main__":
    main()
