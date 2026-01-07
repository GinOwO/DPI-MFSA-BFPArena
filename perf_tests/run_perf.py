#!/usr/bin/env python3
"""
ZDPI Performance Test Runner

Runs all benchmark executables, collects CSV output,
and writes results to a timestamped CSV file.

Workflow:
  1. Generate traffic data via gen_traffic.py (if not present)
  2. Run each C benchmark (they output CSV to stdout)
  3. Collect all results into one CSV
  4. Print summary statistics
"""

import argparse
import csv
import datetime
import os
import subprocess
import sys
import time
import statistics

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
BUILD_DIR = os.path.join(PROJECT_DIR, "build")
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
TRAFFIC_DIR = os.path.join(SCRIPT_DIR, "traffic")

BENCHMARKS = [
    "bench_single_dfa",
    "bench_multi_dfa",
    "bench_stress",
    "bench_fuzz",
    "bench_large_scale",
    "bench_arena_stress",
    "bench_arena_throughput",
]


def ensure_traffic_data(n_packets=1000, large_scale=10000):
    """Generate traffic data if not already present."""
    marker = os.path.join(TRAFFIC_DIR, "large_scale.bin")
    if os.path.exists(marker):
        print(f"Traffic data exists at {TRAFFIC_DIR}/")
        return

    print("Generating traffic data with scapy...")
    gen_script = os.path.join(SCRIPT_DIR, "gen_traffic.py")
    result = subprocess.run(
        [sys.executable, gen_script,
         "-o", TRAFFIC_DIR,
         "-n", str(n_packets),
         "-N", str(large_scale)],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        print(f"WARNING: Traffic generation failed:\n{result.stderr}")
    else:
        print(result.stdout)


def run_benchmark(name, timeout=300):
    """Run a benchmark and collect CSV lines from stdout."""
    exe = os.path.join(BUILD_DIR, "perf_tests", name)
    if not os.path.exists(exe):
        print(f"  SKIP: {exe} not found")
        return []

    args = [exe]

    # bench_pcap needs payload files as arguments
    if name == "bench_pcap":
        if not os.path.isdir(TRAFFIC_DIR):
            print(f"  SKIP: {TRAFFIC_DIR} not found (run gen_traffic.py)")
            return []
        payload_files = sorted([
            os.path.join(TRAFFIC_DIR, f)
            for f in os.listdir(TRAFFIC_DIR)
            if f.endswith(".bin")
        ])
        if not payload_files:
            print(f"  SKIP: no .bin files in {TRAFFIC_DIR}")
            return []
        args.extend(payload_files)

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"  TIMEOUT: {name} ({timeout}s)")
        return []

    if result.returncode != 0:
        print(f"  ERROR: {name} returned {result.returncode}")
        if result.stderr:
            for line in result.stderr.strip().split("\n")[-5:]:
                print(f"    {line}")
        return []

    # Print stderr (progress info)
    if result.stderr:
        for line in result.stderr.strip().split("\n"):
            print(f"    {line}")

    # Parse CSV from stdout
    rows = []
    for line in result.stdout.strip().split("\n"):
        if line.startswith("test,") or not line.strip():
            continue
        parts = line.split(",")
        if len(parts) >= 5:
            rows.append(parts[:5])

    return rows


def percentile(data, pct):
    """Compute the pct-th percentile of a sorted list."""
    s = sorted(data)
    k = (len(s) - 1) * pct / 100.0
    f = int(k)
    c = f + 1 if f + 1 < len(s) else f
    d = k - f
    return s[f] + d * (s[c] - s[f])


def summarize_results(rows):
    """Print summary statistics from collected results."""
    # Group by (test, description)
    groups = {}
    for row in rows:
        key = (row[0], row[1])
        try:
            val = float(row[4])
        except (ValueError, IndexError):
            continue
        groups.setdefault(key, []).append(val)

    print("\n" + "=" * 90)
    print("BENCHMARK SUMMARY")
    print("=" * 90)

    current_test = None
    for (test, desc), values in sorted(groups.items()):
        if test != current_test:
            print(f"\n--- {test} ---")
            current_test = test

        n = len(values)
        mean = statistics.mean(values)
        med = statistics.median(values)
        if n > 1:
            stdev = statistics.stdev(values)
            mn = min(values)
            mx = max(values)
            p5 = percentile(values, 5)
            p95 = percentile(values, 95)
            p99 = percentile(values, 99)
            print(f"  {desc:40s}  "
                  f"mean={mean:10.2f}  "
                  f"med={med:10.2f}  "
                  f"std={stdev:8.2f}  "
                  f"min={mn:10.2f}  "
                  f"p5={p5:10.2f}  "
                  f"p95={p95:10.2f}  "
                  f"p99={p99:10.2f}  "
                  f"max={mx:10.2f}  "
                  f"(n={n})")
        else:
            print(f"  {desc:40s}  value={mean:10.2f}")


def main():
    parser = argparse.ArgumentParser(description="ZDPI benchmark runner")
    parser.add_argument(
        "-b", "--benchmarks", nargs="+", default=None,
        help="Benchmark names to run (default: all)")
    parser.add_argument(
        "--with-pcap", action="store_true",
        help="Also run bench_pcap with generated traffic")
    parser.add_argument(
        "-t", "--timeout", type=int, default=300,
        help="Timeout per benchmark in seconds")
    parser.add_argument(
        "--skip-traffic-gen", action="store_true",
        help="Skip traffic data generation")
    args = parser.parse_args()

    benchmarks = args.benchmarks or BENCHMARKS
    if args.with_pcap and "bench_pcap" not in benchmarks:
        benchmarks.append("bench_pcap")

    os.makedirs(RESULTS_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    outpath = os.path.join(RESULTS_DIR, f"perf_results_{timestamp}.csv")

    # Generate traffic if needed
    if not args.skip_traffic_gen and "bench_pcap" in benchmarks:
        ensure_traffic_data()

    all_rows = []
    total_t0 = time.perf_counter()

    for name in benchmarks:
        print(f"\nRunning {name}...")
        t0 = time.perf_counter()
        rows = run_benchmark(name, timeout=args.timeout)
        elapsed = time.perf_counter() - t0
        print(f"  {len(rows)} data points in {elapsed:.1f}s")
        all_rows.extend(rows)

    total_elapsed = time.perf_counter() - total_t0

    # Write CSV
    with open(outpath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["test", "description", "variant", "run", "value"])
        writer.writerows(all_rows)

    print(f"\nResults written to {outpath}")
    print(f"Total data points: {len(all_rows)}")
    print(f"Total wall time: {total_elapsed:.1f}s")

    # Summary
    summarize_results(all_rows)


if __name__ == "__main__":
    main()
