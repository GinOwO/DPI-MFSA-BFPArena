#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"

cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" \
	-DCMAKE_BUILD_TYPE=Release \
	-DBUILD_BENCHMARKS=ON \
	-G Ninja
ninja -C "$BUILD_DIR" bench_single_dfa bench_multi_dfa bench_mfsa

echo "Benchmark executables built."
