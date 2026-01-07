#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

BUILD_TYPE="${1:-Release}"
BUILD_DIR="$PROJECT_DIR/build"

mkdir -p "$BUILD_DIR"
cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" \
	-DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
	-DBUILD_TESTS=ON \
	-G Ninja
ninja -C "$BUILD_DIR" -j"$(nproc)"

echo "Build complete ($BUILD_TYPE)"
