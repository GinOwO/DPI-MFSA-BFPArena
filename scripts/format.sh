#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"
find src/ tests/ perf_tests/ include/ \
	\( -name '*.c' -o -name '*.h' -o -name '*.cpp' \) \
	! -path 'include/vmlinux.h' \
	! -path 'include/bpf_arena_*' \
	2>/dev/null | xargs -r clang-format -i

echo "Formatted all source files."
