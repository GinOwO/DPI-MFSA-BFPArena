#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== ZDPI Bootstrap ==="

# Check kernel version >= 6.10
KVER=$(uname -r | cut -d. -f1-2)
KMAJ=$(echo "$KVER" | cut -d. -f1)
KMIN=$(echo "$KVER" | cut -d. -f2)
if [ "$KMAJ" -lt 6 ] || { [ "$KMAJ" -eq 6 ] && [ "$KMIN" -lt 10 ]; }; then
	echo "ERROR: Kernel >= 6.10 required (have $(uname -r))"
	exit 1
fi
echo "[OK] Kernel $(uname -r)"

# Check required tools
for cmd in clang cmake ninja-build pkg-config python3; do
	bin="$cmd"
	[ "$cmd" = "ninja-build" ] && bin="ninja"
	if ! command -v "$bin" &>/dev/null; then
		echo "ERROR: $bin not found"
		exit 1
	fi
done
echo "[OK] Build tools"

# Check required libraries
for lib in libbpf libpcre2-8; do
	if ! pkg-config --exists "$lib"; then
		echo "ERROR: $lib not found (install dev package)"
		exit 1
	fi
done
echo "[OK] Libraries (libbpf, libpcre2)"

# Check GTest
if ! pkg-config --exists gtest 2>/dev/null; then
	if [ ! -f /usr/include/gtest/gtest.h ]; then
		echo "ERROR: gtest-devel not found"
		exit 1
	fi
fi
echo "[OK] GTest"

# Build bpftool if not in PATH
if ! command -v bpftool &>/dev/null; then
	echo "Building bpftool from libbpf/bpftool..."
	BPFTOOL_DIR="/tmp/bpftool-build"
	if [ ! -d "$BPFTOOL_DIR" ]; then
		git clone --depth 1 https://github.com/libbpf/bpftool.git "$BPFTOOL_DIR"
		cd "$BPFTOOL_DIR"
		git submodule update --init --depth 1
	fi
	cd "$BPFTOOL_DIR"
	make -C src -j"$(nproc)" BUILD_BPF_SKELS= 2>/dev/null || true
	if [ -f "$BPFTOOL_DIR/src/bootstrap/bpftool" ]; then
		mkdir -p "$HOME/.local/bin"
		cp "$BPFTOOL_DIR/src/bootstrap/bpftool" "$HOME/.local/bin/bpftool"
		export PATH="$HOME/.local/bin:$PATH"
		echo "[OK] bpftool installed to ~/.local/bin/"
	elif [ -f "$BPFTOOL_DIR/src/bpftool" ]; then
		mkdir -p "$HOME/.local/bin"
		cp "$BPFTOOL_DIR/src/bpftool" "$HOME/.local/bin/bpftool"
		export PATH="$HOME/.local/bin:$PATH"
		echo "[OK] bpftool installed to ~/.local/bin/"
	else
		echo "ERROR: bpftool build failed"
		exit 1
	fi
	cd "$PROJECT_DIR"
else
	echo "[OK] bpftool $(bpftool version | head -1)"
fi

# Generate vmlinux.h
VMLINUX="$PROJECT_DIR/include/vmlinux.h"
if [ ! -f "$VMLINUX" ]; then
	echo "Generating vmlinux.h..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX"
	echo "[OK] vmlinux.h generated"
else
	echo "[OK] vmlinux.h exists"
fi

# Download arena headers from kernel selftests
ARENA_COMMON="$PROJECT_DIR/include/bpf_arena_common.h"
BASE_URL="https://raw.githubusercontent.com/torvalds/linux/master/tools/testing/selftests/bpf"

if [ ! -f "$ARENA_COMMON" ]; then
	echo "Downloading bpf_arena_common.h..."
	curl -sf -o "$ARENA_COMMON" "$BASE_URL/bpf_arena_common.h"
	echo "[OK] bpf_arena_common.h"
else
	echo "[OK] bpf_arena_common.h exists"
fi

# Verify BPF arena support
if bpftool feature probe 2>/dev/null | grep -q arena; then
	echo "[OK] BPF Arena supported"
else
	echo "[WARN] BPF Arena support not detected (may still work)"
fi

echo ""
echo "=== Bootstrap complete ==="
echo "Run: scripts/build.sh [Debug|Release]"
