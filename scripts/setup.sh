#!/bin/bash
# ZDPI dependency installer and build script for Ubuntu 24.04 (AWS c5n.large / ENA).
# Run as a normal user with sudo access.
# Usage: bash scripts/setup.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== ZDPI Setup ==="
echo "Repo: $REPO_DIR"
echo ""

# ── 1. System packages ────────────────────────────────────────────────────────
echo "[1/5] Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y \
    cmake gcc make libelf-dev zlib1g-dev \
    libpcre2-dev libgtest-dev pkgconf bc \
    ncat git python3-scapy hping3 tcpreplay \
    wget lsb-release software-properties-common gnupg
echo "  [OK] system packages"

# ── 2. Clang 20 ───────────────────────────────────────────────────────────────
echo "[2/5] Installing clang 20..."
if ! command -v clang-20 &>/dev/null; then
    wget -qO /tmp/llvm.sh https://apt.llvm.org/llvm.sh
    sudo bash /tmp/llvm.sh 20
fi
sudo update-alternatives --install /usr/bin/clang   clang   /usr/bin/clang-20   100
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-20 100
echo "  [OK] $(clang --version | head -1)"

# ── 3. libbpf 1.5 from source ─────────────────────────────────────────────────
echo "[3/5] Building libbpf 1.5.0..."
if ! pkg-config --exists libbpf 2>/dev/null || \
   [ "$(pkg-config --modversion libbpf 2>/dev/null)" \< "1.4" ]; then

    if [ ! -d /tmp/libbpf ]; then
        git clone --depth 1 -b v1.5.0 \
            git@github.com:libbpf/libbpf.git /tmp/libbpf
    fi
    cd /tmp/libbpf/src
    make -j"$(nproc)"
    sudo make install
    cd "$REPO_DIR"

    # Fix pkg-config path (installs to /usr/lib64 on Ubuntu)
    if [ -f /usr/lib64/pkgconfig/libbpf.pc ]; then
        sudo cp /usr/lib64/pkgconfig/libbpf.pc \
            /usr/lib/x86_64-linux-gnu/pkgconfig/libbpf.pc
    fi

    # Fix runtime .so path (Ubuntu looks in /lib/x86_64-linux-gnu)
    LIBBPF_SO=$(find /usr/lib64 /usr/local/lib -name 'libbpf.so.1.5.0' 2>/dev/null | head -1)
    if [ -n "$LIBBPF_SO" ]; then
        sudo cp "$LIBBPF_SO" /lib/x86_64-linux-gnu/libbpf.so.1.5.0
        sudo ln -sf /lib/x86_64-linux-gnu/libbpf.so.1.5.0 \
                    /lib/x86_64-linux-gnu/libbpf.so.1
    fi
    sudo ldconfig
fi
echo "  [OK] libbpf $(pkg-config --modversion libbpf)"

# ── 4. vmlinux.h ──────────────────────────────────────────────────────────────
echo "[4/5] Generating vmlinux.h..."
VMLINUX="$REPO_DIR/include/vmlinux.h"
if [ ! -f "$VMLINUX" ]; then
    mkdir -p "$REPO_DIR/include"
    BPFTOOL=$(command -v bpftool || true)
    if [ -z "$BPFTOOL" ]; then
        echo "  bpftool not found building from source..."
        git clone --depth 1 git@github.com:libbpf/bpftool.git /tmp/bpftool-src
        cd /tmp/bpftool-src && git submodule update --init --depth 1
        make -C src -j"$(nproc)" BUILD_BPF_SKELS= 2>/dev/null || true
        BPFTOOL=/tmp/bpftool-src/src/bootstrap/bpftool
        [ -f "$BPFTOOL" ] || BPFTOOL=/tmp/bpftool-src/src/bpftool
        cd "$REPO_DIR"
    fi
    sudo "$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX"
fi
echo "  [OK] vmlinux.h"

# ── 5. Build ZDPI ─────────────────────────────────────────────────────────────
echo "[5/5] Building ZDPI..."
cd "$REPO_DIR"
cmake -B build -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -3
cmake --build build -j"$(nproc)" 2>&1 | tail -5
echo "  [OK] build complete"

echo ""
echo "=== Setup complete ==="
echo "Run: bash scripts/run.sh -r   (receiver)"
echo "     bash scripts/run.sh -s   (sender)"
