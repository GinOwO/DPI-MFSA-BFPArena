#!/bin/bash
# ZDPI run script.
# Usage: bash scripts/run.sh -r              (receiver: load rules, attach XDP)
#        bash scripts/run.sh -r --no-ac      (receiver: V2 mode, no AC pre-filter)
#        bash scripts/run.sh -s              (sender: generate pcaps, start listener)
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$REPO_DIR/build/src/control/zdpi-cli"
RULES="$REPO_DIR/tests/rules/content_sample.rules"
IFACE="ens5"

ENV_FILE="$REPO_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: .env not found copy .env.example to .env and fill in IPs/MACs"
    exit 1
fi
source "$ENV_FILE"

usage() {
    echo "Usage: bash scripts/run.sh -r [-r rules_file] [-i iface] [--no-ac]"
    echo "       bash scripts/run.sh -s"
    echo ""
    echo "  -r          Run as receiver (attach XDP to interface)"
    echo "  -s          Run as sender (generate pcaps + start listener)"
    echo "  --no-ac     Force V2 mode (no Aho-Corasick pre-filter)"
    echo "  --rules F   Path to rules file (default: content_sample.rules)"
    echo "  --iface I   Network interface (default: ens5)"
    exit 1
}

MODE=""
EXTRA_ARGS=""
while [ $# -gt 0 ]; do
    case "$1" in
        -r) MODE="recv" ;;
        -s) MODE="send" ;;
        --no-ac) EXTRA_ARGS="$EXTRA_ARGS --no-ac" ;;
        --rules) RULES="$2"; shift ;;
        --iface) IFACE="$2"; shift ;;
        *) usage ;;
    esac
    shift
done

[ -z "$MODE" ] && usage

# ── Receiver ──────────────────────────────────────────────────────────────────
if [ "$MODE" = "recv" ]; then
    if [ ! -f "$CLI" ]; then
        echo "ERROR: zdpi-cli not found run setup.sh first"
        exit 1
    fi
    echo "=== ZDPI Receiver ==="
    echo "Rules:     $RULES"
    echo "Interface: $IFACE"
    echo "Mode:      $(echo "$EXTRA_ARGS" | grep -q no-ac && echo V2 || echo V4)"
    echo ""
    echo "Check stats: sudo kill -USR1 \$(pgrep zdpi-cli)"
    echo ""
    # shellcheck disable=SC2086
    exec sudo "$CLI" -r "$RULES" -i "$IFACE" -v $EXTRA_ARGS
fi

# ── Sender ────────────────────────────────────────────────────────────────────
if [ "$MODE" = "send" ]; then
    echo "=== ZDPI Sender ==="
    echo "Receiver: $RECV_PRIVATE ($RECV_MAC)"
    echo ""

    echo "[1/2] Generating pcaps..."
    python3 "$REPO_DIR/scripts/gen_pcaps.py"

    echo ""
    echo "[2/2] Starting listener in tmux session 'listener'..."
    tmux kill-session -t listener 2>/dev/null || true
    tmux new-session -d -s listener "bash $REPO_DIR/scripts/sender_listener.sh"
    sleep 1
    tmux capture-pane -pt listener

    echo ""
    echo "Listener running. Trigger traffic from receiver:"
    echo "  echo 'SEND clean_256B 30 100000'  | ncat $SEND_PRIVATE 9999"
    echo "  echo 'SEND attack_mixed 30 50000' | ncat $SEND_PRIVATE 9999"
fi
