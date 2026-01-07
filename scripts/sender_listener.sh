#!/bin/bash
# Sender listener for ZDPI benchmark.
# Listens on port 9999 for commands from trigger_bench.sh on receiver.
# Command format: SEND <pcap_name> <duration_sec> <target_pps>
# Pcaps must exist at /tmp/bench_pcaps/<pcap_name>.pcap
#
# Usage: bash scripts/sender_listener.sh
# Generate pcaps first: python3 /tmp/gen_pcaps.py

PORT=9999
PCAP_DIR="/tmp/bench_pcaps"
IFACE=$(ip -o addr show | grep '172.31' | awk '{print $2}' | head -1)

echo "=== ZDPI Sender Listener ==="
echo "Interface: $IFACE"
echo "Pcap dir: $PCAP_DIR"
echo "Listening on port $PORT..."
echo ""

while true; do
    CMD=$(ncat -l -p $PORT 2>/dev/null) || true
    [ -z "$CMD" ] && continue

    echo "[$(date '+%H:%M:%S')] Received: $CMD"

    PCAP_NAME=$(echo "$CMD" | awk '{print $2}')
    DUR=$(echo "$CMD"  | awk '{print $3}')
    PPS=$(echo "$CMD"  | awk '{print $4}')
    PCAP="$PCAP_DIR/${PCAP_NAME}.pcap"

    # Validate
    if [ -z "$PCAP_NAME" ] || [ -z "$DUR" ] || [ -z "$PPS" ] \
        || ! [[ "$DUR" =~ ^[0-9]+$ ]] || ! [[ "$PPS" =~ ^[0-9]+$ ]] \
        || [ "$PPS" -eq 0 ]; then
        echo "  Bad command, skipping"
        continue
    fi

    if [ ! -f "$PCAP" ]; then
        echo "  Pcap not found: $PCAP skipping"
        continue
    fi

    echo "  tcpreplay $PCAP at ${PPS} pps for ${DUR}s on $IFACE"

    sudo tcpreplay \
        -i "$IFACE" \
        --pps="$PPS" \
        --duration="$DUR" \
        --loop=0 \
        "$PCAP" \
        > /dev/null 2>&1

    echo "  Done."
done
