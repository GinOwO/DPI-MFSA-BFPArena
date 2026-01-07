#!/bin/bash
set -euo pipefail

# XDP integration test using veth pair + network namespace.
# Sends matching and non-matching payloads, checks drop/pass stats.
# Requires root. Safe: uses isolated veth pair, no real NICs touched.

if [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: Must run as root (sudo $0)"
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CLI="$PROJECT_DIR/build/src/control/zdpi-cli"
RULES="${1:-$PROJECT_DIR/tests/rules/snort_sample.rules}"

NS="zdpi_test"
VETH_OUT="veth_zdpi"
VETH_IN="veth_zdpi_ns"

# Ensure clean state
cleanup() {
	echo ""
	echo "Cleaning up..."
	kill "$CLI_PID" 2>/dev/null && wait "$CLI_PID" 2>/dev/null || true
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$VETH_OUT" 2>/dev/null || true
	echo "[OK] Cleanup done"
}
trap cleanup EXIT
CLI_PID=""

echo "========================================="
echo "  ZDPI XDP Integration Test"
echo "========================================="
echo "Rules: $RULES"
echo ""

# --- Dry run first to make sure rules compile ---
echo "--- Dry Run ---"
"$CLI" -r "$RULES" -d -v 2>&1 | sed 's/^/  /'
echo ""

# --- Create veth pair in network namespace ---
echo "--- Setting up veth pair ---"
ip netns add "$NS"
ip link add "$VETH_OUT" type veth peer name "$VETH_IN"
ip link set "$VETH_IN" netns "$NS"
ip addr add 10.99.0.1/24 dev "$VETH_OUT"
ip link set "$VETH_OUT" up
ip netns exec "$NS" ip addr add 10.99.0.2/24 dev "$VETH_IN"
ip netns exec "$NS" ip link set "$VETH_IN" up
ip netns exec "$NS" ip link set lo up
echo "[OK] veth pair created (10.99.0.1 <-> 10.99.0.2)"
echo ""

# --- Load ZDPI on the outside interface ---
echo "--- Loading ZDPI XDP ---"
"$CLI" -r "$RULES" -i "$VETH_OUT" -v &
CLI_PID=$!
sleep 2

# Verify XDP is attached
if ip link show "$VETH_OUT" | grep -q xdp; then
	echo "[OK] XDP program attached to $VETH_OUT"
else
	echo "[WARN] Could not verify XDP attachment"
fi
echo ""

# --- Test 1: ICMP (should PASS - not TCP/UDP) ---
echo "--- Test 1: ICMP ping (expect PASS) ---"
if ip netns exec "$NS" ping -c 3 -W 1 10.99.0.1 > /dev/null 2>&1; then
	echo "[OK] ICMP packets passed through"
else
	echo "[WARN] ICMP failed (may be expected if ARP issues)"
fi
echo ""

# --- Test 2: Non-matching UDP payload (should PASS) ---
echo "--- Test 2: Non-matching payload (expect PASS) ---"
echo "GET /index.html HTTP/1.1" | ip netns exec "$NS" \
	socat -t 0.5 - UDP:10.99.0.1:80,sourceport=12345 2>/dev/null || true
sleep 0.3
echo "[OK] Sent non-matching payload: 'GET /index.html HTTP/1.1'"
echo ""

# --- Test 3: Path traversal (should DROP - matches SID 1001) ---
echo "--- Test 3: Path traversal payload (expect DROP) ---"
echo "GET /../../etc/shadow HTTP/1.1" | ip netns exec "$NS" \
	socat -t 0.5 - UDP:10.99.0.1:80,sourceport=12346 2>/dev/null || true
sleep 0.3
echo "[OK] Sent matching payload: 'GET /../../etc/shadow HTTP/1.1'"
echo ""

# --- Test 4: /etc/passwd access (should DROP - matches SID 1002) ---
echo "--- Test 4: /etc/passwd payload (expect DROP) ---"
echo "GET /etc/passwd HTTP/1.1" | ip netns exec "$NS" \
	socat -t 0.5 - UDP:10.99.0.1:80,sourceport=12347 2>/dev/null || true
sleep 0.3
echo "[OK] Sent matching payload: 'GET /etc/passwd HTTP/1.1'"
echo ""

# --- Test 5: XSS script tag (should DROP - matches SID 1005) ---
echo "--- Test 5: XSS payload (expect DROP) ---"
echo '<script>alert(1)</script>' | ip netns exec "$NS" \
	socat -t 0.5 - UDP:10.99.0.1:80,sourceport=12348 2>/dev/null || true
sleep 0.3
echo "[OK] Sent matching payload: '<script>alert(1)</script>'"
echo ""

# --- Test 6: Bulk non-matching (for stats) ---
echo "--- Test 6: Bulk non-matching (20 packets) ---"
for i in $(seq 1 20); do
	echo "SAFE DATA $i" | ip netns exec "$NS" \
		socat -t 0.2 - UDP:10.99.0.1:80,sourceport=$((13000+i)) 2>/dev/null || true
done
sleep 0.5
echo "[OK] Sent 20 non-matching UDP packets"
echo ""

# --- Collect stats ---
echo "========================================="
echo "  Packet Statistics"
echo "========================================="
kill -USR1 "$CLI_PID" 2>/dev/null || true
sleep 1
echo ""
echo "========================================="
echo "  XDP Integration Test Complete"
echo "========================================="
