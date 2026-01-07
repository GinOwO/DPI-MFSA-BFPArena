#!/bin/bash
set -euo pipefail

# Gbps-level XDP benchmark using kernel pktgen.
# Compares: (1) no XDP (baseline), (2) XDP + DFA inspection.
# pktgen generates packets in-kernel no userspace bottleneck.
# Uses veth pair no real NICs touched. Requires root.
#
# Usage: sudo ./scripts/bench_gbps.sh [rules_file] [count] [pkt_size]
#   count:    total packets per scenario (default 5M)
#   pkt_size: packet size in bytes (default 256)

if [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: Must run as root (sudo $0)"
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CLI="$PROJECT_DIR/build/src/control/zdpi-cli"
RESULTS_DIR="$PROJECT_DIR/perf_tests/results"

RULES="${1:-$PROJECT_DIR/tests/rules/snort_sample.rules}"
COUNT="${2:-5000000}"
PKT_SIZE="${3:-256}"

VETH_TX="veth_pktgen_tx"
VETH_RX="veth_pktgen_rx"
CLI_PID=""

# ── Cleanup ──────────────────────────────────────────────
cleanup() {
	echo ""
	echo "--- Cleaning up ---"
	[ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null && \
		wait "$CLI_PID" 2>/dev/null || true
	echo "rem_device_all" > /proc/net/pktgen/kpktgend_0 2>/dev/null || true
	ip link del "$VETH_TX" 2>/dev/null || true
	echo "[OK] Cleanup done"
}
trap cleanup EXIT

# ── Preflight ────────────────────────────────────────────
echo "========================================="
echo "  ZDPI Gbps Benchmark (kernel pktgen)"
echo "========================================="
echo "Rules:    $RULES"
echo "Count:    $COUNT packets per scenario"
echo "Pkt size: ${PKT_SIZE} bytes"
echo ""

if [ ! -x "$CLI" ]; then
	echo "ERROR: zdpi-cli not found. Run: cmake --build build"
	exit 1
fi

modprobe pktgen 2>/dev/null || true
if [ ! -d /proc/net/pktgen ]; then
	echo "ERROR: pktgen module not available"
	exit 1
fi

mkdir -p "$RESULTS_DIR"

# ── Create veth pair ─────────────────────────────────────
ip link del "$VETH_TX" 2>/dev/null || true
ip link add "$VETH_TX" type veth peer name "$VETH_RX"
ip addr add 10.77.0.1/24 dev "$VETH_TX"
ip addr add 10.77.0.2/24 dev "$VETH_RX"
ip link set "$VETH_TX" up
ip link set "$VETH_RX" up
ethtool -K "$VETH_TX" gro off gso off tso off 2>/dev/null || true
ethtool -K "$VETH_RX" gro off gso off tso off 2>/dev/null || true

RX_MAC=$(cat /sys/class/net/"$VETH_RX"/address)
echo "[OK] veth pair: $VETH_TX -> $VETH_RX ($RX_MAC)"
echo ""

# ── Helper: run pktgen and parse results ─────────────────
run_pktgen() {
	local label="$1"

	echo "rem_device_all" > /proc/net/pktgen/kpktgend_0
	echo "add_device $VETH_TX" > /proc/net/pktgen/kpktgend_0

	local pgdev="/proc/net/pktgen/$VETH_TX"
	echo "pkt_size $PKT_SIZE"         > "$pgdev"
	echo "count $COUNT"               > "$pgdev"
	echo "delay 0"                    > "$pgdev"
	echo "dst 10.77.0.2"             > "$pgdev"
	echo "dst_mac $RX_MAC"           > "$pgdev"
	echo "src_mac 00:00:00:00:00:01" > "$pgdev"
	echo "udp_dst_min 80"            > "$pgdev"
	echo "udp_dst_max 80"            > "$pgdev"
	echo "udp_src_min 12345"         > "$pgdev"
	echo "udp_src_max 12345"         > "$pgdev"
	echo "flag UDPCSUM"              > "$pgdev"

	echo "  [$label] Sending $COUNT packets at max speed..."

	echo "start" > /proc/net/pktgen/pgctrl

	# Read full output (Result: line + pps line are separate)
	local result
	result=$(tail -5 "$pgdev")

	# Format:
	#   Result: OK: 1032174(c1032174+d0) usec, 1000000 (256byte,0frags)
	#     968828pps 1984Mb/sec (1984159744bps) errors: 0
	local pps_val mbps_val usec_val sofar_pkts

	sofar_pkts=$(cat "$pgdev" | grep -oP 'pkts-sofar:\s*\K\d+' || echo "$COUNT")
	pps_val=$(echo "$result" | grep -oP '\d+(?=pps)' || echo "0")
	mbps_val=$(echo "$result" | grep -oP '\d+(?=Mb/sec)' || echo "0")
	usec_val=$(echo "$result" | grep -oP 'OK:\s*\K\d+' || echo "0")

	local duration_sec="?"
	if [ "$usec_val" -gt 0 ] 2>/dev/null; then
		duration_sec=$(echo "scale=2; $usec_val / 1000000" | bc)
	fi

	local gbps mpps
	gbps=$(echo "scale=3; $mbps_val / 1000" | bc 2>/dev/null || echo "0")
	mpps=$(echo "scale=3; $pps_val / 1000000" | bc 2>/dev/null || echo "0")

	echo "  [$label] ${sofar_pkts} pkts in ${duration_sec}s"
	echo "  [$label] ${mpps} Mpps | ${mbps_val} Mbps | ${gbps} Gbps"
	echo ""

	LAST_PPS="$pps_val"
	LAST_MBPS="$mbps_val"
	LAST_GBPS="$gbps"
	LAST_MPPS="$mpps"
	LAST_PKTS="$sofar_pkts"
	LAST_SEC="$duration_sec"

	echo "rem_device_all" > /proc/net/pktgen/kpktgend_0
}

# ── Scenario 1: No XDP (baseline) ───────────────────────
echo "===== Scenario 1: No XDP (baseline) ====="
run_pktgen "baseline"
BASE_PPS="$LAST_PPS"
BASE_GBPS="$LAST_GBPS"
BASE_MPPS="$LAST_MPPS"
BASE_MBPS="$LAST_MBPS"
BASE_SEC="$LAST_SEC"

# ── Scenario 2: XDP + DFA (rules loaded) ────────────────
echo "===== Scenario 2: XDP + DFA inspection ====="
"$CLI" -r "$RULES" -i "$VETH_RX" -v &
CLI_PID=$!
sleep 2

if ip link show "$VETH_RX" | grep -q xdp; then
	echo "  [OK] XDP attached to $VETH_RX"
fi
echo ""

run_pktgen "xdp+dfa"
DPI_PPS="$LAST_PPS"
DPI_GBPS="$LAST_GBPS"
DPI_MPPS="$LAST_MPPS"
DPI_MBPS="$LAST_MBPS"
DPI_SEC="$LAST_SEC"

echo "--- BPF Stats ---"
kill -USR1 "$CLI_PID" 2>/dev/null || true
sleep 1

kill "$CLI_PID" 2>/dev/null && wait "$CLI_PID" 2>/dev/null || true
CLI_PID=""

# ── Results ──────────────────────────────────────────────
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║               ZDPI Gbps Benchmark Results                  ║"
echo "╠════════════════════════════════════════════════════════════╣"
printf "║  Packet size:  %-6s bytes                                 ║\n" "$PKT_SIZE"
printf "║  Packets/run:  %-12s                                   ║\n" "$COUNT"
echo "╠════════════════════════════════════════════════════════════╣"
printf "║  %-22s %7s Mpps  %6s Mbps  %5s Gbps   ║\n" \
	"Baseline (no XDP):" "$BASE_MPPS" "$BASE_MBPS" "$BASE_GBPS"
printf "║  %-22s %7s Mpps  %6s Mbps  %5s Gbps   ║\n" \
	"XDP + DPI:" "$DPI_MPPS" "$DPI_MBPS" "$DPI_GBPS"
echo "╠════════════════════════════════════════════════════════════╣"

if [ "$BASE_PPS" -gt 0 ] 2>/dev/null && [ "$DPI_PPS" -gt 0 ] 2>/dev/null; then
	OVERHEAD=$(echo "scale=1; (1 - $DPI_PPS * 1.0 / $BASE_PPS) * 100" | bc 2>/dev/null || echo "?")
	printf "║  DPI overhead:  %5s%% throughput reduction                  ║\n" "$OVERHEAD"
else
	echo "║  DPI overhead: N/A                                           ║"
fi
echo "╚════════════════════════════════════════════════════════════╝"

# ── Save CSV ─────────────────────────────────────────────
TS=$(date +"%Y-%m-%d_%H-%M-%S")
CSV="$RESULTS_DIR/gbps_bench_${TS}.csv"
cat > "$CSV" <<EOF
scenario,pkt_size,packets,duration_sec,pps,mpps,mbps,gbps
baseline,$PKT_SIZE,$COUNT,$BASE_SEC,$BASE_PPS,$BASE_MPPS,$BASE_MBPS,$BASE_GBPS
xdp_dpi,$PKT_SIZE,$COUNT,$DPI_SEC,$DPI_PPS,$DPI_MPPS,$DPI_MBPS,$DPI_GBPS
EOF
echo ""
echo "Results saved: $CSV"
