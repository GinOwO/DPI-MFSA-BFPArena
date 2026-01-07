#!/bin/bash
set -euo pipefail

# Full ZDPI benchmark: XDP validation + TRex performance test.
# Uses veth pairs + network namespace no real NICs touched. Safe to run.
#
# Usage: sudo ./scripts/run_full_bench.sh [rules_file] [duration] [rate_pps]

if [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: Must run as root (sudo $0)"
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CLI="$PROJECT_DIR/build/src/control/zdpi-cli"
# Under sudo, $HOME is /root. Resolve real user's home via SUDO_USER.
if [ -n "${SUDO_USER:-}" ]; then
	REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
	REAL_HOME="$HOME"
fi
VENV_PYTHON="$PROJECT_DIR/.venv/bin/python3"
RESULTS_DIR="$PROJECT_DIR/perf_tests/results"

RULES="${1:-$PROJECT_DIR/tests/rules/snort_sample.rules}"
DURATION="${2:-10}"
RATE="${3:-100000}"

NS="zdpi_bench"
VETH_ZDPI="veth_zdpi_b"
VETH_TREX="veth_trex_b"
TREX_CFG="/tmp/trex_zdpi_bench.yaml"
TREX_PROFILE="/tmp/trex_zdpi_stl.py"
CLI_PID=""
TREX_PID=""

# ── Cleanup ─────────────────────────────────────────────
cleanup() {
	echo ""
	echo "--- Cleaning up ---"
	[ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null && \
		wait "$CLI_PID" 2>/dev/null || true
	[ -n "$TREX_PID" ] && kill "$TREX_PID" 2>/dev/null && \
		wait "$TREX_PID" 2>/dev/null || true
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$VETH_ZDPI" 2>/dev/null || true
	rm -f "$TREX_CFG" "$TREX_PROFILE" /tmp/trex_server.log
	echo "[OK] Cleanup done"
}
trap cleanup EXIT

# ── Preflight checks ────────────────────────────────────
echo "========================================="
echo "  ZDPI Full Benchmark"
echo "========================================="
echo "Rules:    $RULES"
echo "Duration: ${DURATION}s"
echo "Rate:     $RATE pps"
echo ""

if [ ! -x "$CLI" ]; then
	echo "ERROR: zdpi-cli not found. Run: cmake --build build"
	exit 1
fi

if ! command -v socat &>/dev/null; then
	echo "ERROR: socat not found. Install: sudo dnf install socat"
	exit 1
fi

mkdir -p "$RESULTS_DIR"

# ── Phase 1: Compile rules (dry run) ────────────────────
echo "===== Phase 1: Compile Rules ====="
"$CLI" -r "$RULES" -d -v 2>&1 | sed 's/^/  /'
echo ""

# ── Phase 2: XDP Validation ─────────────────────────────
echo "===== Phase 2: XDP Validation ====="

# Clean any stale state
ip netns del "$NS" 2>/dev/null || true
ip link del "$VETH_ZDPI" 2>/dev/null || true

# Create veth pair with one end in a network namespace.
# This forces traffic to traverse the veth (no loopback shortcut).
ip netns add "$NS"
ip link add "$VETH_ZDPI" type veth peer name "$VETH_TREX"
ip link set "$VETH_TREX" netns "$NS"

# Host side (where XDP attaches)
ip addr add 10.88.0.1/24 dev "$VETH_ZDPI"
ip link set "$VETH_ZDPI" up
ethtool -K "$VETH_ZDPI" gro off gso off tso off 2>/dev/null || true

# Namespace side (traffic sender)
ip netns exec "$NS" ip addr add 10.88.0.2/24 dev "$VETH_TREX"
ip netns exec "$NS" ip link set "$VETH_TREX" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ethtool -K "$VETH_TREX" gro off gso off tso off \
	2>/dev/null || true

echo "[OK] veth pair + namespace: $VETH_ZDPI (10.88.0.1) <-> $NS:$VETH_TREX (10.88.0.2)"

# Attach ZDPI XDP to the host-side veth
"$CLI" -r "$RULES" -i "$VETH_ZDPI" -v &
CLI_PID=$!
sleep 2

if ip link show "$VETH_ZDPI" 2>/dev/null | grep -q xdp; then
	echo "[OK] XDP program attached"
else
	echo "[WARN] XDP attachment not verified (may still work)"
fi

# --- Validation tests (traffic sent from inside namespace) ---
echo ""
echo "  Test 1: ICMP ping (expect PASS not TCP/UDP)"
if ip netns exec "$NS" ping -c 2 -W 1 10.88.0.1 >/dev/null 2>&1; then
	echo "  [OK] ICMP passed through XDP"
else
	echo "  [--] ICMP no reply (ARP may not resolve on veth)"
fi

echo "  Test 2: Clean HTTP (expect PASS)"
echo "GET /index.html HTTP/1.1" | \
	ip netns exec "$NS" socat -t 0.5 - UDP:10.88.0.1:80 2>/dev/null || true
sleep 0.2
echo "  [OK] Sent: 'GET /index.html HTTP/1.1'"

echo "  Test 3: Path traversal (expect DROP matches /../)"
echo "GET /../../etc/shadow" | \
	ip netns exec "$NS" socat -t 0.5 - UDP:10.88.0.1:80 2>/dev/null || true
sleep 0.2
echo "  [OK] Sent: 'GET /../../etc/shadow'"

echo "  Test 4: /etc/passwd probe (expect DROP)"
echo "GET /etc/passwd" | \
	ip netns exec "$NS" socat -t 0.5 - UDP:10.88.0.1:80 2>/dev/null || true
sleep 0.2
echo "  [OK] Sent: 'GET /etc/passwd'"

echo "  Test 5: XSS payload (expect DROP)"
echo '<script>alert(1)</script>' | \
	ip netns exec "$NS" socat -t 0.5 - UDP:10.88.0.1:80 2>/dev/null || true
sleep 0.2
echo "  [OK] Sent: '<script>alert(1)</script>'"

echo "  Test 6: SQL injection (expect DROP UNION SELECT)"
echo 'SELECT * FROM users UNION SELECT password FROM admin' | \
	ip netns exec "$NS" socat -t 0.5 - UDP:10.88.0.1:80 2>/dev/null || true
sleep 0.2
echo "  [OK] Sent: 'UNION SELECT'"

echo "  Test 7: Bulk clean (20 packets)"
for i in $(seq 1 20); do
	echo "SAFE PAYLOAD $i" | \
		ip netns exec "$NS" socat -t 0.1 - UDP:10.88.0.1:80 \
		2>/dev/null || true
done
sleep 0.5
echo "  [OK] Sent 20 clean UDP packets"

# XDP stats after validation
echo ""
echo "--- XDP Stats (after validation) ---"
kill -USR1 "$CLI_PID" 2>/dev/null || true
sleep 1

# ── Phase 3: Throughput Benchmark (tcpreplay + scapy) ──
echo ""
echo "===== Phase 3: Throughput Benchmark ====="

if ! command -v tcpreplay &>/dev/null; then
	echo "[SKIP] tcpreplay not found. Install: sudo dnf install tcpreplay"
	echo ""
	echo "========================================="
	echo "  XDP Validation Complete (bench skipped)"
	echo "========================================="
	exit 0
fi

PCAP_FILE="/tmp/zdpi_bench_traffic.pcap"

# Get MAC address of veth_trex_b inside namespace for proper L2
TREX_MAC=$(ip netns exec "$NS" cat /sys/class/net/"$VETH_TREX"/address)
ZDPI_MAC=$(cat /sys/class/net/"$VETH_ZDPI"/address)

# Build pcap: 80% clean HTTP + 20% attack mix (100 packets per round)
echo "Building traffic pcap (80% clean / 20% attack)..."
"$VENV_PYTHON" - "$PCAP_FILE" "$TREX_MAC" "$ZDPI_MAC" <<'PYEOF'
import sys
from scapy.all import Ether, IP, UDP, Raw, wrpcap

pcap_path = sys.argv[1]
src_mac = sys.argv[2]
dst_mac = sys.argv[3]

pkts = []

# 80 clean HTTP packets
for i in range(80):
    pkt = (Ether(src=src_mac, dst=dst_mac) /
           IP(src="10.88.0.2", dst="10.88.0.1") /
           UDP(sport=12345 + i, dport=80) /
           Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
    pkts.append(pkt)

# 7 path traversal
for i in range(7):
    pkt = (Ether(src=src_mac, dst=dst_mac) /
           IP(src="10.88.0.2", dst="10.88.0.1") /
           UDP(sport=13000 + i, dport=80) /
           Raw(b"GET /../../etc/shadow HTTP/1.1\r\n\r\n"))
    pkts.append(pkt)

# 7 /etc/passwd
for i in range(7):
    pkt = (Ether(src=src_mac, dst=dst_mac) /
           IP(src="10.88.0.2", dst="10.88.0.1") /
           UDP(sport=14000 + i, dport=80) /
           Raw(b"GET /etc/passwd HTTP/1.1\r\n\r\n"))
    pkts.append(pkt)

# 6 XSS
for i in range(6):
    pkt = (Ether(src=src_mac, dst=dst_mac) /
           IP(src="10.88.0.2", dst="10.88.0.1") /
           UDP(sport=15000 + i, dport=80) /
           Raw(b"<script>alert(document.cookie)</script>"))
    pkts.append(pkt)

wrpcap(pcap_path, pkts)
print(f"  [OK] Wrote {len(pkts)} packets to {pcap_path}")
avg_size = sum(len(bytes(p)) for p in pkts) / len(pkts)
print(f"  Avg pkt size: {avg_size:.0f} bytes")
PYEOF

# Move veth_trex_b back to root namespace for tcpreplay
ip netns exec "$NS" ip link set "$VETH_TREX" netns 1
ip addr add 10.88.0.2/24 dev "$VETH_TREX" 2>/dev/null || true
ip link set "$VETH_TREX" up

# Replay at target rate for specified duration
echo ""
echo "--- Traffic: ${RATE} pps x ${DURATION}s via tcpreplay ---"
echo "  Interface: $VETH_TREX -> $VETH_ZDPI (XDP)"
echo ""

REPLAY_LOG="/tmp/tcpreplay_output.txt"
tcpreplay --intf1="$VETH_TREX" \
	--pps="$RATE" \
	--duration="$DURATION" \
	--loop=0 \
	--stats=1 \
	"$PCAP_FILE" > "$REPLAY_LOG" 2>&1 &
REPLAY_PID=$!

# Wait for tcpreplay to finish
wait "$REPLAY_PID" 2>/dev/null || true
echo ""

# Parse tcpreplay output
echo "--- tcpreplay results ---"
cat "$REPLAY_LOG"
echo ""

# Compute throughput from tcpreplay output
"$VENV_PYTHON" - "$REPLAY_LOG" "$RESULTS_DIR" "$DURATION" "$RATE" <<'PYEOF'
import sys, re, os, csv
from datetime import datetime

log_path = sys.argv[1]
results_dir = sys.argv[2]
target_dur = int(sys.argv[3])
target_pps = int(sys.argv[4])

with open(log_path) as f:
    log = f.read()

# Find the LAST "Actual:" line (final summary, not per-second)
all_actual = re.findall(
    r'Actual:\s+([\d,]+)\s+packets\s+\(([\d,]+)\s+bytes\)\s+sent\s+in\s+'
    r'([\d.]+)\s+seconds',
    log)
# Find the LAST "Rated:" line
all_rated = re.findall(r'Rated:.*?([\d.]+)\s+Mbps', log)

if all_actual:
    last = all_actual[-1]
    total_tx = int(last[0].replace(',', ''))
    total_bytes = int(last[1].replace(',', ''))
    duration = float(last[2])
else:
    total_tx = 0
    total_bytes = 0
    duration = target_dur

mbps = float(all_rated[-1]) if all_rated else 0
gbps = mbps / 1000
avg_pps = total_tx / duration if duration > 0 else 0

# Attack ratio: 20% of traffic
attack_pkts = int(total_tx * 0.20)
clean_pkts = total_tx - attack_pkts

print(f"\n  ╔══════════════════════════════════════════╗")
print(f"  ║      Throughput Benchmark Summary         ║")
print(f"  ╠══════════════════════════════════════════╣")
print(f"  ║ Duration:     {duration:>10.1f} s              ║")
print(f"  ║ Total TX:     {total_tx:>10,} pkts           ║")
print(f"  ║ Clean (80%):  {clean_pkts:>10,} pkts           ║")
print(f"  ║ Attack (20%): {attack_pkts:>10,} pkts           ║")
print(f"  ║ Avg TX:       {avg_pps:>10,.0f} pps            ║")
print(f"  ║ Throughput:   {mbps:>10.1f} Mbps           ║")
print(f"  ║ Throughput:   {gbps:>10.3f} Gbps           ║")
print(f"  ╚══════════════════════════════════════════╝")

# Save CSV
ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
csv_path = os.path.join(results_dir, f"bench_{ts}.csv")
with open(csv_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["metric", "value"])
    w.writerow(["duration_sec", f"{duration:.1f}"])
    w.writerow(["target_pps", target_pps])
    w.writerow(["total_tx_pkts", total_tx])
    w.writerow(["clean_pkts_80pct", clean_pkts])
    w.writerow(["attack_pkts_20pct", attack_pkts])
    w.writerow(["avg_pps", f"{avg_pps:.0f}"])
    w.writerow(["throughput_mbps", f"{mbps:.1f}"])
    w.writerow(["throughput_gbps", f"{gbps:.3f}"])
print(f"\n  Results saved: {csv_path}")
PYEOF

rm -f "$PCAP_FILE" "$REPLAY_LOG"

echo ""

# Final ZDPI stats
echo "--- Final ZDPI BPF Stats ---"
kill -USR1 "$CLI_PID" 2>/dev/null || true
sleep 1

echo ""
echo "========================================="
echo "  Full Benchmark Complete"
echo "========================================="
