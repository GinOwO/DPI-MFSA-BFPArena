#!/bin/bash
# Comprehensive V2 vs V4 benchmark on AWS ENA.
# Usage: ./scripts/trigger_bench.sh
#
# Rule counts: 70, 100, 200, 300, 500, 750, 1000
# PPS rates: 200k, 500k
# Runs: 1 warmup + 3 measured per config
# Packet size: 256B

ENV_FILE="$(dirname "$0")/../.env"
if [ ! -f "$ENV_FILE" ]; then echo "ERROR: .env not found copy .env.example to .env"; exit 1; fi
# shellcheck source=../.env
source "$ENV_FILE"

RECEIVER="$RECV_PUBLIC"
SSH_KEY="$HOME/.ssh/zdpi-key.pem"
SSH="ssh -A -i $SSH_KEY -o StrictHostKeyChecking=no ubuntu@$RECEIVER"

set -e

export SSH_AUTH_SOCK=$(ls /tmp/ssh-*/agent.* 2>/dev/null | head -1)

echo "=== Pushing latest code ==="
git push origin main 2>&1 | tail -2

echo ""
echo "=== Running comprehensive benchmark on $RECEIVER ==="
$SSH 'bash -s' << 'REMOTE'
set -e
REPO=~/DPI-MFSA-BFPArena
SENDER="172.31.26.142"
IFACE=$(ip -o addr show | grep '172.31' | grep -v '127\.' | head -1 | awk '{print $2}')
CLI=$REPO/build/src/control/zdpi-cli
SZ=256
PPS_RATES="200000 500000"
RUNS=3
WARMUP_DUR=10
MEASURE_DUR=30
RESULTS=/tmp/ena_final_results.csv

echo "Interface: $IFACE"
echo "Warmup: ${WARMUP_DUR}s, Measure: ${MEASURE_DUR}s x ${RUNS} runs"

# Pull and rebuild
cd $REPO
git pull origin main 2>&1 | tail -2
cmake -B build -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -3
cmake --build build -j$(nproc) 2>&1 | tail -3
echo ""

echo "rules,dfas,mode,target_pps,run,duration_sec,rx_packets,bpf_rx,bpf_pass,bpf_drop,bpf_err,actual_pps,mbps" > $RESULTS
get_rx() { cat /sys/class/net/$IFACE/statistics/rx_packets; }
trigger() { echo "SEND $1 $2 $3" | ncat -w 120 $SENDER 9999 2>/dev/null || true; }

get_bpf_stats() {
    local log=$1
    sudo kill -USR1 $CLI_PID 2>/dev/null
    sleep 1
    BRX=$(grep 'RX' "$log" | tail -1 | grep -oP ':\s*\K[0-9]+')
    BPA=$(grep 'PASS' "$log" | tail -1 | grep -oP ':\s*\K[0-9]+')
    BDR=$(grep 'DROP' "$log" | tail -1 | grep -oP ':\s*\K[0-9]+')
    BERR=$(grep 'ERR' "$log" | tail -1 | grep -oP ':\s*\K[0-9]+')
}

run_config() {
    local RULES=$1
    local MODE=$2
    local LABEL=$3
    local NRULES=$4
    local NDFAS=$5
    local LOG=/tmp/zdpi_bench_${MODE}.log

    echo ""
    echo "================================================================"
    echo "=== $LABEL ==="
    echo "================================================================"
    sudo ip link set $IFACE xdp off 2>/dev/null || true
    sleep 1

    # Safety watchdog
    nohup bash -c "sleep 3600 && sudo ip link set $IFACE xdp off" >/dev/null 2>&1 &
    WD=$!

    if [ "$MODE" = "v2" ]; then
        sudo $CLI -r $RULES --no-ac -i $IFACE -v > $LOG 2>&1 &
    elif [ "$MODE" = "v4" ]; then
        sudo $CLI -r $RULES -i $IFACE -v > $LOG 2>&1 &
    fi
    CLI_PID=$!

    # Wait for XDP attach (large rulesets take 30-60s to compile)
    if [ "$MODE" != "baseline" ]; then
        echo "  Waiting for XDP attach..."
        for attempt in $(seq 1 24); do
            sleep 5
            if ip link show $IFACE | grep -q xdp; then
                echo "  XDP attached after $((attempt * 5))s"
                break
            fi
            if ! kill -0 $CLI_PID 2>/dev/null; then
                echo "ERROR: zdpi-cli exited ($MODE)"
                kill $WD 2>/dev/null
                return 1
            fi
        done
        if ! ip link show $IFACE | grep -q xdp; then
            echo "ERROR: XDP failed to attach after 120s ($MODE)"
            sudo kill $CLI_PID 2>/dev/null; wait $CLI_PID 2>/dev/null
            kill $WD 2>/dev/null
            return 1
        fi
    fi

    for TARGET_PPS in $PPS_RATES; do
        # Warmup run
        echo "  Warmup @ ${TARGET_PPS} pps..."
        trigger "clean_${SZ}B" $WARMUP_DUR $TARGET_PPS
        sleep $((WARMUP_DUR + 2))

        # Measured runs
        for run in $(seq 1 $RUNS); do
            > $LOG 2>/dev/null
            RX1=$(get_rx)
            trigger "clean_${SZ}B" $MEASURE_DUR $TARGET_PPS
            sleep $((MEASURE_DUR + 3))
            RX2=$(get_rx)

            if [ "$MODE" != "baseline" ]; then
                get_bpf_stats $LOG
            else
                BRX=""; BPA=""; BDR=""; BERR=""
            fi

            D=$((RX2 - RX1))
            PPS=$((D / (MEASURE_DUR + 3)))
            MBPS=$(echo "$PPS * $SZ * 8 / 1000000" | bc)
            echo "  Run $run @ ${TARGET_PPS}: ${PPS} pps, ${MBPS} Mbps"
            echo "$NRULES,$NDFAS,$MODE,$TARGET_PPS,$run,$MEASURE_DUR,$D,$BRX,$BPA,$BDR,$BERR,$PPS,$MBPS" >> $RESULTS
        done
    done

    # Cleanup
    if [ "$MODE" != "baseline" ]; then
        sudo kill $CLI_PID 2>/dev/null; wait $CLI_PID 2>/dev/null
    fi
    kill $WD 2>/dev/null
    sudo ip link set $IFACE xdp off 2>/dev/null || true
    sleep 2
}

# ---- Baseline ----
echo ""
echo "================================================================"
echo "=== BASELINE (no XDP) ==="
echo "================================================================"
sudo ip link set $IFACE xdp off 2>/dev/null || true
sleep 1
for TARGET_PPS in $PPS_RATES; do
    # Warmup
    trigger "clean_${SZ}B" $WARMUP_DUR $TARGET_PPS
    sleep $((WARMUP_DUR + 2))
    for run in $(seq 1 $RUNS); do
        RX1=$(get_rx)
        trigger "clean_${SZ}B" $MEASURE_DUR $TARGET_PPS
        sleep $((MEASURE_DUR + 3))
        RX2=$(get_rx)
        D=$((RX2 - RX1)); PPS=$((D / (MEASURE_DUR + 3))); MBPS=$(echo "$PPS * $SZ * 8 / 1000000" | bc)
        echo "  Baseline run $run @ ${TARGET_PPS}: ${PPS} pps, ${MBPS} Mbps"
        echo "0,0,baseline,$TARGET_PPS,$run,$MEASURE_DUR,$D,,,,,${PPS},${MBPS}" >> $RESULTS
    done
done

# ---- Rule scale configs ----
# Format: rules_file  nrules  ndfas
CONFIGS="
stress_v4.rules:70:70
et_100.rules:100:100
et_200.rules:200:199
et_300.rules:300:295
et_500.rules:500:444
et_750.rules:750:654
et_1000.rules:1000:720
"

for config in $CONFIGS; do
    IFS=':' read -r RFILE NRULES NDFAS <<< "$config"
    RULES=$REPO/tests/rules/$RFILE

    run_config "$RULES" v2 "V2 $NRULES rules ($NDFAS DFAs)" $NRULES $NDFAS
    run_config "$RULES" v4 "V4 $NRULES rules ($NDFAS DFAs)" $NRULES $NDFAS
done

# ---- Push results ----
echo ""
echo "=== PUSHING RESULTS ==="
cd ~
git clone git@github.com:GinOwO/Capstone-2026.git capstone-parent 2>/dev/null || true
cd ~/capstone-parent
git pull origin main 2>/dev/null || true
cp $RESULTS docs/ena_final_results.csv
git add docs/ena_final_results.csv
git commit -m "Final ENA benchmark V2 vs V4, 70-1000 rules, 3 runs + warmup (automated)" 2>&1 | tail -1
git push origin main 2>&1 | tail -2

echo ""
echo "=== RAW DATA ==="
cat $RESULTS
echo ""
echo "=== DONE ==="
REMOTE

echo ""
echo "=== Pulling results locally ==="
cd /home/gin/Capstone-2026 && git stash 2>/dev/null; git pull origin main 2>&1 | tail -3; git stash pop 2>/dev/null
echo ""
echo "=== Results ==="
cat docs/ena_final_results.csv
