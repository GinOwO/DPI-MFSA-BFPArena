#!/usr/bin/env python3
"""Generate benchmark pcap files for ZDPI sender.
Run on the traffic generator (send) instance after setup.
Pcaps are written to /tmp/bench_pcaps/ and used by sender_listener.sh.

IPs and MACs are read from .env in the repo root.
Copy .env.example to .env and fill in values before running.
"""
from scapy.all import Ether, IP, TCP, Raw, wrpcap
import random, os

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(REPO_DIR, ".env")

def load_env(path):
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    return env

if not os.path.exists(ENV_FILE):
    print(f"ERROR: {ENV_FILE} not found.")
    print(f"Copy .env.example to .env and fill in your instance IPs/MACs.")
    raise SystemExit(1)

env = load_env(ENV_FILE)
SRC_IP     = env["SEND_PRIVATE"]
SRC_MAC    = env["SEND_MAC"]
TARGET_IP  = env["RECV_PRIVATE"]
TARGET_MAC = env["RECV_MAC"]

OUTDIR = "/tmp/bench_pcaps"
os.makedirs(OUTDIR, exist_ok=True)

CLEAN = [
    b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
    b"POST /api/data HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    b"GET /style.css HTTP/1.1\r\nHost: example.com\r\n\r\n",
]
ATTACK = [
    b"../etc/passwd\r\n",
    b"UNION SELECT * FROM users--\r\n",
    b"<script>alert(1)</script>\r\n",
    b"; cat /etc/shadow\r\n",
]

def make_pcap(name, count, pkt_size, attack_ratio=0.0):
    pkts = []
    for i in range(count):
        src = ATTACK if random.random() < attack_ratio else CLEAN
        pay = random.choice(src)
        pay = (pay * (pkt_size // len(pay) + 1))[:pkt_size]
        pkt = (Ether(src=SRC_MAC, dst=TARGET_MAC) /
               IP(src=SRC_IP, dst=TARGET_IP) /
               TCP(dport=80, sport=1024 + i % 60000, flags="PA") /
               Raw(load=pay))
        pkts.append(pkt)
    wrpcap(f"{OUTDIR}/{name}.pcap", pkts)
    print(f"  {name}.pcap: {count} pkts")

print(f"Sender: {SRC_IP} ({SRC_MAC})")
print(f"Target: {TARGET_IP} ({TARGET_MAC})")
print("Generating pcaps...")

for sz in [64, 256, 512, 1024, 1500]:
    make_pcap(f"clean_{sz}B", 100000, max(1, sz - 54), 0.0)

make_pcap("mixed_80_20",  100000, 202, 0.2)
make_pcap("attack_mixed", 100000, 202, 1.0)

print("Done!")
