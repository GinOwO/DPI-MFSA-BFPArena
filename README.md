# ZDPI: Zero-Copy Deep Packet Inspection

eBPF/XDP-based DPI engine using BPF Arena for zero-copy packet inspection.
Implements a two-stage pipeline: Aho-Corasick pre-filter (Stage 1) + MFSA parallel DFA traversal (Stage 2).

## Architecture

```
Packet → XDP hook → [Stage 1: AC pre-filter] → match? → [Stage 2: MFSA DFAs] → DROP/PASS
                                                  no  →  XDP_PASS (O(1), zero MFSA cost)
```

- **V4 (default)**: AC pre-filter on `content:` keywords, then MFSA only for matched rules
- **V2 (`--no-ac`)**: All MFSA DFAs run on every packet
- **Arena**: BPF Arena for zero-copy shared memory between userspace and XDP program

## Requirements

- Linux kernel 6.10+ with `CONFIG_BPF_ARENA=y` (tested on 6.17.0-aws)
- Ubuntu 24.04 (or equivalent)
- clang 20+ (clang 18 crashes on BPF Arena relocations)
- libbpf 1.4+ (Ubuntu 24.04 ships 1.3 handled automatically by setup.sh)
- cmake 3.20+, libpcre2-dev, libgtest-dev

## AWS Instance Management

```bash
# Create instances, write .env, update SSH config
bash scripts/aws_create.sh --scp-key ~/.ssh/id_ed25519_github

# Terminate instances (reads from ~/.cache/zdpi/instances)
bash scripts/aws_kill.sh
```

`aws_create.sh` automatically:
- Launches 2 x c5n.large (Ubuntu 24.04, ap-southeast-2)
- Waits for SSH, fetches MACs
- Writes `.env` with all IPs/MACs
- Updates `~/.ssh/config` with `recv`/`send` aliases
- SCPs the GitHub key to both instances (with `--scp-key`)
- Saves instance IDs to `~/.cache/zdpi/instances` for later cleanup

## Setup (on each instance)

```bash
git clone git@github.com:GinOwO/DPI-MFSA-BFPArena.git
cd DPI-MFSA-BFPArena
# Copy .env from local machine or fill in manually:
cp .env.example .env
bash scripts/setup.sh
```

`setup.sh` installs clang 20, builds libbpf 1.5 from source, fixes pkg-config/runtime paths,
generates `vmlinux.h`, and builds ZDPI. Takes ~5-10 min on a fresh instance.

## Run

```bash
bash scripts/run.sh -r          # receiver: load rules, attach XDP
bash scripts/run.sh -r --no-ac  # receiver: V2 mode (no AC pre-filter)
bash scripts/run.sh -s          # sender: generate pcaps, start listener
```

### Instance config (.env)
IPs and MACs live in `.env` (gitignored). Copy `.env.example` to `.env` and fill in:

```bash
cp .env.example .env
# Edit: RECV_PUBLIC, RECV_PRIVATE, RECV_MAC, SEND_PUBLIC, SEND_PRIVATE, SEND_MAC
```

### Rule format
Snort-style rules with `content:` and `pcre:` fields:
```
alert tcp any any -> any 80 (content:"../"; pcre:"/\.\.\//"; sid:2001;)
alert tcp any any -> any 80 (content:"SELECT"; nocase; pcre:"/UNION\s+SELECT/"; sid:2002;)
alert tcp any any -> any any (pcre:"/;\s*(cat|ls|id|whoami)/"; sid:2004;)
```
Rules with `content:` use V4 AC+MFSA. Rules with only `pcre:` are always-run in MFSA.

## Stats

Stats print automatically every 2 seconds while zdpi-cli is running:
```
--- Packet Statistics ---
  RX    : 1500000
  PASS  : 375000
  DROP  : 1125000
  ERR   : 0
```

## Tests

```bash
cd build && ctest --output-on-failure
```

87 tests across 9 suites (control plane unit tests + XDP simulation).

## Expected Results

| Traffic | Drop Rate |
|---------|-----------|
| Clean (0% attack) | 0% |
| Mixed (20% attack) | ~15% |
| Pure attack | ~75% |

V4 overhead vs baseline at 200k pps: ~0% (AC pre-filter exits immediately for clean traffic).
V2 degrades with rule count: ~12% overhead at 500 rules, ~0% at 100 rules.

## FAQ

**`libbpf>=1.4` not found during cmake**
Ubuntu 24.04 ships libbpf 1.3. After building 1.5 from source, the `.pc` file lands in
`/usr/lib64/pkgconfig/` but cmake looks in `/usr/lib/x86_64-linux-gnu/pkgconfig/`:
```bash
sudo cp /usr/lib64/pkgconfig/libbpf.pc /usr/lib/x86_64-linux-gnu/pkgconfig/libbpf.pc
```

**`bad map relo against 'arena_hdr'` at runtime**
Runtime is loading libbpf 1.3 from `/lib/x86_64-linux-gnu/`. Fix:
```bash
sudo cp /usr/lib64/libbpf.so.1.5.0 /lib/x86_64-linux-gnu/libbpf.so.1.5.0
sudo ln -sf /lib/x86_64-linux-gnu/libbpf.so.1.5.0 /lib/x86_64-linux-gnu/libbpf.so.1
sudo ldconfig
```

**`fatal error in backend: Cannot select: addrspacecast[1->0]`**
clang 18 (default on Ubuntu 24.04) crashes on BPF Arena. Install clang 20:
```bash
wget -qO /tmp/llvm.sh https://apt.llvm.org/llvm.sh && sudo bash /tmp/llvm.sh 20
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-20 100
```

**`bpf_arena_common.h` file not found**
This header ships with the repo in `include/`. If missing: `git pull origin main`.

**XDP fails to attach BPF Arena not supported**
Requires kernel 6.10+ with `CONFIG_BPF_ARENA=y`. On AWS use Ubuntu 24.04
with kernel `6.17.0-1009-aws` or newer.

**Attack packets not being dropped**
Ensure payloads are TCP data packets (flags `PA`), not SYN SYN packets carry no payload
so XDP skips them. Also confirm zdpi-cli is running with rules matching your payload patterns.

**tcpreplay delivers fewer packets than target pps**
tcpreplay on a single thread tops out at ~200k pps on c5n.large. This is expected.
The measurement window accounts for this use the NIC rx_packets counter for accurate measurement.
