# ZDPI Architecture

## Overview

ZDPI (Zero-Copy Deep Packet Inspection) performs network payload
pattern matching directly inside the Linux kernel using eBPF/XDP
and BPF Arena shared memory. Snort-style rules are compiled into a
flat DFA transition table in userspace, written into a BPF Arena,
and traversed at wire speed by an XDP program.

## Components

### Control Plane (zdpi-cli)

Userspace application that compiles Snort rules into a flat DFA
transition table. Two compilation modes are supported:

**Union mode** (`-u`): NFA union of all rules, then subset
construction into a single DFA + Hopcroft minimization.

**MFSA mode** (default): Each rule compiled to an individual
minimized DFA, then merged via product-state construction
(Cicolini et al. 2024). Avoids the exponential blowup of NFA
union subset construction.

Pipeline stages:

1. **Rule Parser** (`rule_parser.c`) Parses Snort rule files,
   extracts PCRE patterns, SIDs, and metadata
2. **Regex Parser** (`regex_parser.c`) Converts PCRE-subset
   patterns to postfix token streams via shunting-yard algorithm
3. **NFA Builder** (`nfa.c`) Thompson's construction from
   postfix tokens. Supports union of multiple NFAs.
4. **DFA Builder** (`dfa.c`) Subset construction + Hopcroft
   minimization. State 0 = dead, state 1 = start.
5. **MFSA Merger** (`mfsa.c`) Product-state merge of individual
   DFAs. Only used in MFSA mode.
6. **Unanchoring** (`main.c`) Two-step dead-transition redirect
   so patterns match anywhere in payload, not just at offset 0.
   See `docs/bugs-and-findings.md` for details.
7. **EC Compressor** (`ec_compress.c`) Equivalence class
   computation to reduce table width from 256 to typically 10-30
8. **Linearizer** (`linearize.c`) Packs DFA + EC map + accept
   bitset into flat binary blob matching the arena layout
9. **Arena Flash** (`arena_flash.c`) Opens BPF skeleton, gets
   arena mmap pointer via `bpf_map__initial_value()`, memcpy the
   blob, and attaches XDP to the target interface

### Data Plane (zdpi_kern.bpf.c)

eBPF programs running in the kernel:

- **SEC("syscall") zdpi_alloc** No-op; arena pages are
  demand-paged when userspace writes via memcpy
- **SEC("xdp") zdpi_inspect** Parses ETH/IPv4/TCP/UDP headers,
  traverses the DFA transition table in the arena, drops packets
  that reach an accept state

The XDP program's arena association is established via a global
variable stored in the `.addr_space.1` ELF section:
```c
struct zdpi_arena_hdr __arena arena_hdr;
```

### Data Flow

```
Snort Rules
    |
    v
Rule Parser --> Regex Parser --> NFA Builder
                                     |
                              [union mode]    [MFSA mode]
                                     |              |
                                     v              v
                              NFA Union      Individual DFAs
                                     |              |
                                     v              v
                              Subset Constr.  Product Merge
                                     |              |
                                     +------+-------+
                                            |
                                            v
                                     DFA (minimized)
                                            |
                                            v
                                     Unanchoring
                                            |
                                            v
                                     EC Compression
                                            |
                                            v
                                     Linearize (flat blob)
                                            |
                                            v
                                     Arena Flash (memcpy)
                                            |
                                            v
                              XDP: packet --> DFA lookup --> DROP/PASS
```

## XDP Packet Processing

```
1. Parse Ethernet header (skip VLAN 0x8100 if present)
2. Check IPv4 (0x0800) pass non-IPv4
3. Parse IPv4 header, extract L4 protocol
4. Parse TCP/UDP header, extract payload pointer + length
5. Skip empty payloads
6. Read arena header, validate magic + table_ready
7. For each payload byte (up to ZDPI_MAX_PAYLOAD = 1500):
   a. Look up equivalence class: ec = ec_map[byte]
   b. Transition: state = table[state * num_ec + ec]
   c. If dead state: break (no match possible)
   d. If accept state: XDP_DROP immediately
8. If loop completes without accept: XDP_PASS
```

## Key Design Decisions

- **MFSA as product-state DFA**: All MFSA complexity is in the
  control plane. The XDP program does a simple
  `table[state * stride + ec]` lookup no MFSA-awareness needed.
- **BPF Arena (not BPF maps)**: Provides up to 16 MB of shared
  memory (4096 pages x 4 KB) between userspace and kernel via a
  single mmap. Avoids per-transition `bpf_map_lookup_elem()` calls.
- **Equivalence classes**: Reduce table width from 256 to typically
  10-30 columns. For 6 Snort rules: 52 states x 30 ECs = 6,240
  entries (24 KB), vs 52 x 256 = 13,312 entries (52 KB) without EC.
- **In-loop accept check**: Accept states are checked after every
  transition, not just at loop end. Patterns matching mid-payload
  are detected immediately.
- **Two-step unanchoring**: Dead transitions from ALL states are
  redirected to the start state's transition for the same byte.
  This implements a simplified Aho-Corasick failure function.
- **Demand paging**: No explicit arena page allocation. Userspace
  memcpy triggers page faults that allocate pages on demand.
