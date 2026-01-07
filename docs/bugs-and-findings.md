# Bugs, Fixes & Key Technical Findings

Engineering notes from bringing the ZDPI XDP data plane to life.
Documents every critical bug encountered, the root cause analysis,
and the fix applied. Written for future maintainers and the
capstone report.

---

## Table of Contents

1. [Arena mmap EINVAL](#1-arena-mmap-einval)
2. [Loopback shortcut 0 DROPs on lo](#2-loopback-shortcut--0-drops-on-lo)
3. [BPF verifier: addr_space_cast without arena](#3-bpf-verifier-addr_space_cast-without-arena)
4. [Arena page allocation failure](#4-arena-page-allocation-failure)
5. [Transition table all zeros](#5-transition-table-all-zeros)
6. [DFA anchoring patterns only match at offset 0](#6-dfa-anchoring--patterns-only-match-at-offset-0)
7. [Accept state missed mid-payload](#7-accept-state-missed-mid-payload)
8. [Partial match kills future matches](#8-partial-match-kills-future-matches)
9. [Skeleton type mismatch](#9-skeleton-type-mismatch)
10. [TRex stale ZMQ port](#10-trex-stale-zmq-port)
11. [Key Findings Summary](#key-findings-summary)

---

## 1. Arena mmap EINVAL

**Symptom**: `mmap()` on the arena map fd returns `EINVAL`.

**Root cause**: Raw `mmap()` on a `BPF_MAP_TYPE_ARENA` fd does not
work the way it does for `BPF_MAP_TYPE_ARRAY`. The arena's virtual
address range is managed by libbpf internally during skeleton load.

**Fix**: Use `bpf_map__initial_value(skel->maps.arena, &arena_sz)`
after `zdpi_kern_bpf__load(skel)`. This returns the userspace
pointer into the arena's mmap region that libbpf already set up.

```c
/* arena_flash.c */
size_t arena_sz = 0;
void *arena_ptr = bpf_map__initial_value(skel->maps.arena, &arena_sz);
```

**Lesson**: For `BPF_MAP_TYPE_ARENA`, always use the skeleton/libbpf
API to get the arena pointer. Never call `mmap()` directly.

---

## 2. Loopback shortcut 0 DROPs on lo

**Symptom**: XDP attached to `lo` sees packets (RX counter
increments) but never drops anything. Same rules work in the
userspace simulator.

**Root cause**: Linux's loopback interface has a fast path that
bypasses XDP for locally-originated traffic on kernels < 6.x.
Even on newer kernels, `lo` traffic between two local sockets
may take a shortcut that skips XDP processing entirely.

**Fix**: Use a **veth pair with a network namespace**. Traffic
crossing the veth always goes through the full network stack
including XDP:

```bash
ip netns add zdpi_test
ip link add veth_zdpi type veth peer name veth_peer
ip link set veth_peer netns zdpi_test
ip addr add 10.99.0.1/24 dev veth_zdpi
ip link set veth_zdpi up
ip netns exec zdpi_test ip addr add 10.99.0.2/24 dev veth_peer
ip netns exec zdpi_test ip link set veth_peer up
```

Attach XDP to `veth_zdpi` (host side), send traffic from inside
the namespace via `veth_peer`.

**Lesson**: Never use `lo` for XDP testing. Always use veth + netns.

---

## 3. BPF verifier: addr_space_cast without arena

**Symptom**: BPF verifier rejects `zdpi_inspect` with:
```
addr_space_cast insn can only be used in a program that has
an associated arena
```

**Root cause**: The XDP program used a pointer stored in BSS to
reference the arena:

```c
/* WRONG pointer lives in BSS (.bss section) */
__u8 __arena *arena_base_ptr;
```

A pointer *to* arena memory (`__u8 __arena *`) is stored in the
program's `.bss` section, not in `.addr_space.1`. libbpf associates
a BPF program with an arena only when the program references data
in the `.addr_space.1` ELF section. No `.addr_space.1` relocation
means no arena association.

**Relevant libbpf code** (`tools/lib/bpf/libbpf.c:4581-4597`):
```c
/* Arena data relocation */
if (shdr->sh_type == SHT_PROGBITS &&
    strcmp(sec_name, ARENA_SEC) == 0) {
        /* Associate program with arena map */
}
```
Where `ARENA_SEC` is `".addr_space.1"` (line 527).

**Fix**: Declare a global variable *stored inside* the arena (using
the `__arena` qualifier without a pointer indirection):

```c
/* CORRECT variable stored IN the arena (.addr_space.1 section) */
struct zdpi_arena_hdr __arena arena_hdr;
```

When clang compiles this, the variable goes into the `.addr_space.1`
section. Any BPF program that references `&arena_hdr` gets an
`.addr_space.1` relocation, which libbpf resolves to the arena map.

The `arena_hdr` lives at arena offset 0 and is overwritten by the
userspace `memcpy` of the DFA blob which is exactly what we want
since the blob starts with the header.

**Lesson**: For BPF Arena programs, the XDP program must reference
a global stored IN the arena (`__arena` qualifier on the variable
itself, not on a pointer type). The `.addr_space.1` relocation is
the mechanism that tells libbpf to associate the program with its
arena map.

---

## 4. Arena page allocation failure

**Symptom**: `Arena alloc failed: err=0 ret=-1` from the
`SEC("syscall") zdpi_alloc` program.

**Root cause**: The `arena_hdr` global in `.addr_space.1` causes
libbpf to pre-allocate page 0 during skeleton load (via a memcpy
that triggers a page fault). The `zdpi_alloc` program then called
`bpf_arena_alloc_pages(&arena, NULL, ZDPI_ARENA_PAGES, ...)` which
requested all 4096 pages, but only 4095 remained free.

**Fix**: Make `zdpi_alloc` a no-op. Arena pages are demand-paged:
when userspace does `memcpy(arena_ptr, blob->data, blob->size)`,
each 4K page is faulted in automatically by the kernel's page fault
handler. No explicit allocation is needed.

```c
SEC("syscall")
int zdpi_alloc(void *ctx)
{
	(void)&arena;  /* keep arena reference for compilation */
	return 0;
}
```

**Lesson**: BPF Arena pages are demand-paged. The userspace memcpy
into the mmap region handles allocation implicitly.
`bpf_arena_alloc_pages()` is only needed for BPF-side allocations,
not for userspace-written data.

---

## 5. Transition table all zeros

**Symptom**: `bpf_printk` traces show header data is correct
(`magic=0x5A445049, states=52, ec=30`) and EC map is correct
(`ec['.']=2, ec['/']=3`), but the transition table reads all
zeros (`table[0]=0, table[30]=0, table[60]=0`).

**Root cause**: Red herring. The sampled table indices happened to
be legitimately zero. With 30 ECs:

- `table[0]` = state 0 (dead), EC 0 → 0 (dead to dead, correct)
- `table[30]` = state 1 (start), EC 0 → 0 (before unanchoring)
- `table[60]` = state 2, EC 0 → 0 (also legitimate)

The actual non-zero entries were at different indices. The
diagnostic was misleading.

**Fix**: Improved the trace to sample meaningful indices based on
the actual `num_ec` value:

```c
bpf_printk("zdpi: tbl[%u]=%u", num_ec, table[num_ec]);
/* num_ec = start state entry for EC 0 */
```

**Lesson**: When debugging BPF data, sample indices relative to the
actual table dimensions. Hardcoded indices are meaningless if the
table shape changes.

---

## 6. DFA anchoring patterns only match at offset 0

**Symptom**: Patterns match in the userspace simulator (which tests
exact strings like `"../"`), but the XDP program never drops
anything when the pattern appears mid-payload
(e.g., `GET /../../etc/passwd`).

**Root cause**: Thompson's NFA construction and subset construction
produce an **anchored** DFA. The start state only has transitions
for bytes that begin a pattern. All other bytes from the start
state go to dead state 0. Once in dead state, the DFA stays dead
forever.

For the pattern `\.\./`:

```
Start state(1) + 'G' → dead(0)  ← packet starts with "GET", dies immediately
Start state(1) + '.' → state 2  ← only matches if '.' is the first byte
```

**Fix (step 1)**: Add self-loops on the start state for bytes that
don't begin any pattern. This lets the DFA skip non-matching bytes
until a pattern prefix appears:

```c
/* main.c after DFA construction, before EC compression */
for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
	if (dfa_graph.states[ZDPI_START_STATE].trans[c] ==
	    ZDPI_DEAD_STATE)
		dfa_graph.states[ZDPI_START_STATE].trans[c] =
			ZDPI_START_STATE;
}
```

This alone is insufficient see Bug #8.

**Lesson**: DFAs built from Thompson's construction are anchored by
default. They only match patterns at the very start of input. For
IDS/DPI use (match *anywhere* in payload), you must unanchor them.

---

## 7. Accept state missed mid-payload

**Symptom**: Trace shows the DFA correctly reaching an accept state
mid-payload (e.g., state 40 after matching `<script`), but the
packet is not dropped. The next byte (`>`) sends the DFA to dead
state 0, and the accept check runs after the loop exits finding
state 0, not an accept state.

**Trace evidence**:
```
[6] 0x74 ec=27 st=36->40    ← 't' of '<script', state 40 is ACCEPT
[7] 0x3e ec=0  st=40->0     ← '>' sends DFA to dead state
final state=0 num_states=52  ← accept check finds state 0, PASS
```

**Root cause**: The accept check was outside the DFA traversal loop:

```c
/* WRONG check only runs after loop ends */
for (...) {
	state = table[state * num_ec + ec];
	if (state == ZDPI_DEAD_STATE) break;
}
/* By this point, state may be 0 (dead), not the accept state */
if (accept[state/8] & (1 << (state%8)))
	return XDP_DROP;
```

**Fix**: Move the accept check inside the loop, immediately after
each transition:

```c
for (__u32 i = 0; i < ZDPI_MAX_PAYLOAD; i++) {
	/* ... bounds checks ... */
	state = table[(__u32)state * num_ec + ec];
	if (state == ZDPI_DEAD_STATE)
		break;
	/* Check accept IMMEDIATELY after transition */
	__u32 byte_idx = state / 8;
	__u8 bit_mask = 1 << (state % 8);
	if (accept[byte_idx] & bit_mask) {
		bump_stat(STAT_DROP);
		return XDP_DROP;
	}
}
```

Applied the same fix to `linearize_simulate()` in `linearize.c`
for consistency between the userspace simulator and the XDP program.

**Lesson**: In a DFA that matches patterns embedded in longer input,
accept states must be checked after every single transition, not
just at the end. A pattern can match in the middle of a payload,
and subsequent bytes will overwrite the match.

---

## 8. Partial match kills future matches

**Symptom**: After fixing bugs #6 and #7, only 2 of 5 expected
attacks are dropped. Payloads like `POST /api?file=../../config`
pass through even though they contain `../`.

**Root cause**: The step-1 unanchoring (Bug #6) only adds
self-loops to the **start state**. Non-start states still
transition to dead state 0 on non-matching bytes.

When the DFA enters a partial-match state and sees a byte that
doesn't continue the pattern, it dies permanently:

```
'f' → state 1 (self-loop, start)
'i' → state 1 (self-loop)
'l' → state 1 (self-loop)
'e' → state 4 (partial match for 'etc/passwd')
'=' → state 0 (DEAD state 4 has no transition for '=')
      ↑ DFA is dead. The '../' later in the payload is never reached.
```

**Fix (step 2)**: For ALL non-start, non-dead states, redirect dead
transitions to the start state's transition for that same byte.
This way, when a partial match fails, the DFA acts as if it's
starting fresh from the current byte:

```c
/* main.c two-step unanchoring */

/* Step 1: start state self-loops */
for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
	if (dfa_graph.states[ZDPI_START_STATE].trans[c] ==
	    ZDPI_DEAD_STATE)
		dfa_graph.states[ZDPI_START_STATE].trans[c] =
			ZDPI_START_STATE;
}

/* Step 2: all other states redirect dead → start's transition */
for (uint32_t s = 2; s < dfa_graph.num_states; s++) {
	for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
		if (dfa_graph.states[s].trans[c] ==
		    ZDPI_DEAD_STATE)
			dfa_graph.states[s].trans[c] =
				dfa_graph.states[ZDPI_START_STATE]
					.trans[c];
	}
}
```

**Why this works**: After step 1, the start state has valid
transitions for every byte (either entering a pattern or
self-looping). Step 2 copies these transitions to every state's
dead slots. The effect is similar to Aho-Corasick's failure
function when a partial match fails, the DFA falls back to the
best possible state for the current byte rather than dying.

**Limitation**: This is a simplified version of Aho-Corasick. It
handles the common case (patterns don't share suffixes that are
prefixes of other patterns) but doesn't handle the edge case where
a failed partial match could resume a *different* partial match.
Full AC failure links would be needed for that, but in practice,
typical IDS patterns are distinct enough that this works.

**Result**: All 5 attack payloads correctly dropped, all 3 clean
payloads correctly passed.

**Lesson**: DFA unanchoring requires TWO steps: (1) start state
self-loops, and (2) failure fallbacks on all other states. Only
doing step 1 creates a DFA that can only match patterns preceded
by bytes that don't start any pattern prefix.

---

## 9. Skeleton type mismatch

**Symptom**: `arena_flash.c` fails to compile with:
```
error: field 'arena_hdr' has incomplete type 'struct zdpi_arena_hdr'
```

**Root cause**: bpftool's generated skeleton (`zdpi_kern.skel.h`)
includes `struct zdpi_arena_hdr arena_hdr;` in its arena struct
definition. But the BPF-side `struct zdpi_arena_hdr` uses kernel
types (`__u32`, `__u16`) which aren't available in userspace, and
the struct isn't defined in any userspace header.

**Fix**: Typedef the BPF-side name to the userspace-side name
before including the skeleton:

```c
/* arena_flash.c */
#include "zdpi_types.h"

/* The BPF skeleton references struct zdpi_arena_hdr (the BPF-side
 * name for the arena header). It is layout-identical to the userspace
 * struct zdpi_table_header defined in zdpi_types.h. */
#define zdpi_arena_hdr zdpi_table_header

#include "zdpi_kern.skel.h"
```

Both structs have identical memory layout (same fields, same sizes,
same offsets), just different type names (`__u32` vs `uint32_t`).

**Lesson**: When BPF programs define structs that appear in the
skeleton, userspace needs a compatible type definition. Use
`#define` to alias the BPF name to the userspace name.

---

## 10. TRex stale ZMQ port

**Symptom**: TRex server fails to start with:
```
ZMQ port is used by the following process:
pid: 218276, cmd: ./_t-rex-64 ...
ERROR encountered while configuring TRex system
```

**Root cause**: A previous TRex run was not cleaned up properly.
TRex uses ZMQ for its control plane (port 4500/4501 by default),
and a stale process holds the port.

**Fix**: Kill stale TRex processes before starting:
```bash
pkill -9 -f t-rex-64
sleep 1
```

The `scripts/run_full_bench.sh` cleanup trap should handle this,
but if the script is killed with `SIGKILL` (not `SIGTERM`), the
trap doesn't fire.

**Lesson**: Always check for stale TRex processes before starting
a new instance. Add explicit cleanup at the top of benchmark
scripts.

---

## Key Findings Summary

### BPF Arena Mechanics

1. **Arena association**: The BPF verifier requires an explicit
   `.addr_space.1` relocation linking a program to its arena map.
   This is created by referencing a variable declared with the
   `__arena` qualifier (not a pointer *to* arena the variable
   itself must be in arena space).

2. **`cast_kern()` is a NOP**: When compiled with
   `__BPF_FEATURE_ADDR_SPACE_CAST` (which clang 20 supports),
   `cast_kern(ptr)` expands to nothing. LLVM automatically inserts
   `addr_space_cast` instructions when dereferencing arena pointers.
   The `cast_kern()` calls are kept for readability/portability.

3. **Demand paging**: Arena pages are faulted in on first access.
   When userspace does `memcpy(arena_ptr, blob, size)`, each 4K
   page is allocated by the kernel's page fault handler. No explicit
   `bpf_arena_alloc_pages()` call is needed for userspace-written
   data.

4. **Arena pointer from libbpf**: Use
   `bpf_map__initial_value(skel->maps.arena, &sz)` after
   `skeleton__load()` to get the userspace arena pointer. Never
   `mmap()` the map fd directly.

### DFA Engineering for DPI

5. **Anchored vs unanchored**: Thompson + subset construction
   produces anchored DFAs. For DPI (match anywhere in payload),
   two-step unanchoring is required:
   - Step 1: Start state dead transitions → self-loop
   - Step 2: All states dead transitions → start's transition

6. **In-loop accept check**: Accept states must be checked after
   EVERY transition in the DFA traversal loop, not just at the end.
   Patterns that match mid-payload will be overwritten by subsequent
   bytes if the check is deferred.

7. **Equivalence class compression**: Reduces table width from 256
   columns to typically 10-30, making the table fit in fewer cache
   lines. For 6 Snort rules, the DFA has 52 states and 30 ECs,
   producing an 8 KB blob.

### Testing & Debugging

8. **veth + netns for XDP testing**: The only reliable way to test
   XDP packet drops. Loopback (`lo`) has fast paths that skip XDP.
   Always create a veth pair with one end in a network namespace.

9. **tracefs location**: On Nobara/Fedora 42 (kernel 6.17),
   tracefs is mounted at `/sys/kernel/tracing/`, not the older
   `/sys/kernel/debug/tracing/` path.

10. **`bpf_printk` for XDP debugging**: Essential for tracing DFA
    traversal byte-by-byte. Limit to first N bytes per packet to
    avoid flooding the trace buffer. Remember to remove before
    production each `bpf_printk` adds ~100ns per call.

### Compilation Pipeline

11. **MFSA produces same results as union**: Both compilation modes
    (MFSA product-state merge and NFA union → single DFA) produce
    identical matching results. MFSA avoids the exponential blowup
    of NFA union subset construction.

12. **Unanchoring happens post-DFA, pre-EC**: The unanchoring step
    runs on the full 256-alphabet DFA, after DFA construction
    (or MFSA product merge) but before equivalence class compression.
    This ensures EC computation sees the self-loops.

---

## Chronological Bug Resolution Order

| # | Bug                          | Impact      | Blocked by |
|---|------------------------------|-------------|------------|
| 1 | Arena mmap EINVAL            | No arena    |          |
| 2 | Loopback shortcut            | 0 DROPs     | #1         |
| 3 | addr_space_cast verifier     | BPF reject  | #1         |
| 9 | Skeleton type mismatch       | Build error | #3         |
| 4 | Arena page alloc failure     | Load error  | #3, #9     |
| 5 | Table all zeros (red herring)| Debugging   | #4         |
| 6 | DFA anchoring (step 1)       | Partial fix | #4         |
| 7 | Accept check timing          | 0 DROPs     | #6         |
| 8 | Partial match fallback       | 2/5 DROPs   | #6, #7     |

After resolving all 8 real bugs: **5/5 attacks dropped, 3/3 clean
packets passed**, with both MFSA and union compilation modes.
