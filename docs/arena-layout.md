# BPF Arena Memory Layout

## Overview

The arena is a contiguous memory region shared between userspace
(control plane) and the XDP program (data plane) via
`BPF_MAP_TYPE_ARENA`. Userspace writes the DFA table via memcpy
into the mmap'd region; the XDP program reads it via
`addr_space_cast` pointer dereferences.

## Arena Configuration

```c
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 4096);  /* 4096 pages = 16 MB */
} arena SEC(".maps");
```

Userspace obtains the arena pointer after skeleton load:
```c
size_t arena_sz = 0;
void *arena_ptr = bpf_map__initial_value(skel->maps.arena, &arena_sz);
memcpy(arena_ptr, blob->data, blob->size);
```

## Layout

```
Offset    Size       Description
------    ----       -----------
0x0000    64 B       zdpi_table_header (cache-line aligned)
0x0040    256 B      ec_map[256] (byte -> equivalence class index)
0x0140    192 B      padding (align to 0x0200)
0x0200    variable   transition_table[num_states * num_ec] (uint32_t, state-major)
varies    variable   accept_bitset (packed bits, 1 bit per state)
varies    variable   rule_ids[num_states] (uint32_t per state)
```

Total size is page-aligned (rounded up to 4096-byte boundary).

### Example (6 Snort rules)

```
States: 52, ECs: 30
Table:  52 * 30 * 4 = 6,240 bytes  (at offset 0x0200)
Accept: ceil(52/8) = 7 bytes        (at offset 0x1A60)
RuleID: 52 * 4 = 208 bytes          (at offset 0x1A67)
Total:  8,192 bytes (2 pages)
```

## Header Structure (64 bytes)

```c
struct zdpi_table_header {
	uint32_t magic;           /* 0x5A445049 ("ZDPI") */
	uint16_t version_major;
	uint16_t version_minor;
	uint16_t version_patch;
	uint16_t num_ec;          /* Number of equivalence classes */
	uint32_t num_states;      /* Total DFA states */
	uint32_t num_rules;       /* Number of source rules */
	uint32_t table_offset;    /* Byte offset of transition table */
	uint32_t table_size;      /* Size of transition table in bytes */
	uint32_t accept_offset;   /* Byte offset of accept bitset */
	uint32_t accept_size;     /* Size of accept bitset in bytes */
	uint32_t rule_id_offset;  /* Byte offset of rule ID array */
	uint32_t rule_id_size;    /* Size of rule ID array in bytes */
	uint32_t total_size;      /* Total blob size (page-aligned) */
	uint32_t table_ready;     /* Set to 1 after flash complete */
	uint8_t  _pad[12];        /* Pad to 64 bytes */
};
```

The BPF program mirrors this as `struct zdpi_arena_hdr` using
kernel types (`__u32`/`__u16`/`__u8`). The two structs are
layout-identical.

## State Conventions

- **State 0**: Dead state. After unanchoring, dead state is never
  reached during traversal (all transitions redirected).
- **State 1**: Start state. Initial DFA state for each packet.
  After unanchoring, all 256 byte transitions are non-dead
  (either self-loop or pattern prefix).

## Transition Table Access

```c
/* EC lookup + table transition */
uint8_t ec = ec_map[byte];
uint32_t next = table[current_state * num_ec + ec];
```

The table is state-major: all EC transitions for state 0 are at
indices `[0 .. num_ec-1]`, state 1 at `[num_ec .. 2*num_ec-1]`,
and so on.

## Accept Check

```c
/* Packed bitset: 1 bit per state */
int is_accept = (accept[state / 8] >> (state % 8)) & 1;
```

Checked after EVERY transition in the XDP traversal loop, not just
at loop end. This ensures patterns matching mid-payload are
detected immediately.

## Arena Association (BPF internals)

The XDP program declares a global stored IN the arena:

```c
struct zdpi_arena_hdr __arena arena_hdr;
```

This places the variable in the `.addr_space.1` ELF section.
Referencing `&arena_hdr` from the XDP program creates a relocation
that libbpf uses to associate the program with the arena map.
Without this association, the BPF verifier rejects any
`addr_space_cast` instructions.

The `arena_hdr` variable lives at arena offset 0 and is
overwritten when userspace memcpy's the DFA blob (which starts
with the header). This is intentional.
