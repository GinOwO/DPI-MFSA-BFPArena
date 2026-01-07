/**
 * @file zdpi_defs.h
 * @brief Compile-time constants for the ZDPI project.
 *
 * Shared between control plane (userspace) and data plane (eBPF).
 * All tunable limits use #ifndef guards so they can be overridden
 * at build time via -D flags (e.g. cmake -DZDPI_MAX_STATES=65536).
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.2
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#ifndef ZDPI_DEFS_H
#define ZDPI_DEFS_H

/* --- Tunable limits (override via -DZDPI_MAX_STATES=N etc.) --- */

#ifndef ZDPI_MAX_EC
#define ZDPI_MAX_EC		256
#endif

#ifndef ZDPI_MAX_RULES
#define ZDPI_MAX_RULES		131072
#endif

#ifndef ZDPI_MAX_PAYLOAD
#define ZDPI_MAX_PAYLOAD	1500
#endif

#ifndef ZDPI_ALPHABET_SIZE
#define ZDPI_ALPHABET_SIZE	256
#endif

#ifndef ZDPI_ARENA_PAGE_SIZE
#define ZDPI_ARENA_PAGE_SIZE	4096
#endif

/* BPF arena hard limit: 4 GB (kernel-enforced).
 * 1048576 pages × 4096 bytes = 4 GB.
 * Pages are demand-paged only written pages use physical RAM. */
#ifndef ZDPI_ARENA_PAGES
#define ZDPI_ARENA_PAGES	1048576
#endif

/* Max DFA states limited by compilation RAM (~1 KB/state).
 * 8M states ≈ 8 GB RAM during compilation.
 * At runtime the arena table is much smaller (num_ec × 4 bytes/state;
 * e.g. 104 ECs → 416 bytes/state → 8M states = 3.2 GB, fits in 4 GB arena). */
#ifndef ZDPI_MAX_STATES
#define ZDPI_MAX_STATES		8388608
#endif

/* --- Fixed layout constants (not tunable) --- */

#define ZDPI_DEAD_STATE		0
#define ZDPI_START_STATE	1

#define ZDPI_TABLE_ALIGN	64
#define ZDPI_HEADER_SIZE	64
#define ZDPI_EC_MAP_OFFSET	ZDPI_HEADER_SIZE
#define ZDPI_EC_MAP_SIZE	ZDPI_ALPHABET_SIZE
#define ZDPI_TABLE_OFFSET	0x0200

#define ZDPI_MAGIC		0x5A445049 /* "ZDPI" */

/* --- V2 parallel DFA layout constants --- */

#ifndef ZDPI_MAX_PARALLEL_DFAS
#define ZDPI_MAX_PARALLEL_DFAS	65536
#endif

#define ZDPI_HEADER_V2_SIZE	128
#define ZDPI_DFA_DIR_ENTRY_SIZE	16
#define ZDPI_EC_MAP_V2_OFFSET	ZDPI_HEADER_V2_SIZE		/* 0x0080 */
#define ZDPI_DFA_DIR_OFFSET	(ZDPI_EC_MAP_V2_OFFSET + ZDPI_EC_MAP_SIZE)  /* 0x0180 */

/* --- V3 MFSA merged layout constants --- */

#ifndef ZDPI_MFSA_MAX_STATES
#define ZDPI_MFSA_MAX_STATES	4096
#endif

#define ZDPI_HEADER_V3_SIZE	128
#define ZDPI_EC_MAP_V3_OFFSET	ZDPI_HEADER_V3_SIZE		/* 0x0080 */
#define ZDPI_STARTS_V3_OFFSET	(ZDPI_EC_MAP_V3_OFFSET + ZDPI_EC_MAP_SIZE)  /* 0x0180 */

/* Bitset size for NFA active state tracking in XDP */
#define ZDPI_MFSA_BITSET_BYTES	(ZDPI_MFSA_MAX_STATES / 8)	/* 512 */

#define ZDPI_ACTION_PASS	0
#define ZDPI_ACTION_DROP	1

/* --- V4 AC + MFSA two-stage layout constants --- */

#define ZDPI_HEADER_V4_SIZE	128

/* Max AC DFA states in XDP must be power of two for mask bounds.
 * AC table uses uint16_t entries, so max is 65536. */
#ifndef ZDPI_AC_MAX_XDP_STATES
#define ZDPI_AC_MAX_XDP_STATES	(1 << 16)	/* 64K */
#endif

/* Max match entries per AC accept state in XDP */
#ifndef ZDPI_AC_MAX_MATCH_PER_STATE
#define ZDPI_AC_MAX_MATCH_PER_STATE	4
#endif

#endif /* ZDPI_DEFS_H */
