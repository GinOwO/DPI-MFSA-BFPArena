/**
 * @file zdpi_types.h
 * @brief Shared types and arena layout structures for ZDPI.
 *
 * Defines the binary layout of the BPF arena as shared between
 * the userspace control plane and the XDP data plane.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.2
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#ifndef ZDPI_TYPES_H
#define ZDPI_TYPES_H

#ifdef __BPF__
#include "vmlinux.h"
#else
#include <stdint.h>
#include <stddef.h>
#endif

#include "zdpi_defs.h"

/**
 * @brief Arena header at offset 0x0000 (64 bytes, cache-line aligned).
 *
 * Written by the control plane after flashing the table.
 * Read by the XDP program to validate and traverse the DFA.
 */
struct zdpi_table_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	uint16_t version_patch;
	uint16_t num_ec;
	uint32_t num_states;
	uint32_t num_rules;
	uint32_t table_offset;
	uint32_t table_size;
	uint32_t accept_offset;
	uint32_t accept_size;
	uint32_t rule_id_offset;
	uint32_t rule_id_size;
	uint32_t total_size;
	uint32_t table_ready;
	uint8_t _pad[12];
};

#ifdef __cplusplus
static_assert(sizeof(struct zdpi_table_header) == ZDPI_HEADER_SIZE,
	      "header must be 64 bytes");
#else
_Static_assert(sizeof(struct zdpi_table_header) == ZDPI_HEADER_SIZE,
	       "header must be 64 bytes");
#endif

/**
 * @brief V2 arena header for parallel DFA traversal (128 bytes).
 *
 * Used when multiple individual DFAs are stored in the arena
 * instead of a single merged product-state DFA.
 */
struct zdpi_table_header_v2 {
	uint32_t magic;
	uint16_t version_major;		/* 0 */
	uint16_t version_minor;		/* 1 = parallel format */
	uint16_t num_ec;
	uint16_t num_dfas;
	uint32_t dfa_dir_offset;
	uint32_t ec_map_offset;
	uint32_t total_size;
	uint32_t table_ready;
	uint8_t _pad[100];
};

#ifdef __cplusplus
static_assert(sizeof(struct zdpi_table_header_v2) == ZDPI_HEADER_V2_SIZE,
	      "v2 header must be 128 bytes");
#else
_Static_assert(sizeof(struct zdpi_table_header_v2) == ZDPI_HEADER_V2_SIZE,
	       "v2 header must be 128 bytes");
#endif

/**
 * @brief DFA directory entry one per individual DFA in the arena.
 */
struct zdpi_dfa_dir_entry {
	uint32_t table_offset;
	uint32_t accept_offset;
	uint16_t num_states;
	uint16_t rule_id;
	uint8_t _pad[4];
};

#ifdef __cplusplus
static_assert(sizeof(struct zdpi_dfa_dir_entry) == ZDPI_DFA_DIR_ENTRY_SIZE,
	      "DFA dir entry must be 16 bytes");
#else
_Static_assert(sizeof(struct zdpi_dfa_dir_entry) == ZDPI_DFA_DIR_ENTRY_SIZE,
	       "DFA dir entry must be 16 bytes");
#endif

/**
 * @brief V3 arena header for MFSA merged traversal (128 bytes).
 *
 * Used when individual DFAs are merged via cross-DFA partition
 * refinement into a shared-state automaton with multiple start
 * states.  XDP traverses with an active-state bitset.
 */
struct zdpi_table_header_v3 {
	uint32_t magic;
	uint16_t version_major;		/* 0 */
	uint16_t version_minor;		/* 2 = MFSA merged format */
	uint16_t num_ec;
	uint16_t num_starts;
	uint32_t num_states;
	uint32_t starts_offset;
	uint32_t table_offset;
	uint32_t accept_offset;
	uint32_t rule_id_offset;
	uint32_t total_size;
	uint32_t table_ready;
	uint8_t _pad[88];
};

#ifdef __cplusplus
static_assert(sizeof(struct zdpi_table_header_v3) == ZDPI_HEADER_V3_SIZE,
	      "v3 header must be 128 bytes");
#else
_Static_assert(sizeof(struct zdpi_table_header_v3) == ZDPI_HEADER_V3_SIZE,
	       "v3 header must be 128 bytes");
#endif

/**
 * @brief Error codes for the ZDPI control plane.
 */
enum zdpi_error {
	ZDPI_OK = 0,
	ZDPI_ERR_NOMEM = -1,
	ZDPI_ERR_PARSE = -2,
	ZDPI_ERR_OVERFLOW = -3,
	ZDPI_ERR_BPF = -4,
	ZDPI_ERR_IO = -5,
};

/**
 * @brief V4 arena header for AC + MFSA two-stage pipeline (128 bytes).
 *
 * Stage 1: Aho-Corasick automaton over content keywords (single DFA).
 * Stage 2: MFSA parallel DFAs over PCRE patterns for AC-matched rules.
 */
struct zdpi_table_header_v4 {
	uint32_t magic;
	uint16_t version_major;		/* 0 */
	uint16_t version_minor;		/* 3 = AC+MFSA format */
	/* AC section */
	uint16_t ac_num_ec;
	uint16_t _pad0;
	uint32_t ac_num_states;
	uint32_t ac_table_offset;	/* uint16_t entries */
	uint32_t ac_accept_offset;
	uint32_t ac_matchdir_offset;	/* match_offset[]/count[] */
	uint32_t ac_matchlist_offset;	/* flat uint16_t MFSA indices */
	uint32_t ac_matchlist_count;
	/* MFSA section */
	uint16_t mfsa_num_ec;
	uint16_t mfsa_num_dfas;
	uint32_t mfsa_ec_offset;
	uint32_t mfsa_dir_offset;
	/* Always-run bitmask for rules without content */
	uint32_t always_run_offset;
	uint32_t always_run_count;
	/* Common */
	uint32_t total_size;
	uint32_t table_ready;
	uint8_t _pad[64];
};

#ifdef __cplusplus
static_assert(sizeof(struct zdpi_table_header_v4) == ZDPI_HEADER_V4_SIZE,
	      "v4 header must be 128 bytes");
#else
_Static_assert(sizeof(struct zdpi_table_header_v4) == ZDPI_HEADER_V4_SIZE,
	       "v4 header must be 128 bytes");
#endif

/**
 * @brief Parsed content: field from a Snort rule.
 */
#define ZDPI_MAX_CONTENT_LEN	256
#define ZDPI_MAX_CONTENTS	16

struct zdpi_content {
	uint8_t data[ZDPI_MAX_CONTENT_LEN];
	uint32_t len;
	bool nocase;
	bool negated;
};

/**
 * @brief Parsed Snort rule representation.
 */
struct zdpi_rule {
	uint32_t sid;
	uint8_t action;
	uint8_t proto;
	uint16_t src_port;
	uint16_t dst_port;
	char pcre[512];
	uint32_t pcre_len;
	struct zdpi_content contents[ZDPI_MAX_CONTENTS];
	uint32_t num_contents;
};

#endif /* ZDPI_TYPES_H */
