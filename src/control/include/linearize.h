/**
 * @file linearize.h
 * @brief DFA table linearization for BPF arena layout.
 *
 * Converts a compressed DFA table + EC map into the flat binary
 * format expected by the XDP program in the BPF arena.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.1
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#ifndef ZDPI_LINEARIZE_H
#define ZDPI_LINEARIZE_H

#include <stdint.h>
#include "zdpi_types.h"
#include "ec_compress.h"
#include "mfsa.h"
#include "ac.h"

/**
 * @brief Linearized arena blob ready for memcpy into BPF arena.
 */
struct arena_blob {
	uint8_t *data;
	uint32_t size;
	struct zdpi_table_header header;
};

/**
 * @brief Linearize EC table into arena blob format.
 *
 * Layout:
 *   [header 64B][ec_map 256B][pad to 0x200][table][accept_bits][rule_ids]
 *
 * @param ec_map  Equivalence class mapping
 * @param table   Compressed transition table
 * @param out     Output blob (allocated internally)
 * @return 0 on success, ZDPI_ERR_NOMEM on allocation failure
 */
int linearize(const struct ec_map *ec_map, const struct ec_table *table,
	      struct arena_blob *out);

/**
 * @brief Linearize multiple DFAs into v2 parallel arena blob.
 *
 * Layout:
 *   [v2 header 128B][ec_map 256B][dfa_dir N×16B][pad]
 *   [dfa0 table][dfa0 accept]...[dfaN table][dfaN accept]
 *
 * @param ec_map    Shared equivalence class mapping
 * @param tables    Array of per-DFA compressed tables
 * @param num_dfas  Number of DFAs
 * @param rule_ids  Rule ID per DFA
 * @param out       Output blob (allocated internally)
 * @return 0 on success, ZDPI_ERR_NOMEM on allocation failure
 */
int linearize_parallel(const struct ec_map *ec_map,
		       const struct ec_table *tables, uint32_t num_dfas,
		       const uint32_t *rule_ids, struct arena_blob *out);

/**
 * @brief Simulate parallel DFA traversal on a v2 blob.
 *
 * @param blob   V2 arena blob
 * @param input  Input bytes
 * @param len    Length of input
 * @return ZDPI_ACTION_DROP if any DFA accepts, ZDPI_ACTION_PASS otherwise
 */
int linearize_parallel_simulate(const struct arena_blob *blob,
				const uint8_t *input, uint32_t len);

/**
 * @brief Linearize MFSA merged automaton into v3 arena blob.
 *
 * Layout:
 *   [v3 header 128B][ec_map 256B][starts N×2B][pad to 64B]
 *   [trans table num_states×num_ec×2B][accept bits][rule_ids]
 *
 * @param ec_map   Equivalence class mapping
 * @param merged   Merged MFSA automaton
 * @param out      Output blob (allocated internally)
 * @return 0 on success, ZDPI_ERR_NOMEM on allocation failure
 */
int linearize_mfsa(const struct ec_map *ec_map,
		   const struct mfsa_merged *merged,
		   struct arena_blob *out);

/**
 * @brief Simulate MFSA merged traversal on a v3 blob.
 *
 * @param blob   V3 arena blob
 * @param input  Input bytes
 * @param len    Length of input
 * @return ZDPI_ACTION_DROP if any accept reached, ZDPI_ACTION_PASS
 */
int linearize_mfsa_simulate(const struct arena_blob *blob,
			    const uint8_t *input, uint32_t len);

/**
 * @brief Linearize AC + MFSA two-stage pipeline into v4 arena blob.
 *
 * Layout:
 *   [V4 header 128B]
 *   [AC EC map 256B]
 *   [AC transition table: ac_num_states × ac_num_ec × 4B]
 *   [AC accept bitset: (ac_num_states+7)/8]
 *   [AC match directory: ac_num_states × 4B (offset<<16 | count)]
 *   [AC match list: total_matches × 2B (uint16_t MFSA indices)]
 *   [Always-run list: always_run_count × 2B]
 *   [Padding to 64B alignment]
 *   [MFSA EC map 256B]
 *   [MFSA DFA directory: mfsa_num_dfas × 16B]
 *   [Per-MFSA-DFA tables + accept bits (same as V2)]
 *   [Page alignment]
 */
int linearize_v4(const struct ec_map *ac_ecm,
		 const struct ec_table *ac_table,
		 const struct ac_match_info *match_info,
		 const struct ec_map *mfsa_ecm,
		 const struct ec_table *mfsa_tables,
		 uint32_t num_mfsa_dfas,
		 const uint32_t *rule_ids,
		 const uint16_t *always_run_indices,
		 uint32_t always_run_count,
		 struct arena_blob *out);

/**
 * @brief Simulate two-stage AC+MFSA traversal on a v4 blob.
 *
 * CPU-side simulation for testing without BPF:
 * 1. Run AC DFA, collect matched MFSA indices
 * 2. OR in always-run indices
 * 3. Run only matched MFSA DFAs
 *
 * @return ZDPI_ACTION_DROP if any MFSA DFA accepts, ZDPI_ACTION_PASS otherwise
 */
int linearize_v4_simulate(const struct arena_blob *blob,
			   const uint8_t *input, uint32_t len);

/**
 * @brief Free arena blob resources.
 */
void arena_blob_free(struct arena_blob *b);

/**
 * @brief Simulate DFA traversal on a linearized blob.
 *
 * Used for testing without BPF mirrors the XDP traversal logic.
 *
 * @param blob     Linearized arena blob
 * @param input    Input bytes
 * @param len      Length of input
 * @return ZDPI_ACTION_DROP if accept state reached, ZDPI_ACTION_PASS otherwise
 */
int linearize_simulate(const struct arena_blob *blob, const uint8_t *input,
		       uint32_t len);

#endif /* ZDPI_LINEARIZE_H */
