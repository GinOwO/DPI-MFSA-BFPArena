/**
 * @file ec_compress.h
 * @brief Equivalence class compression for DFA transition tables.
 *
 * Groups input bytes that produce identical transitions across all
 * DFA states into equivalence classes, reducing table width from
 * 256 to num_ec columns.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.2
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#ifndef ZDPI_EC_COMPRESS_H
#define ZDPI_EC_COMPRESS_H

#include <stdint.h>
#include "zdpi_defs.h"
#include "dfa.h"

/**
 * @brief Equivalence class mapping result.
 */
struct ec_map {
	uint8_t byte_to_ec[ZDPI_ALPHABET_SIZE];
	uint32_t num_ec;
};

/**
 * @brief Compressed DFA transition table using equivalence classes.
 */
struct ec_table {
	uint32_t *table;
	uint32_t num_states;
	uint32_t num_ec;
	bool *accept;
	uint32_t *rule_ids;
};

/**
 * @brief Compute equivalence classes from a DFA.
 *
 * Two bytes are equivalent if they produce the same transition
 * in every DFA state.
 *
 * @param d     Source DFA
 * @param out   Output EC mapping (caller-allocated)
 * @return 0 on success, negative error code on failure
 */
int ec_compute(const struct dfa *d, struct ec_map *out);

/**
 * @brief Compute shared equivalence classes across multiple DFAs.
 *
 * Two bytes are equivalent only if they produce identical transitions
 * in every state of every DFA.
 *
 * @param dfas      Array of DFA pointers
 * @param num_dfas  Number of DFAs
 * @param out       Output EC mapping (caller-allocated)
 * @return 0 on success, ZDPI_ERR_OVERFLOW if >256 classes
 */
int ec_compute_multi(const struct dfa **dfas, uint32_t num_dfas,
		     struct ec_map *out);

/**
 * @brief Build compressed transition table from DFA + EC map.
 *
 * @param d     Source DFA
 * @param ec    Equivalence class mapping
 * @param out   Output compressed table (allocated internally)
 * @return 0 on success, ZDPI_ERR_NOMEM on allocation failure
 */
int ec_table_build(const struct dfa *d, const struct ec_map *ec,
		   struct ec_table *out);

/**
 * @brief Compute equivalence classes from a raw transition table.
 *
 * @param trans       Flat transition table [num_states * 256]
 * @param num_states  Number of states
 * @param out         Output EC mapping
 * @return 0 on success, ZDPI_ERR_OVERFLOW if >256 classes
 */
int ec_compute_raw(const uint32_t *trans, uint32_t num_states,
		   struct ec_map *out);

/**
 * @brief Free compressed table resources.
 */
void ec_table_free(struct ec_table *t);

#endif /* ZDPI_EC_COMPRESS_H */
