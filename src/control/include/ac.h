/**
 * @file ac.h
 * @brief Aho-Corasick multi-pattern matching automaton.
 *
 * Builds a single DFA from multiple fixed-string patterns using the
 * Aho-Corasick algorithm (trie + failure links + DFA materialization).
 * The output is a standard struct dfa compatible with the existing
 * EC compression and linearization pipeline.
 *
 * @author Kiran P Das
 * @date 2026-03-15
 * @version 0.4.0
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#ifndef ZDPI_AC_H
#define ZDPI_AC_H

#include <stdint.h>
#include "dfa.h"

/**
 * @brief Input pattern for AC construction.
 */
struct ac_pattern {
	const uint8_t *data;
	uint32_t len;
	uint32_t pattern_id;	/* maps to MFSA DFA index */
};

/**
 * @brief AC accept-state to pattern-ID mapping.
 *
 * For each accept state in the materialized DFA, stores the list
 * of pattern IDs that match at that state (including dictionary
 * suffix links from the failure function).
 */
struct ac_match_info {
	uint32_t *pattern_ids;		/* flat list of pattern IDs */
	uint32_t *state_offsets;	/* offsets[state] into pattern_ids */
	uint32_t *state_counts;		/* counts[state] */
	uint32_t num_states;
	uint32_t total_matches;
};

/**
 * @brief Build an Aho-Corasick DFA from fixed-string patterns.
 *
 * Steps:
 * 1. Trie construction from all patterns
 * 2. BFS failure link computation
 * 3. Output propagation along failure chains
 * 4. DFA materialization (goto + failure -> direct transitions)
 * 5. Unanchoring (dead -> self-loop on start, dead -> start's trans elsewhere)
 *
 * @param patterns      Array of input patterns
 * @param num_patterns  Number of patterns
 * @param out           Output DFA (allocated internally)
 * @param match_info    Output match info (allocated internally)
 * @return 0 on success, negative error code on failure
 */
int ac_build(const struct ac_pattern *patterns, uint32_t num_patterns,
	     struct dfa *out, struct ac_match_info *match_info);

/**
 * @brief Free AC match info resources.
 */
void ac_match_info_free(struct ac_match_info *mi);

#endif /* ZDPI_AC_H */
