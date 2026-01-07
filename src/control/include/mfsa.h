/**
 * @file mfsa.h
 * @brief Parallel DFA compilation for multi-rule pattern matching.
 *
 * Builds individual minimized DFAs per Snort rule pattern.  The XDP
 * data plane traverses all DFAs in parallel per payload byte, giving
 * additive memory usage (sum of DFA sizes) instead of the exponential
 * blowup of product-state merging.
 *
 * @author Kiran P Das
 * @date 2026-02-22
 * @version 0.2.0
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#ifndef ZDPI_MFSA_H
#define ZDPI_MFSA_H

#include <stdint.h>
#include "dfa.h"
#include "regex_parser.h"
#include "nfa.h"

/**
 * @brief Collection of individual minimized DFAs for parallel traversal.
 *
 * Each DFA corresponds to one Snort rule pattern.  The downstream
 * pipeline uses ec_compute_multi / ec_table_build / linearize_parallel
 * to pack all DFAs into a v2 arena blob.
 */
struct mfsa {
	struct dfa *dfas;
	uint32_t *rule_ids;
	uint32_t num_dfas;
	uint32_t capacity;
};

/**
 * @brief Build individual minimized DFAs from regex token streams.
 *
 * For each pattern: NFA (Thompson) -> DFA (subset) -> minimize (Hopcroft).
 * Failed patterns are skipped with a warning; at least one must succeed.
 *
 * @param streams   Array of regex token streams
 * @param count     Number of patterns
 * @param rule_ids  Rule IDs for each pattern's accept states
 * @param out       Output MFSA (DFA array allocated internally)
 * @return 0 on success, negative error code on failure
 */
int mfsa_build(const struct re_token_stream *streams, uint32_t count,
	       const uint32_t *rule_ids, struct mfsa *out);

/**
 * @brief Free MFSA resources (all individual DFAs + arrays).
 */
void mfsa_free(struct mfsa *m);

/**
 * @brief Merge all DFAs in an MFSA into a single DFA via product union.
 *
 * Incrementally computes union product of all individual DFAs,
 * minimizing after each step.  Result is a single DFA.
 *
 * @param m       MFSA with individual DFAs (consumed on success)
 * @param merged  Output: single merged DFA
 * @return 0 on success, ZDPI_ERR_NOMEM if merging is infeasible
 */
int mfsa_merge_all(struct mfsa *m, struct dfa *merged);

/**
 * @brief Merged MFSA: shared-state automaton with multiple start states.
 *
 * Produced by cross-DFA partition refinement.  States from
 * individual DFAs are pooled and equivalent states are merged.
 * The result is a single transition table traversed with an
 * active-state bitset (one start per original pattern).
 */
struct mfsa_merged {
	uint32_t *trans;	/* [num_states * 256] → next state */
	bool *accept;		/* [num_states] */
	uint32_t *rule_ids;	/* [num_states] (0 if non-accept) */
	uint16_t *starts;	/* [num_starts] start state per DFA */
	uint32_t num_states;
	uint32_t num_starts;
};

/**
 * @brief Merge individual DFAs by sharing equivalent states.
 *
 * Implements the Cicolini 2024 MFSA algorithm adapted for DFAs:
 * pools all DFA states, runs cross-DFA partition refinement to
 * identify equivalent states, and builds a shared-state automaton
 * with multiple start states (one per original DFA).
 *
 * @param m    MFSA with individual DFAs
 * @param out  Output merged automaton (allocated internally)
 * @return 0 on success, negative error code on failure
 */
int mfsa_merge_shared(struct mfsa *m, struct mfsa_merged *out);

/**
 * @brief Free merged MFSA resources.
 */
void mfsa_merged_free(struct mfsa_merged *mm);

#endif /* ZDPI_MFSA_H */
