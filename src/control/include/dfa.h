/**
 * @file dfa.h
 * @brief DFA construction and minimization for ZDPI.
 *
 * Converts an NFA to a DFA via subset construction, then
 * minimizes using Hopcroft's algorithm.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.2
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#ifndef ZDPI_DFA_H
#define ZDPI_DFA_H

#include <stdint.h>
#include <stdbool.h>
#include "zdpi_defs.h"
#include "nfa.h"

/**
 * @brief DFA state with full 256-symbol transition table.
 */
struct dfa_state {
	uint32_t trans[ZDPI_ALPHABET_SIZE];
	bool accept;
	uint32_t rule_id;
};

/**
 * @brief Complete DFA graph.
 */
struct dfa {
	struct dfa_state *states;
	uint32_t num_states;
	uint32_t capacity;
};

/**
 * @brief Allocate a DFA with initial capacity.
 *
 * @param out       Output DFA (caller-allocated struct)
 * @param capacity  Initial state capacity
 * @return 0 on success, ZDPI_ERR_NOMEM on allocation failure
 */
int dfa_alloc(struct dfa *out, uint32_t capacity);

/**
 * @brief Free DFA resources.
 */
void dfa_free(struct dfa *d);

/**
 * @brief Build DFA from NFA via subset construction.
 *
 * Uses worklist algorithm with epsilon-closure computation.
 * Dead state (ID=0) absorbs all unmatched transitions.
 * State 1 is always the start state.
 *
 * @param nfa   Source NFA (Thompson-constructed)
 * @param out   Output DFA (caller-allocated via dfa_alloc)
 * @return 0 on success, ZDPI_ERR_NOMEM on state explosion,
 *         ZDPI_ERR_OVERFLOW if exceeding capacity
 */
int dfa_build(const struct nfa *nfa, struct dfa *out);

/**
 * @brief Minimize DFA using Hopcroft's algorithm.
 *
 * Merges equivalent states to produce a minimal DFA.
 * Preserves state 0 as dead and state 1 as start.
 *
 * @param d   DFA to minimize (modified in-place, may realloc)
 * @return 0 on success, negative error code on failure
 */
int dfa_minimize(struct dfa *d);

/**
 * @brief Simulate DFA on an input string.
 *
 * @param d        DFA to simulate
 * @param input    Input bytes
 * @param len      Length of input
 * @param rule_out If non-NULL, set to the matched rule ID
 * @return true if DFA reaches an accept state
 */
bool dfa_simulate(const struct dfa *d, const uint8_t *input, uint32_t len,
		  uint32_t *rule_out);

/**
 * @brief Merge two DFAs via union product construction.
 *
 * Computes a DFA recognizing L(a) ∪ L(b).  Uses BFS to build
 * only reachable product states.  Dead state = 0, start = 1.
 *
 * @param a    First DFA
 * @param b    Second DFA
 * @param out  Output DFA (allocated internally)
 * @return 0 on success, negative error code on failure
 */
int dfa_product_union(const struct dfa *a, const struct dfa *b,
		      struct dfa *out);

#endif /* ZDPI_DFA_H */
