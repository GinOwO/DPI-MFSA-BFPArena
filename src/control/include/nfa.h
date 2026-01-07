/**
 * @file nfa.h
 * @brief Thompson's NFA construction for ZDPI.
 *
 * Builds an NFA from a postfix token stream using Thompson's
 * construction algorithm. Each operator creates a small NFA
 * fragment that is composed via a stack.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.2
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#ifndef ZDPI_NFA_H
#define ZDPI_NFA_H

#include <stdint.h>
#include <stdbool.h>
#include "regex_parser.h"

#ifndef NFA_DEFAULT_CAPACITY
#define NFA_DEFAULT_CAPACITY 8192
#endif

#define NFA_EPSILON          256

/**
 * @brief Transition type for NFA edges.
 */
enum nfa_trans_type {
	NFA_TRANS_LITERAL = 0,
	NFA_TRANS_EPSILON,
	NFA_TRANS_CLASS,
};

/**
 * @brief Single NFA transition edge.
 */
struct nfa_trans {
	enum nfa_trans_type type;
	union {
		uint8_t literal;
		struct re_char_class cclass;
	};
	uint32_t to;
};

/**
 * @brief NFA state with up to 2 outgoing transitions (Thompson).
 */
struct nfa_state {
	struct nfa_trans out[2];
	uint8_t num_out;
	bool accept;
	uint32_t rule_id;
};

/**
 * @brief Complete NFA graph (heap-allocated states).
 */
struct nfa {
	struct nfa_state *states;
	uint32_t num_states;
	uint32_t capacity;
	uint32_t start;
	uint32_t accept;
};

/**
 * @brief Allocate an NFA with given capacity.
 *
 * @param out       Output NFA
 * @param capacity  Maximum number of states
 * @return 0 on success, ZDPI_ERR_NOMEM on failure
 */
int nfa_alloc(struct nfa *out, uint32_t capacity);

/**
 * @brief Free NFA resources.
 */
void nfa_free(struct nfa *n);

/**
 * @brief Build an NFA from a postfix token stream via Thompson's construction.
 *
 * @param tokens   Postfix token stream from regex_parse()
 * @param out      Output NFA (must be pre-allocated via nfa_alloc)
 * @return 0 on success, ZDPI_ERR_NOMEM on state limit, ZDPI_ERR_PARSE on bad tokens
 */
int nfa_build(const struct re_token_stream *tokens, struct nfa *out);

/**
 * @brief Build a union NFA from multiple token streams.
 *
 * Creates a super-start state with epsilon transitions to each
 * individual NFA's start state.
 *
 * @param streams    Array of token streams
 * @param count      Number of token streams
 * @param rule_ids   Rule IDs for each stream's accept states
 * @param out        Output NFA (must be pre-allocated via nfa_alloc)
 * @return 0 on success, negative error code on failure
 */
int nfa_build_union(const struct re_token_stream *streams, uint32_t count,
		    const uint32_t *rule_ids, struct nfa *out);

/**
 * @brief Compute epsilon closure of a set of NFA states.
 *
 * @param nfa       NFA graph
 * @param states    Input/output state set (bitset, capacity bits)
 */
void nfa_epsilon_closure(const struct nfa *nfa, uint8_t *states);

#endif /* ZDPI_NFA_H */
