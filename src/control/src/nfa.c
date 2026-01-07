/**
 * @file nfa.c
 * @brief Thompson's NFA construction from postfix token streams.
 *
 * States are heap-allocated so the NFA can scale beyond a fixed
 * compile-time limit.  Callers must pre-allocate the NFA with
 * nfa_alloc() before calling nfa_build() or nfa_build_union().
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.2
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include "nfa.h"

#include <stdlib.h>
#include <string.h>

#include "zdpi_types.h"

/* ------------------------------------------------------------------ */
/*  NFA allocation / deallocation                                     */
/* ------------------------------------------------------------------ */

int nfa_alloc(struct nfa *out, uint32_t capacity)
{
	out->states = calloc(capacity, sizeof(struct nfa_state));
	if (!out->states)
		return ZDPI_ERR_NOMEM;
	out->num_states = 0;
	out->capacity = capacity;
	out->start = 0;
	out->accept = 0;
	return ZDPI_OK;
}

void nfa_free(struct nfa *n)
{
	if (!n)
		return;
	free(n->states);
	n->states = NULL;
	n->num_states = 0;
	n->capacity = 0;
}

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                   */
/* ------------------------------------------------------------------ */

struct nfa_frag {
	uint32_t start;
	uint32_t accept;
};

static uint32_t new_state(struct nfa *nfa)
{
	if (nfa->num_states >= nfa->capacity)
		return UINT32_MAX;
	uint32_t id = nfa->num_states++;
	memset(&nfa->states[id], 0, sizeof(struct nfa_state));
	return id;
}

static void add_epsilon(struct nfa *nfa, uint32_t from, uint32_t to)
{
	struct nfa_state *s = &nfa->states[from];
	if (s->num_out >= 2)
		return;
	struct nfa_trans *t = &s->out[s->num_out++];
	t->type = NFA_TRANS_EPSILON;
	t->to = to;
}

static void add_literal(struct nfa *nfa, uint32_t from, uint32_t to,
			uint8_t c)
{
	struct nfa_state *s = &nfa->states[from];
	if (s->num_out >= 2)
		return;
	struct nfa_trans *t = &s->out[s->num_out++];
	t->type = NFA_TRANS_LITERAL;
	t->literal = c;
	t->to = to;
}

static void add_class(struct nfa *nfa, uint32_t from, uint32_t to,
		      const struct re_char_class *cc)
{
	struct nfa_state *s = &nfa->states[from];
	if (s->num_out >= 2)
		return;
	struct nfa_trans *t = &s->out[s->num_out++];
	t->type = NFA_TRANS_CLASS;
	t->cclass = *cc;
	t->to = to;
}

/* ------------------------------------------------------------------ */
/*  nfa_build  -- single-pattern Thompson construction                */
/* ------------------------------------------------------------------ */

int nfa_build(const struct re_token_stream *tokens, struct nfa *out)
{
	out->num_states = 0;

	struct nfa_frag stack[RE_MAX_TOKENS];
	uint32_t sp = 0;

	for (uint32_t i = 0; i < tokens->len; i++) {
		const struct re_token *tok = &tokens->tokens[i];

		switch (tok->type) {
		case RE_TOK_LITERAL: {
			uint32_t s = new_state(out);
			uint32_t a = new_state(out);
			if (s == UINT32_MAX || a == UINT32_MAX)
				return ZDPI_ERR_NOMEM;
			add_literal(out, s, a, tok->literal);
			stack[sp++] = (struct nfa_frag){ s, a };
			break;
		}

		case RE_TOK_DOT: {
			uint32_t s = new_state(out);
			uint32_t a = new_state(out);
			if (s == UINT32_MAX || a == UINT32_MAX)
				return ZDPI_ERR_NOMEM;
			/* Dot matches any byte: char class with all bits */
			struct re_char_class any;
			cc_fill(&any);
			add_class(out, s, a, &any);
			stack[sp++] = (struct nfa_frag){ s, a };
			break;
		}

		case RE_TOK_CLASS: {
			uint32_t s = new_state(out);
			uint32_t a = new_state(out);
			if (s == UINT32_MAX || a == UINT32_MAX)
				return ZDPI_ERR_NOMEM;
			add_class(out, s, a, &tok->cclass);
			stack[sp++] = (struct nfa_frag){ s, a };
			break;
		}

		case RE_TOK_CONCAT: {
			if (sp < 2)
				return ZDPI_ERR_PARSE;
			struct nfa_frag f2 = stack[--sp];
			struct nfa_frag f1 = stack[--sp];
			add_epsilon(out, f1.accept, f2.start);
			stack[sp++] = (struct nfa_frag){ f1.start,
							 f2.accept };
			break;
		}

		case RE_TOK_ALTER: {
			if (sp < 2)
				return ZDPI_ERR_PARSE;
			struct nfa_frag f2 = stack[--sp];
			struct nfa_frag f1 = stack[--sp];
			uint32_t s = new_state(out);
			uint32_t a = new_state(out);
			if (s == UINT32_MAX || a == UINT32_MAX)
				return ZDPI_ERR_NOMEM;
			add_epsilon(out, s, f1.start);
			add_epsilon(out, s, f2.start);
			add_epsilon(out, f1.accept, a);
			add_epsilon(out, f2.accept, a);
			stack[sp++] = (struct nfa_frag){ s, a };
			break;
		}

		case RE_TOK_STAR: {
			if (sp < 1)
				return ZDPI_ERR_PARSE;
			struct nfa_frag f = stack[--sp];
			uint32_t s = new_state(out);
			uint32_t a = new_state(out);
			if (s == UINT32_MAX || a == UINT32_MAX)
				return ZDPI_ERR_NOMEM;
			add_epsilon(out, s, f.start);
			add_epsilon(out, s, a);
			add_epsilon(out, f.accept, f.start);
			add_epsilon(out, f.accept, a);
			stack[sp++] = (struct nfa_frag){ s, a };
			break;
		}

		case RE_TOK_PLUS: {
			if (sp < 1)
				return ZDPI_ERR_PARSE;
			struct nfa_frag f = stack[--sp];
			uint32_t s = new_state(out);
			uint32_t a = new_state(out);
			if (s == UINT32_MAX || a == UINT32_MAX)
				return ZDPI_ERR_NOMEM;
			add_epsilon(out, s, f.start);
			add_epsilon(out, f.accept, f.start);
			add_epsilon(out, f.accept, a);
			stack[sp++] = (struct nfa_frag){ s, a };
			break;
		}

		case RE_TOK_QUEST: {
			if (sp < 1)
				return ZDPI_ERR_PARSE;
			struct nfa_frag f = stack[--sp];
			uint32_t s = new_state(out);
			uint32_t a = new_state(out);
			if (s == UINT32_MAX || a == UINT32_MAX)
				return ZDPI_ERR_NOMEM;
			add_epsilon(out, s, f.start);
			add_epsilon(out, s, a);
			add_epsilon(out, f.accept, a);
			stack[sp++] = (struct nfa_frag){ s, a };
			break;
		}

		case RE_TOK_LPAREN:
		case RE_TOK_RPAREN:
			return ZDPI_ERR_PARSE;
		}
	}

	if (sp != 1)
		return ZDPI_ERR_PARSE;

	out->start = stack[0].start;
	out->accept = stack[0].accept;
	out->states[out->accept].accept = true;

	return ZDPI_OK;
}

/* ------------------------------------------------------------------ */
/*  nfa_epsilon_closure  -- heap-allocated worklist                    */
/* ------------------------------------------------------------------ */

void nfa_epsilon_closure(const struct nfa *nfa, uint8_t *states)
{
	/* Heap-allocated worklist -- capacity may be too large for stack */
	uint32_t *worklist = malloc(nfa->capacity * sizeof(uint32_t));
	if (!worklist)
		return;
	uint32_t wl_len = 0;

	for (uint32_t i = 0; i < nfa->num_states; i++) {
		if (states[i / 8] & (1 << (i % 8)))
			worklist[wl_len++] = i;
	}

	while (wl_len > 0) {
		uint32_t s = worklist[--wl_len];
		const struct nfa_state *st = &nfa->states[s];
		for (uint8_t j = 0; j < st->num_out; j++) {
			if (st->out[j].type == NFA_TRANS_EPSILON) {
				uint32_t to = st->out[j].to;
				if (!(states[to / 8] & (1 << (to % 8)))) {
					states[to / 8] |=
						(1 << (to % 8));
					worklist[wl_len++] = to;
				}
			}
		}
	}

	free(worklist);
}

/* ------------------------------------------------------------------ */
/*  nfa_build_union  -- multi-pattern union with rule IDs             */
/* ------------------------------------------------------------------ */

int nfa_build_union(const struct re_token_stream *streams, uint32_t count,
		    const uint32_t *rule_ids, struct nfa *out)
{
	out->num_states = 0;

	/*
	 * Build an epsilon relay chain for the super-start.
	 * Each nfa_state has at most 2 outgoing transitions, so a
	 * single super-start can only connect to 2 sub-NFAs.  For N
	 * patterns we create a chain of relay states:
	 *
	 *   relay_0 --eps--> pattern_0_start
	 *     \--eps--> relay_1 --eps--> pattern_1_start
	 *                 \--eps--> relay_2 --eps--> pattern_2_start
	 *                             ...
	 *
	 * The last relay connects both of its epsilon slots to the
	 * last two sub-NFA starts (if count >= 2).
	 */

	/* Pre-allocate relay states: one for each pattern except the
	 * last (which shares a relay with the second-to-last). */
	uint32_t num_relays = (count <= 2) ? 1 : count - 1;
	uint32_t first_relay = out->num_states;
	for (uint32_t i = 0; i < num_relays; i++) {
		if (new_state(out) == UINT32_MAX)
			return ZDPI_ERR_NOMEM;
	}

	/* Chain relays: relay[i] --eps--> relay[i+1] */
	for (uint32_t i = 0; i + 1 < num_relays; i++)
		add_epsilon(out, first_relay + i,
			    first_relay + i + 1);

	for (uint32_t r = 0; r < count; r++) {
		/* Build individual NFA into a temporary sub-NFA */
		struct nfa sub;
		int rc = nfa_alloc(&sub, NFA_DEFAULT_CAPACITY);
		if (rc)
			return rc;

		rc = nfa_build(&streams[r], &sub);
		if (rc) {
			nfa_free(&sub);
			return rc;
		}

		/* Copy sub-NFA states into output, offsetting IDs */
		uint32_t base = out->num_states;
		if (base + sub.num_states > out->capacity) {
			nfa_free(&sub);
			return ZDPI_ERR_NOMEM;
		}

		for (uint32_t i = 0; i < sub.num_states; i++) {
			struct nfa_state *dst =
				&out->states[base + i];
			struct nfa_state *src = &sub.states[i];
			*dst = *src;
			for (uint8_t j = 0; j < dst->num_out; j++)
				dst->out[j].to += base;
			if (dst->accept)
				dst->rule_id = rule_ids[r];
		}
		out->num_states += sub.num_states;

		/* Connect the appropriate relay to this sub-NFA */
		uint32_t relay;
		if (count <= 2) {
			relay = first_relay;
		} else if (r < count - 1) {
			relay = first_relay + r;
		} else {
			/* Last pattern shares relay with second-to-last */
			relay = first_relay + r - 1;
		}
		add_epsilon(out, relay, base + sub.start);

		nfa_free(&sub);
	}

	out->start = first_relay;
	return ZDPI_OK;
}
