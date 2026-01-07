/**
 * @file ac.c
 * @brief Aho-Corasick multi-pattern matching automaton.
 *
 * @author Kiran P Das
 * @date 2026-03-15
 * @version 0.4.0
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include "ac.h"

#include <stdlib.h>
#include <string.h>

#include "zdpi_types.h"

/* --- Trie node for AC construction --- */

struct ac_trie_node {
	int children[ZDPI_ALPHABET_SIZE]; /* -1 = no child */
	int failure;			  /* failure link */
	uint32_t *output_ids;		  /* pattern IDs matching here */
	uint32_t output_count;
	uint32_t output_cap;
	int depth;
};

struct ac_trie {
	struct ac_trie_node *nodes;
	uint32_t num_nodes;
	uint32_t capacity;
};

static int trie_alloc(struct ac_trie *t, uint32_t cap)
{
	t->nodes = calloc(cap, sizeof(struct ac_trie_node));
	if (!t->nodes)
		return ZDPI_ERR_NOMEM;
	t->capacity = cap;
	t->num_nodes = 0;
	return ZDPI_OK;
}

static int trie_new_node(struct ac_trie *t)
{
	if (t->num_nodes >= t->capacity) {
		uint32_t new_cap = t->capacity * 2;
		struct ac_trie_node *tmp = realloc(t->nodes,
			new_cap * sizeof(struct ac_trie_node));
		if (!tmp)
			return -1;
		t->nodes = tmp;
		t->capacity = new_cap;
	}
	int id = (int)t->num_nodes;
	struct ac_trie_node *n = &t->nodes[id];
	memset(n, 0, sizeof(*n));
	for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++)
		n->children[c] = -1;
	n->failure = 0;
	t->num_nodes++;
	return id;
}

static int trie_add_output(struct ac_trie_node *n, uint32_t pattern_id)
{
	if (n->output_count >= n->output_cap) {
		uint32_t new_cap = n->output_cap ? n->output_cap * 2 : 4;
		uint32_t *tmp = realloc(n->output_ids,
					new_cap * sizeof(uint32_t));
		if (!tmp)
			return ZDPI_ERR_NOMEM;
		n->output_ids = tmp;
		n->output_cap = new_cap;
	}
	n->output_ids[n->output_count++] = pattern_id;
	return ZDPI_OK;
}

static void trie_free(struct ac_trie *t)
{
	for (uint32_t i = 0; i < t->num_nodes; i++)
		free(t->nodes[i].output_ids);
	free(t->nodes);
	memset(t, 0, sizeof(*t));
}

/* --- AC construction --- */

int ac_build(const struct ac_pattern *patterns, uint32_t num_patterns,
	     struct dfa *out, struct ac_match_info *match_info)
{
	if (num_patterns == 0)
		return ZDPI_ERR_PARSE;

	/* Estimate trie size: sum of pattern lengths + root */
	uint32_t total_len = 0;
	for (uint32_t i = 0; i < num_patterns; i++)
		total_len += patterns[i].len;
	uint32_t est_cap = total_len + 256;
	if (est_cap < 1024)
		est_cap = 1024;

	struct ac_trie trie;
	int rc = trie_alloc(&trie, est_cap);
	if (rc)
		return rc;

	/* Create root node (state 0) */
	int root = trie_new_node(&trie);
	if (root < 0) {
		trie_free(&trie);
		return ZDPI_ERR_NOMEM;
	}

	/* Step 1: Insert all patterns into the trie */
	for (uint32_t pi = 0; pi < num_patterns; pi++) {
		int cur = root;
		for (uint32_t ci = 0; ci < patterns[pi].len; ci++) {
			uint8_t byte = patterns[pi].data[ci];
			if (trie.nodes[cur].children[byte] < 0) {
				int nid = trie_new_node(&trie);
				if (nid < 0) {
					trie_free(&trie);
					return ZDPI_ERR_NOMEM;
				}
				trie.nodes[nid].depth =
					trie.nodes[cur].depth + 1;
				trie.nodes[cur].children[byte] = nid;
			}
			cur = trie.nodes[cur].children[byte];
		}
		rc = trie_add_output(&trie.nodes[cur],
				     patterns[pi].pattern_id);
		if (rc) {
			trie_free(&trie);
			return rc;
		}
	}

	/* Step 2: BFS failure link computation */
	/* Queue for BFS */
	int *queue = calloc(trie.num_nodes, sizeof(int));
	if (!queue) {
		trie_free(&trie);
		return ZDPI_ERR_NOMEM;
	}
	uint32_t q_head = 0, q_tail = 0;

	/* Initialize: depth-1 nodes have failure = root */
	for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
		int child = trie.nodes[root].children[c];
		if (child >= 0) {
			trie.nodes[child].failure = root;
			queue[q_tail++] = child;
		}
	}

	/* BFS over remaining nodes */
	while (q_head < q_tail) {
		int u = queue[q_head++];

		for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
			int v = trie.nodes[u].children[c];
			if (v < 0)
				continue;

			/* Compute failure link for v:
			 * follow parent u's failure links until we
			 * find one with a child on byte c */
			int f = trie.nodes[u].failure;
			while (f != root &&
			       trie.nodes[f].children[c] < 0)
				f = trie.nodes[f].failure;
			if (trie.nodes[f].children[c] >= 0 &&
			    trie.nodes[f].children[c] != v)
				f = trie.nodes[f].children[c];
			trie.nodes[v].failure = f;

			/* Step 3: Output propagation - merge failure's
			 * outputs into this node */
			int fl = trie.nodes[v].failure;
			for (uint32_t oi = 0;
			     oi < trie.nodes[fl].output_count; oi++) {
				rc = trie_add_output(&trie.nodes[v],
					trie.nodes[fl].output_ids[oi]);
				if (rc) {
					free(queue);
					trie_free(&trie);
					return rc;
				}
			}

			queue[q_tail++] = v;
		}
	}
	free(queue);

	/* Step 4: DFA materialization
	 * Map trie node IDs to DFA state IDs.
	 * Trie node 0 (root) -> DFA state 1 (start).
	 * DFA state 0 is dead state (never used by AC but kept
	 * for compatibility with the existing pipeline). */

	uint32_t num_trie_nodes = trie.num_nodes;
	uint32_t num_dfa_states = num_trie_nodes + 1;

	rc = dfa_alloc(out, num_dfa_states);
	if (rc) {
		trie_free(&trie);
		return rc;
	}

	/* State 0 = dead (self-loop on everything) */
	out->num_states = num_dfa_states;
	for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++)
		out->states[0].trans[c] = ZDPI_DEAD_STATE;
	out->states[0].accept = false;
	out->states[0].rule_id = 0;

	/* For each trie node, build DFA state transitions.
	 * Trie node n -> DFA state n+1.
	 * For each byte c:
	 *   if goto(n, c) exists -> DFA state goto(n,c)+1
	 *   else follow failure links until goto exists or reach root */
	for (uint32_t n = 0; n < num_trie_nodes; n++) {
		uint32_t dfa_s = n + 1; /* trie node -> DFA state */
		struct ac_trie_node *tn = &trie.nodes[n];

		for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
			if (tn->children[c] >= 0) {
				/* Direct goto */
				out->states[dfa_s].trans[c] =
					(uint32_t)tn->children[c] + 1;
			} else {
				/* Follow failure links */
				int f = (int)n;
				while (f != root &&
				       trie.nodes[f].children[c] < 0)
					f = trie.nodes[f].failure;
				if (trie.nodes[f].children[c] >= 0)
					out->states[dfa_s].trans[c] =
						(uint32_t)trie.nodes[f]
							.children[c] + 1;
				else
					out->states[dfa_s].trans[c] =
						root + 1; /* start */
			}
		}

		/* Mark accept if this node has outputs */
		out->states[dfa_s].accept = (tn->output_count > 0);
		out->states[dfa_s].rule_id = 0;
	}

	/* Step 5: Build match_info from trie outputs */
	memset(match_info, 0, sizeof(*match_info));
	match_info->num_states = num_dfa_states;
	match_info->state_offsets = calloc(num_dfa_states,
					   sizeof(uint32_t));
	match_info->state_counts = calloc(num_dfa_states,
					  sizeof(uint32_t));
	if (!match_info->state_offsets || !match_info->state_counts) {
		dfa_free(out);
		free(match_info->state_offsets);
		free(match_info->state_counts);
		trie_free(&trie);
		return ZDPI_ERR_NOMEM;
	}

	/* Count total matches and per-state counts */
	uint32_t total = 0;
	for (uint32_t n = 0; n < num_trie_nodes; n++) {
		uint32_t dfa_s = n + 1;
		match_info->state_counts[dfa_s] =
			trie.nodes[n].output_count;
		total += trie.nodes[n].output_count;
	}
	match_info->total_matches = total;

	/* Compute offsets */
	uint32_t offset = 0;
	for (uint32_t s = 0; s < num_dfa_states; s++) {
		match_info->state_offsets[s] = offset;
		offset += match_info->state_counts[s];
	}

	/* Fill pattern_ids */
	if (total > 0) {
		match_info->pattern_ids = calloc(total, sizeof(uint32_t));
		if (!match_info->pattern_ids) {
			dfa_free(out);
			ac_match_info_free(match_info);
			trie_free(&trie);
			return ZDPI_ERR_NOMEM;
		}
		for (uint32_t n = 0; n < num_trie_nodes; n++) {
			uint32_t dfa_s = n + 1;
			uint32_t off = match_info->state_offsets[dfa_s];
			for (uint32_t oi = 0;
			     oi < trie.nodes[n].output_count; oi++) {
				match_info->pattern_ids[off + oi] =
					trie.nodes[n].output_ids[oi];
			}
		}
	}

	trie_free(&trie);

	/* Note: We do NOT unanchor here the AC DFA naturally handles
	 * multi-pattern matching without unanchoring because the root
	 * state already serves as the fallback via failure links.
	 * The root's transitions to itself for unmatched bytes give
	 * us the "match anywhere" behavior automatically. */

	return ZDPI_OK;
}

void ac_match_info_free(struct ac_match_info *mi)
{
	if (!mi)
		return;
	free(mi->pattern_ids);
	free(mi->state_offsets);
	free(mi->state_counts);
	memset(mi, 0, sizeof(*mi));
}
