/**
 * @file mfsa.c
 * @brief Parallel DFA compilation build individual minimized DFAs.
 *
 * For each Snort rule pattern, builds NFA -> DFA -> minimize and
 * stores the result.  The downstream pipeline (ec_compute_multi,
 * linearize_parallel) packs all DFAs into the v2 arena for XDP
 * parallel traversal.
 *
 * @author Kiran P Das
 * @date 2026-02-22
 * @version 0.2.0
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include "mfsa.h"

#include <stdlib.h>
#include <string.h>

#include "zdpi_types.h"
#include "zdpi_log.h"

int mfsa_build(const struct re_token_stream *streams, uint32_t count,
	       const uint32_t *rule_ids, struct mfsa *out)
{
	if (count == 0)
		return ZDPI_ERR_PARSE;

	memset(out, 0, sizeof(*out));

	out->dfas = calloc(count, sizeof(struct dfa));
	out->rule_ids = calloc(count, sizeof(uint32_t));
	if (!out->dfas || !out->rule_ids) {
		free(out->dfas);
		free(out->rule_ids);
		memset(out, 0, sizeof(*out));
		return ZDPI_ERR_NOMEM;
	}
	out->capacity = count;

	uint32_t skip_nfa = 0, skip_dfa = 0;
	uint32_t states_before_min = 0;

	for (uint32_t i = 0; i < count; i++) {
		struct nfa nfa_g;
		int rc = nfa_alloc(&nfa_g, NFA_DEFAULT_CAPACITY);
		if (rc) {
			skip_nfa++;
			continue;
		}

		rc = nfa_build(&streams[i], &nfa_g);
		if (rc) {
			LOG_DBG("[%u/%u] SID %u: nfa_build failed: %d",
				i + 1, count, rule_ids[i], rc);
			nfa_free(&nfa_g);
			skip_nfa++;
			continue;
		}

		for (uint32_t s = 0; s < nfa_g.num_states; s++) {
			if (nfa_g.states[s].accept)
				nfa_g.states[s].rule_id = rule_ids[i];
		}

		struct dfa single;
		rc = dfa_alloc(&single, 4096);
		if (rc) {
			nfa_free(&nfa_g);
			skip_dfa++;
			continue;
		}

		rc = dfa_build(&nfa_g, &single);
		nfa_free(&nfa_g);
		if (rc) {
			LOG_DBG("[%u/%u] SID %u: dfa_build failed: %d",
				i + 1, count, rule_ids[i], rc);
			dfa_free(&single);
			skip_dfa++;
			continue;
		}

		states_before_min += single.num_states;

		rc = dfa_minimize(&single);
		if (rc) {
			LOG_DBG("[%u/%u] SID %u: dfa_minimize "
				"failed: %d",
				i + 1, count, rule_ids[i], rc);
			dfa_free(&single);
			skip_dfa++;
			continue;
		}

		uint32_t idx = out->num_dfas++;
		out->dfas[idx] = single;
		out->rule_ids[idx] = rule_ids[i];

		if (out->num_dfas % 100 == 0)
			LOG_DBG("[%u/%u] built %u DFAs",
				i + 1, count, out->num_dfas);
	}

	if (out->num_dfas == 0) {
		LOG_ERR("No DFAs successfully built from %u streams",
			count);
		free(out->dfas);
		free(out->rule_ids);
		memset(out, 0, sizeof(*out));
		return ZDPI_ERR_PARSE;
	}

	uint32_t total_states = 0;
	for (uint32_t i = 0; i < out->num_dfas; i++)
		total_states += out->dfas[i].num_states;

	LOG_INF("MFSA: %u/%u DFAs built, %u states before minimize, "
		"%u after (%.1f%% reduction)",
		out->num_dfas, count, states_before_min, total_states,
		states_before_min > 0
		    ? (1.0 - (double)total_states / states_before_min) * 100
		    : 0.0);
	if (skip_nfa || skip_dfa)
		LOG_WRN("Skipped: %u NFA failures, %u DFA failures",
			skip_nfa, skip_dfa);

	return ZDPI_OK;
}

int mfsa_merge_all(struct mfsa *m, struct dfa *merged)
{
	if (m->num_dfas == 0)
		return ZDPI_ERR_PARSE;

	if (m->num_dfas == 1) {
		*merged = m->dfas[0];
		m->dfas[0].states = NULL; /* transfer ownership */
		LOG_INF("MFSA merge: 1 DFA, nothing to merge");
		return ZDPI_OK;
	}

	/* Start with a copy of the first DFA */
	struct dfa acc;
	int rc = dfa_alloc(&acc, m->dfas[0].num_states);
	if (rc)
		return rc;
	memcpy(acc.states, m->dfas[0].states,
	       m->dfas[0].num_states * sizeof(struct dfa_state));
	acc.num_states = m->dfas[0].num_states;

	uint32_t total_before = 0;
	for (uint32_t i = 0; i < m->num_dfas; i++)
		total_before += m->dfas[i].num_states;

	/* Cap intermediate states to keep merge feasible.
	 * If accumulator exceeds this, bail to parallel mode. */
	const uint32_t merge_state_cap = 100000;

	for (uint32_t i = 1; i < m->num_dfas; i++) {
		struct dfa product;
		rc = dfa_product_union(&acc, &m->dfas[i], &product);
		if (rc) {
			LOG_WRN("MFSA merge: product failed at DFA "
				"%u/%u (%u acc × %u), bailing out",
				i + 1, m->num_dfas,
				acc.num_states,
				m->dfas[i].num_states);
			dfa_free(&acc);
			return rc;
		}

		dfa_free(&acc);

		rc = dfa_minimize(&product);
		if (rc) {
			LOG_WRN("MFSA merge: minimize failed at DFA "
				"%u/%u", i + 1, m->num_dfas);
			dfa_free(&product);
			return rc;
		}

		acc = product;

		LOG_DBG("MFSA merge: %u/%u DFAs merged, "
			"%u states",
			i + 1, m->num_dfas, acc.num_states);

		if (acc.num_states > merge_state_cap) {
			LOG_WRN("MFSA merge: %u states exceeds "
				"cap (%u) at DFA %u/%u",
				acc.num_states, merge_state_cap,
				i + 1, m->num_dfas);
			dfa_free(&acc);
			return ZDPI_ERR_NOMEM;
		}
	}

	LOG_INF("MFSA merge: %u DFAs -> 1 DFA, %u -> %u states "
		"(%.1f%% reduction)",
		m->num_dfas, total_before, acc.num_states,
		total_before > 0
		    ? (1.0 - (double)acc.num_states / total_before) * 100
		    : 0.0);

	*merged = acc;
	return ZDPI_OK;
}

void mfsa_free(struct mfsa *m)
{
	if (m->dfas) {
		for (uint32_t i = 0; i < m->num_dfas; i++)
			dfa_free(&m->dfas[i]);
		free(m->dfas);
	}
	free(m->rule_ids);
	memset(m, 0, sizeof(*m));
}

/* ------------------------------------------------------------------ */
/*  Cross-DFA partition refinement (Cicolini MFSA)                    */
/* ------------------------------------------------------------------ */

/* FNV-1a 64-bit hash helpers */
#define FNV_OFFSET	0xcbf29ce484222325ULL
#define FNV_PRIME	0x100000001b3ULL

static inline uint64_t fnv1a_u32(uint64_t h, uint32_t v)
{
	h ^= (v & 0xFF);        h *= FNV_PRIME;
	h ^= ((v >> 8) & 0xFF); h *= FNV_PRIME;
	h ^= ((v >> 16) & 0xFF); h *= FNV_PRIME;
	h ^= ((v >> 24) & 0xFF); h *= FNV_PRIME;
	return h;
}

/* Sort helper for signature-based group assignment */
struct sig_entry {
	uint64_t sig;
	uint32_t state;
};

static int sig_cmp(const void *a, const void *b)
{
	const struct sig_entry *sa = a, *sb = b;
	if (sa->sig < sb->sig) return -1;
	if (sa->sig > sb->sig) return 1;
	return 0;
}

int mfsa_merge_shared(struct mfsa *m, struct mfsa_merged *out)
{
	if (m->num_dfas == 0)
		return ZDPI_ERR_PARSE;

	memset(out, 0, sizeof(*out));

	/* Step 1: compute total states and offsets */
	uint32_t total = 0;
	uint32_t *offsets = calloc(m->num_dfas, sizeof(uint32_t));
	if (!offsets)
		return ZDPI_ERR_NOMEM;

	for (uint32_t d = 0; d < m->num_dfas; d++) {
		offsets[d] = total;
		total += m->dfas[d].num_states;
	}

	LOG_DBG("MFSA shared: %u DFAs, %u total states",
		m->num_dfas, total);

	/* Step 2: build combined transition/accept/rule arrays */
	uint32_t *trans = malloc((uint64_t)total * 256 *
				 sizeof(uint32_t));
	bool *accept = calloc(total, sizeof(bool));
	uint32_t *rule_ids = calloc(total, sizeof(uint32_t));
	uint32_t *group = malloc(total * sizeof(uint32_t));
	uint32_t *new_group = malloc(total * sizeof(uint32_t));
	struct sig_entry *sigs = malloc(total *
					sizeof(struct sig_entry));

	if (!trans || !accept || !rule_ids || !group ||
	    !new_group || !sigs) {
		free(offsets); free(trans); free(accept);
		free(rule_ids); free(group); free(new_group);
		free(sigs);
		return ZDPI_ERR_NOMEM;
	}

	for (uint32_t d = 0; d < m->num_dfas; d++) {
		uint32_t off = offsets[d];
		struct dfa *dfa = &m->dfas[d];
		for (uint32_t s = 0; s < dfa->num_states; s++) {
			uint32_t gs = off + s;
			for (int c = 0; c < 256; c++)
				trans[gs * 256 + c] =
					off + dfa->states[s].trans[c];
			accept[gs] = dfa->states[s].accept;
			rule_ids[gs] = dfa->states[s].rule_id;
		}
	}

	/* Step 3: initial partition group by (accept, rule_id).
	 * Dead states (state 0 from each DFA) get group 0. */
	uint32_t num_groups = 0;

	/* Assign initial groups: dead=0, then by (accept, rule_id) */
	/* First pass: group 0 = dead states, group 1 = non-accept */
	for (uint32_t s = 0; s < total; s++) {
		/* Dead state from each DFA: offset + 0 */
		bool is_dead = false;
		for (uint32_t d = 0; d < m->num_dfas; d++) {
			if (s == offsets[d]) {
				is_dead = true;
				break;
			}
		}
		if (is_dead)
			group[s] = 0;
		else if (!accept[s])
			group[s] = 1;
		else
			/* Accept states: hash rule_id for grouping */
			group[s] = 2 + rule_ids[s];
	}

	/* Normalize group numbers to be contiguous */
	uint32_t *gmap = calloc(total + m->num_dfas + 256,
				sizeof(uint32_t));
	if (!gmap) {
		free(offsets); free(trans); free(accept);
		free(rule_ids); free(group); free(new_group);
		free(sigs);
		return ZDPI_ERR_NOMEM;
	}

	/* Use signature sorting to assign contiguous group IDs */
	for (uint32_t s = 0; s < total; s++) {
		sigs[s].sig = group[s];
		sigs[s].state = s;
	}
	qsort(sigs, total, sizeof(struct sig_entry), sig_cmp);

	num_groups = 0;
	for (uint32_t i = 0; i < total; i++) {
		if (i == 0 || sigs[i].sig != sigs[i - 1].sig)
			num_groups++;
		group[sigs[i].state] = num_groups - 1;
	}

	free(gmap);

	/* Step 4: iterative signature refinement */
	uint32_t rounds = 0;
	for (;;) {
		/* Compute signature for each state */
		for (uint32_t s = 0; s < total; s++) {
			uint64_t h = FNV_OFFSET;
			h = fnv1a_u32(h, group[s]);
			for (int c = 0; c < 256; c++)
				h = fnv1a_u32(h,
					      group[trans[s * 256 + c]]);
			sigs[s].sig = h;
			sigs[s].state = s;
		}

		/* Sort by signature, assign new group IDs */
		qsort(sigs, total, sizeof(struct sig_entry), sig_cmp);

		uint32_t new_num = 0;
		for (uint32_t i = 0; i < total; i++) {
			if (i == 0 ||
			    sigs[i].sig != sigs[i - 1].sig)
				new_num++;
			new_group[sigs[i].state] = new_num - 1;
		}

		rounds++;
		LOG_DBG("MFSA shared: round %u, %u -> %u groups",
			rounds, num_groups, new_num);

		if (new_num == num_groups)
			break; /* converged */

		num_groups = new_num;
		memcpy(group, new_group, total * sizeof(uint32_t));

		if (rounds > 100) {
			LOG_WRN("MFSA shared: refinement did not "
				"converge after %u rounds", rounds);
			break;
		}
	}

	LOG_INF("MFSA shared: %u states -> %u groups "
		"(%.1f%% reduction) in %u rounds",
		total, num_groups,
		total > 0
		    ? (1.0 - (double)num_groups / total) * 100
		    : 0.0,
		rounds);

	/* Step 5: build merged automaton from partition groups.
	 * Pick first state in each group as representative. */
	uint32_t *repr = malloc(num_groups * sizeof(uint32_t));
	if (!repr) {
		free(offsets); free(trans); free(accept);
		free(rule_ids); free(group); free(new_group);
		free(sigs);
		return ZDPI_ERR_NOMEM;
	}
	memset(repr, 0xFF, num_groups * sizeof(uint32_t));

	for (uint32_t s = 0; s < total; s++) {
		uint32_t g = group[s];
		if (repr[g] == UINT32_MAX)
			repr[g] = s;
	}

	/* Build merged transition table */
	out->trans = malloc((uint64_t)num_groups * 256 *
			    sizeof(uint32_t));
	out->accept = calloc(num_groups, sizeof(bool));
	out->rule_ids = calloc(num_groups, sizeof(uint32_t));
	out->starts = malloc(m->num_dfas * sizeof(uint16_t));

	if (!out->trans || !out->accept || !out->rule_ids ||
	    !out->starts) {
		free(repr); free(offsets); free(trans);
		free(accept); free(rule_ids); free(group);
		free(new_group); free(sigs);
		mfsa_merged_free(out);
		return ZDPI_ERR_NOMEM;
	}

	out->num_states = num_groups;
	out->num_starts = m->num_dfas;

	for (uint32_t g = 0; g < num_groups; g++) {
		uint32_t r = repr[g];
		out->accept[g] = accept[r];
		out->rule_ids[g] = rule_ids[r];
		for (int c = 0; c < 256; c++)
			out->trans[g * 256 + c] =
				group[trans[r * 256 + c]];
	}

	/* Record start states: DFA d's start = offset[d] + 1 */
	uint32_t unique_starts = 0;
	for (uint32_t d = 0; d < m->num_dfas; d++) {
		uint32_t global_start = offsets[d] + ZDPI_START_STATE;
		out->starts[d] = (uint16_t)group[global_start];
	}

	/* Count unique start states for logging */
	bool *seen = calloc(num_groups, sizeof(bool));
	if (seen) {
		for (uint32_t d = 0; d < m->num_dfas; d++) {
			if (!seen[out->starts[d]]) {
				seen[out->starts[d]] = true;
				unique_starts++;
			}
		}
		free(seen);
	}

	LOG_INF("MFSA shared: %u start states (%u unique)",
		m->num_dfas, unique_starts);

	free(repr);
	free(offsets);
	free(trans);
	free(accept);
	free(rule_ids);
	free(group);
	free(new_group);
	free(sigs);

	return ZDPI_OK;
}

void mfsa_merged_free(struct mfsa_merged *mm)
{
	free(mm->trans);
	free(mm->accept);
	free(mm->rule_ids);
	free(mm->starts);
	memset(mm, 0, sizeof(*mm));
}
