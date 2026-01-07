/**
 * @file dfa.c
 * @brief DFA subset construction and Hopcroft minimization.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.2
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include "dfa.h"

#include <stdlib.h>
#include <string.h>

#include "zdpi_types.h"

/* ------------------------------------------------------------------ */
/*  NFA set helpers -- dynamically sized bitset                       */
/* ------------------------------------------------------------------ */

#define NFA_SET_BYTES(cap) (((cap) + 7) / 8)

/**
 * @brief Dynamically sized NFA state set (bitset).
 *
 * The number of bytes depends on the NFA capacity at build time,
 * so each nfa_set carries its own byte count.
 */
struct nfa_set {
	uint8_t *bits;
	uint32_t nbytes;
};

static bool nfa_set_init(struct nfa_set *s, uint32_t nbytes)
{
	s->bits = calloc(1, nbytes);
	if (!s->bits)
		return false;
	s->nbytes = nbytes;
	return true;
}

static void nfa_set_destroy(struct nfa_set *s)
{
	free(s->bits);
	s->bits = NULL;
	s->nbytes = 0;
}

static void nfa_set_clear(struct nfa_set *s)
{
	memset(s->bits, 0, s->nbytes);
}

static void nfa_set_add(struct nfa_set *s, uint32_t id)
{
	s->bits[id / 8] |= (1 << (id % 8));
}

static bool nfa_set_test(const struct nfa_set *s, uint32_t id)
{
	return (s->bits[id / 8] >> (id % 8)) & 1;
}

static bool nfa_set_equal(const struct nfa_set *a, const struct nfa_set *b)
{
	return memcmp(a->bits, b->bits, a->nbytes) == 0;
}

static void nfa_set_copy(struct nfa_set *dst, const struct nfa_set *src)
{
	memcpy(dst->bits, src->bits, src->nbytes);
}

static void epsilon_close(const struct nfa *nfa, struct nfa_set *set)
{
	nfa_epsilon_closure(nfa, set->bits);
}

static void nfa_set_move(const struct nfa *nfa, const struct nfa_set *from,
			 uint8_t c, struct nfa_set *to)
{
	nfa_set_clear(to);
	for (uint32_t i = 0; i < nfa->num_states; i++) {
		if (!nfa_set_test(from, i))
			continue;
		const struct nfa_state *st = &nfa->states[i];
		for (uint8_t j = 0; j < st->num_out; j++) {
			const struct nfa_trans *t = &st->out[j];
			if (t->type == NFA_TRANS_LITERAL &&
			    t->literal == c) {
				nfa_set_add(to, t->to);
			} else if (t->type == NFA_TRANS_CLASS &&
				   cc_test(&t->cclass, c)) {
				nfa_set_add(to, t->to);
			}
		}
	}
	epsilon_close(nfa, to);
}

static bool nfa_set_is_empty(const struct nfa_set *s)
{
	for (uint32_t i = 0; i < s->nbytes; i++) {
		if (s->bits[i])
			return false;
	}
	return true;
}

static bool nfa_set_has_accept(const struct nfa *nfa, const struct nfa_set *s,
			       uint32_t *rule_id)
{
	uint32_t best_rule = 0;
	bool found = false;
	for (uint32_t i = 0; i < nfa->num_states; i++) {
		if (nfa_set_test(s, i) && nfa->states[i].accept) {
			found = true;
			uint32_t rid = nfa->states[i].rule_id;
			if (!best_rule || rid < best_rule)
				best_rule = rid;
		}
	}
	if (found && rule_id)
		*rule_id = best_rule;
	return found;
}

/* ------------------------------------------------------------------ */
/*  DFA allocation / free                                             */
/* ------------------------------------------------------------------ */

int dfa_alloc(struct dfa *out, uint32_t capacity)
{
	out->states = calloc(capacity, sizeof(struct dfa_state));
	if (!out->states)
		return ZDPI_ERR_NOMEM;
	out->num_states = 0;
	out->capacity = capacity;
	return ZDPI_OK;
}

void dfa_free(struct dfa *d)
{
	free(d->states);
	d->states = NULL;
	d->num_states = 0;
	d->capacity = 0;
}

/* ------------------------------------------------------------------ */
/*  Hash table for O(1) NFA-set lookup during subset construction     */
/* ------------------------------------------------------------------ */

/*
 * FNV-1a hash over the NFA set bitset.
 * 32-bit version: offset basis 2166136261, prime 16777619.
 */
static uint32_t nfa_set_hash(const struct nfa_set *s)
{
	uint32_t h = 2166136261u;
	for (uint32_t i = 0; i < s->nbytes; i++) {
		h ^= s->bits[i];
		h *= 16777619u;
	}
	return h;
}

/*
 * Open-addressing hash table mapping NFA-set -> DFA state ID.
 * Slots store the DFA state ID (or UINT32_MAX for empty).
 * Lookup compares the hash first, then the full bitset on match.
 */
struct state_map {
	uint32_t *slots;	/* DFA state ID per slot */
	uint32_t *hashes;	/* cached hash per slot */
	uint32_t mask;		/* table_size - 1 (power of 2) */
};

static bool state_map_init(struct state_map *m, uint32_t capacity)
{
	/* Size table to ~2x capacity, rounded up to power of 2 */
	uint32_t sz = 1;
	while (sz < capacity * 2)
		sz <<= 1;
	m->slots = malloc(sz * sizeof(uint32_t));
	m->hashes = malloc(sz * sizeof(uint32_t));
	if (!m->slots || !m->hashes) {
		free(m->slots);
		free(m->hashes);
		return false;
	}
	m->mask = sz - 1;
	memset(m->slots, 0xFF, sz * sizeof(uint32_t));
	return true;
}

static void state_map_destroy(struct state_map *m)
{
	free(m->slots);
	free(m->hashes);
}

static void state_map_insert(struct state_map *m, uint32_t hash,
			     uint32_t dfa_id)
{
	uint32_t idx = hash & m->mask;
	while (m->slots[idx] != UINT32_MAX)
		idx = (idx + 1) & m->mask;
	m->slots[idx] = dfa_id;
	m->hashes[idx] = hash;
}

/*
 * Look up an NFA set in the hash table.
 * Returns the DFA state ID if found, UINT32_MAX if not.
 */
static uint32_t state_map_find(const struct state_map *m,
			       const struct nfa_set *key,
			       uint32_t hash,
			       const struct nfa_set *dfa_sets)
{
	uint32_t idx = hash & m->mask;
	while (m->slots[idx] != UINT32_MAX) {
		if (m->hashes[idx] == hash &&
		    nfa_set_equal(&dfa_sets[m->slots[idx]], key))
			return m->slots[idx];
		idx = (idx + 1) & m->mask;
	}
	return UINT32_MAX;
}

/* ------------------------------------------------------------------ */
/*  Subset construction                                               */
/* ------------------------------------------------------------------ */

int dfa_build(const struct nfa *nfa, struct dfa *out)
{
	uint32_t nbytes = NFA_SET_BYTES(nfa->capacity);

	struct nfa_set *dfa_sets = calloc(out->capacity,
					  sizeof(struct nfa_set));
	if (!dfa_sets)
		return ZDPI_ERR_NOMEM;

	for (uint32_t i = 0; i < out->capacity; i++) {
		dfa_sets[i].bits = NULL;
		dfa_sets[i].nbytes = nbytes;
	}

	uint32_t *worklist = malloc(out->capacity * sizeof(uint32_t));
	if (!worklist) {
		free(dfa_sets);
		return ZDPI_ERR_NOMEM;
	}

	struct state_map smap;
	if (!state_map_init(&smap, out->capacity)) {
		free(worklist);
		free(dfa_sets);
		return ZDPI_ERR_NOMEM;
	}

	int rc = ZDPI_OK;

	/* State 0: dead state (all transitions to self) */
	dfa_sets[0].bits = calloc(1, nbytes);
	if (!dfa_sets[0].bits) {
		rc = ZDPI_ERR_NOMEM;
		goto cleanup;
	}
	dfa_sets[0].nbytes = nbytes;
	memset(&out->states[0], 0, sizeof(struct dfa_state));
	for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++)
		out->states[0].trans[c] = ZDPI_DEAD_STATE;
	out->num_states = 1;
	state_map_insert(&smap, nfa_set_hash(&dfa_sets[0]), 0);

	/* State 1: start = epsilon-closure({nfa->start}) */
	dfa_sets[1].bits = calloc(1, nbytes);
	if (!dfa_sets[1].bits) {
		rc = ZDPI_ERR_NOMEM;
		goto cleanup;
	}
	dfa_sets[1].nbytes = nbytes;
	nfa_set_add(&dfa_sets[1], nfa->start);
	epsilon_close(nfa, &dfa_sets[1]);
	memset(&out->states[1], 0, sizeof(struct dfa_state));
	out->states[1].accept = nfa_set_has_accept(nfa, &dfa_sets[1],
						    &out->states[1].rule_id);
	out->num_states = 2;
	state_map_insert(&smap, nfa_set_hash(&dfa_sets[1]), 1);

	uint32_t wl_head = 0, wl_tail = 0;
	worklist[wl_tail++] = 1;

	struct nfa_set move_result;
	if (!nfa_set_init(&move_result, nbytes)) {
		rc = ZDPI_ERR_NOMEM;
		goto cleanup;
	}

	while (wl_head < wl_tail) {
		uint32_t cur = worklist[wl_head++];

		for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
			nfa_set_move(nfa, &dfa_sets[cur], (uint8_t)c,
				     &move_result);

			if (nfa_set_is_empty(&move_result)) {
				out->states[cur].trans[c] = ZDPI_DEAD_STATE;
				continue;
			}

			uint32_t h = nfa_set_hash(&move_result);
			uint32_t found = state_map_find(&smap,
							&move_result, h,
							dfa_sets);

			if (found != UINT32_MAX) {
				out->states[cur].trans[c] = found;
			} else {
				if (out->num_states >= out->capacity) {
					rc = ZDPI_ERR_OVERFLOW;
					nfa_set_destroy(&move_result);
					goto cleanup;
				}
				uint32_t id = out->num_states++;
				dfa_sets[id].bits = calloc(1, nbytes);
				if (!dfa_sets[id].bits) {
					rc = ZDPI_ERR_NOMEM;
					nfa_set_destroy(&move_result);
					goto cleanup;
				}
				dfa_sets[id].nbytes = nbytes;
				nfa_set_copy(&dfa_sets[id],
					     &move_result);
				memset(&out->states[id], 0,
				       sizeof(struct dfa_state));
				out->states[id].accept =
					nfa_set_has_accept(
						nfa, &move_result,
						&out->states[id]
							 .rule_id);
				out->states[cur].trans[c] = id;
				worklist[wl_tail++] = id;
				state_map_insert(&smap, h, id);
			}
		}
	}

	nfa_set_destroy(&move_result);

cleanup:
	for (uint32_t i = 0; i < out->capacity; i++)
		free(dfa_sets[i].bits);
	free(dfa_sets);
	free(worklist);
	state_map_destroy(&smap);
	return rc;
}

/* ------------------------------------------------------------------ */
/*  Hopcroft minimization                                             */
/* ------------------------------------------------------------------ */

int dfa_minimize(struct dfa *d)
{
	if (d->num_states <= 2)
		return ZDPI_OK;

	uint32_t n = d->num_states;
	uint32_t *partition = calloc(n, sizeof(uint32_t));
	if (!partition)
		return ZDPI_ERR_NOMEM;

	/* Initial partition: non-accept (0) vs accept (1) */
	uint32_t num_groups = 2;
	for (uint32_t i = 0; i < n; i++)
		partition[i] = d->states[i].accept ? 1 : 0;

	/* Keep dead state in group 0 */
	partition[0] = 0;

	bool changed = true;
	while (changed) {
		changed = false;

		for (uint32_t g = 0; g < num_groups; g++) {
			/* Find first state in group */
			uint32_t rep = UINT32_MAX;
			for (uint32_t i = 0; i < n; i++) {
				if (partition[i] == g) {
					rep = i;
					break;
				}
			}
			if (rep == UINT32_MAX)
				continue;

			/* Split: find states that differ from rep */
			for (uint32_t i = rep + 1; i < n; i++) {
				if (partition[i] != g)
					continue;

				bool differs = false;
				for (int c = 0; c < ZDPI_ALPHABET_SIZE;
				     c++) {
					uint32_t t1 = d->states[rep].trans[c];
					uint32_t t2 = d->states[i].trans[c];
					if (partition[t1] !=
					    partition[t2]) {
						differs = true;
						break;
					}
				}

				/* Different rule_id also splits */
				if (!differs &&
				    d->states[rep].rule_id !=
					    d->states[i].rule_id)
					differs = true;

				if (differs) {
					partition[i] = num_groups;
					changed = true;
				}
			}
			if (changed) {
				num_groups++;
				break;
			}
		}
	}

	/* Build minimized DFA */
	struct dfa_state *new_states =
		calloc(num_groups, sizeof(struct dfa_state));
	if (!new_states) {
		free(partition);
		return ZDPI_ERR_NOMEM;
	}

	/* Map each group to its representative */
	for (uint32_t g = 0; g < num_groups; g++) {
		for (uint32_t i = 0; i < n; i++) {
			if (partition[i] == g) {
				new_states[g] = d->states[i];
				for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
					new_states[g].trans[c] =
						partition[d->states[i]
								  .trans[c]];
				}
				break;
			}
		}
	}

	/* Ensure state 0 is dead and state 1 is start */
	uint32_t dead_group = partition[0];
	uint32_t start_group = partition[1];

	if (dead_group != 0 || start_group != 1) {
		/* Remap: swap groups so dead=0, start=1 */
		uint32_t *remap = calloc(num_groups, sizeof(uint32_t));
		if (!remap) {
			free(new_states);
			free(partition);
			return ZDPI_ERR_NOMEM;
		}

		for (uint32_t g = 0; g < num_groups; g++)
			remap[g] = g;
		remap[dead_group] = 0;
		remap[0] = dead_group;

		if (remap[start_group] != 1) {
			uint32_t tmp = remap[start_group];
			uint32_t cur1 = 1;
			for (uint32_t g = 0; g < num_groups; g++) {
				if (remap[g] == 1)
					cur1 = g;
			}
			remap[start_group] = 1;
			remap[cur1] = tmp;
		}

		struct dfa_state *remapped =
			calloc(num_groups, sizeof(struct dfa_state));
		if (!remapped) {
			free(remap);
			free(new_states);
			free(partition);
			return ZDPI_ERR_NOMEM;
		}

		for (uint32_t g = 0; g < num_groups; g++) {
			remapped[remap[g]] = new_states[g];
			for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++)
				remapped[remap[g]].trans[c] =
					remap[new_states[g].trans[c]];
		}

		free(new_states);
		new_states = remapped;
		free(remap);
	}

	free(d->states);
	d->states = new_states;
	d->num_states = num_groups;
	d->capacity = num_groups;

	free(partition);
	return ZDPI_OK;
}

/* ------------------------------------------------------------------ */
/*  Union product construction                                        */
/* ------------------------------------------------------------------ */

/*
 * Merge two DFAs into one recognizing L(a) ∪ L(b).
 *
 * Product state (sa, sb) transitions to (δ_a(sa,c), δ_b(sb,c)).
 * Accept if sa ∈ F_a OR sb ∈ F_b.
 *
 * Uses BFS from start state (1,1) to build only reachable states.
 * State 0 = dead = (0,0), State 1 = start = (1,1).
 */
int dfa_product_union(const struct dfa *a, const struct dfa *b,
		      struct dfa *out)
{
	uint32_t na = a->num_states;
	uint32_t nb = b->num_states;
	uint64_t max_product = (uint64_t)na * nb;

	/* Sanity: if product could be huge, cap initial allocation */
	uint32_t init_cap = 4096;
	if (max_product < init_cap)
		init_cap = (uint32_t)max_product;

	/* State map: (sa, sb) -> product state ID.
	 * Use flat array if small enough, else hash map. */
	uint32_t *state_map = NULL;
	bool use_flat = (max_product <= 4194304); /* 4M entries */

	if (use_flat) {
		state_map = malloc(max_product * sizeof(uint32_t));
		if (!state_map)
			return ZDPI_ERR_NOMEM;
		memset(state_map, 0xFF, max_product * sizeof(uint32_t));
	} else {
		/* For very large products, we shouldn't even try */
		return ZDPI_ERR_NOMEM;
	}

	/* BFS queue */
	uint32_t *queue = malloc(init_cap * 2 * sizeof(uint32_t));
	if (!queue) {
		free(state_map);
		return ZDPI_ERR_NOMEM;
	}
	uint32_t q_cap = init_cap * 2;

	int rc = dfa_alloc(out, init_cap);
	if (rc) {
		free(queue);
		free(state_map);
		return rc;
	}

	/* State 0: dead = (0,0) */
	uint32_t dead_pair = 0; /* 0 * nb + 0 */
	state_map[dead_pair] = 0;
	memset(&out->states[0], 0, sizeof(struct dfa_state));
	for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++)
		out->states[0].trans[c] = 0;
	out->states[0].accept = false;
	out->num_states = 1;

	/* State 1: start = (1,1) */
	uint32_t start_pair = 1 * nb + 1;
	state_map[start_pair] = 1;
	memset(&out->states[1], 0, sizeof(struct dfa_state));
	out->states[1].accept =
		a->states[1].accept || b->states[1].accept;
	if (a->states[1].accept)
		out->states[1].rule_id = a->states[1].rule_id;
	else if (b->states[1].accept)
		out->states[1].rule_id = b->states[1].rule_id;
	out->num_states = 2;

	uint32_t qh = 0, qt = 0;
	queue[qt++] = start_pair;

	while (qh < qt) {
		uint32_t pair = queue[qh++];
		uint32_t sa = pair / nb;
		uint32_t sb = pair % nb;
		uint32_t pid = state_map[pair];

		for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
			uint32_t ta = a->states[sa].trans[c];
			uint32_t tb = b->states[sb].trans[c];
			uint32_t next_pair = ta * nb + tb;

			if (state_map[next_pair] != UINT32_MAX) {
				out->states[pid].trans[c] =
					state_map[next_pair];
				continue;
			}

			/* New product state */
			if (out->num_states >= out->capacity) {
				/* Grow */
				uint32_t new_cap = out->capacity * 2;
				if (new_cap > ZDPI_MAX_STATES)
					new_cap = ZDPI_MAX_STATES;
				if (out->num_states >= new_cap) {
					free(queue);
					free(state_map);
					dfa_free(out);
					return ZDPI_ERR_NOMEM;
				}
				struct dfa_state *ns = realloc(
					out->states,
					new_cap * sizeof(struct dfa_state));
				if (!ns) {
					free(queue);
					free(state_map);
					dfa_free(out);
					return ZDPI_ERR_NOMEM;
				}
				out->states = ns;
				out->capacity = new_cap;
			}

			/* Grow queue if needed */
			if (qt >= q_cap) {
				q_cap *= 2;
				uint32_t *nq = realloc(
					queue, q_cap * sizeof(uint32_t));
				if (!nq) {
					free(queue);
					free(state_map);
					dfa_free(out);
					return ZDPI_ERR_NOMEM;
				}
				queue = nq;
			}

			uint32_t nid = out->num_states++;
			state_map[next_pair] = nid;
			memset(&out->states[nid], 0,
			       sizeof(struct dfa_state));
			out->states[nid].accept =
				a->states[ta].accept ||
				b->states[tb].accept;
			if (a->states[ta].accept)
				out->states[nid].rule_id =
					a->states[ta].rule_id;
			else if (b->states[tb].accept)
				out->states[nid].rule_id =
					b->states[tb].rule_id;

			out->states[pid].trans[c] = nid;
			queue[qt++] = next_pair;
		}
	}

	free(queue);
	free(state_map);
	return ZDPI_OK;
}

/* ------------------------------------------------------------------ */
/*  Simulation                                                        */
/* ------------------------------------------------------------------ */

bool dfa_simulate(const struct dfa *d, const uint8_t *input, uint32_t len,
		  uint32_t *rule_out)
{
	uint32_t state = ZDPI_START_STATE;

	for (uint32_t i = 0; i < len; i++) {
		state = d->states[state].trans[input[i]];
		if (state == ZDPI_DEAD_STATE)
			return false;
	}

	if (d->states[state].accept) {
		if (rule_out)
			*rule_out = d->states[state].rule_id;
		return true;
	}
	return false;
}
