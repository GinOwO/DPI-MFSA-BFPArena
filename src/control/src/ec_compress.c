/**
 * @file ec_compress.c
 * @brief Equivalence class compression for DFA transition tables.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.2
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include "ec_compress.h"

#include <stdlib.h>
#include <string.h>

#include "zdpi_types.h"

int ec_compute(const struct dfa *d, struct ec_map *out)
{
	memset(out, 0, sizeof(*out));

	uint8_t assigned[ZDPI_ALPHABET_SIZE];
	memset(assigned, 0xFF, sizeof(assigned));

	uint32_t next_ec = 0;

	for (int a = 0; a < ZDPI_ALPHABET_SIZE; a++) {
		if (assigned[a] != 0xFF)
			continue;

		assigned[a] = (uint8_t)next_ec;
		out->byte_to_ec[a] = (uint8_t)next_ec;

		for (int b = a + 1; b < ZDPI_ALPHABET_SIZE; b++) {
			if (assigned[b] != 0xFF)
				continue;

			bool same = true;
			for (uint32_t s = 0; s < d->num_states; s++) {
				if (d->states[s].trans[a] !=
				    d->states[s].trans[b]) {
					same = false;
					break;
				}
			}

			if (same) {
				assigned[b] = (uint8_t)next_ec;
				out->byte_to_ec[b] = (uint8_t)next_ec;
			}
		}

		next_ec++;
		if (next_ec > ZDPI_MAX_EC)
			return ZDPI_ERR_OVERFLOW;
	}

	out->num_ec = next_ec;
	return ZDPI_OK;
}

int ec_compute_multi(const struct dfa **dfas, uint32_t num_dfas,
		     struct ec_map *out)
{
	if (num_dfas == 0)
		return ZDPI_ERR_PARSE;
	if (num_dfas == 1)
		return ec_compute(dfas[0], out);

	memset(out, 0, sizeof(*out));

	uint8_t assigned[ZDPI_ALPHABET_SIZE];
	memset(assigned, 0xFF, sizeof(assigned));

	uint32_t next_ec = 0;

	for (int a = 0; a < ZDPI_ALPHABET_SIZE; a++) {
		if (assigned[a] != 0xFF)
			continue;

		assigned[a] = (uint8_t)next_ec;
		out->byte_to_ec[a] = (uint8_t)next_ec;

		for (int b = a + 1; b < ZDPI_ALPHABET_SIZE; b++) {
			if (assigned[b] != 0xFF)
				continue;

			bool same = true;
			for (uint32_t di = 0; di < num_dfas && same; di++) {
				const struct dfa *d = dfas[di];
				for (uint32_t s = 0; s < d->num_states;
				     s++) {
					if (d->states[s].trans[a] !=
					    d->states[s].trans[b]) {
						same = false;
						break;
					}
				}
			}

			if (same) {
				assigned[b] = (uint8_t)next_ec;
				out->byte_to_ec[b] = (uint8_t)next_ec;
			}
		}

		next_ec++;
		if (next_ec > ZDPI_MAX_EC)
			return ZDPI_ERR_OVERFLOW;
	}

	out->num_ec = next_ec;
	return ZDPI_OK;
}

int ec_table_build(const struct dfa *d, const struct ec_map *ec,
		   struct ec_table *out)
{
	memset(out, 0, sizeof(*out));

	uint32_t n = d->num_states;
	uint32_t nec = ec->num_ec;

	out->table = calloc((size_t)n * nec, sizeof(uint32_t));
	out->accept = calloc(n, sizeof(bool));
	out->rule_ids = calloc(n, sizeof(uint32_t));
	if (!out->table || !out->accept || !out->rule_ids) {
		ec_table_free(out);
		return ZDPI_ERR_NOMEM;
	}

	out->num_states = n;
	out->num_ec = nec;

	uint8_t ec_rep[ZDPI_MAX_EC];
	memset(ec_rep, 0, sizeof(ec_rep));
	for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
		ec_rep[ec->byte_to_ec[c]] = (uint8_t)c;
	}

	for (uint32_t s = 0; s < n; s++) {
		for (uint32_t e = 0; e < nec; e++) {
			uint8_t rep = ec_rep[e];
			out->table[s * nec + e] =
				d->states[s].trans[rep];
		}
		out->accept[s] = d->states[s].accept;
		out->rule_ids[s] = d->states[s].rule_id;
	}

	return ZDPI_OK;
}

int ec_compute_raw(const uint32_t *trans, uint32_t num_states,
		   struct ec_map *out)
{
	memset(out, 0, sizeof(*out));

	uint8_t assigned[ZDPI_ALPHABET_SIZE];
	memset(assigned, 0xFF, sizeof(assigned));

	uint32_t next_ec = 0;

	for (int a = 0; a < ZDPI_ALPHABET_SIZE; a++) {
		if (assigned[a] != 0xFF)
			continue;

		assigned[a] = (uint8_t)next_ec;
		out->byte_to_ec[a] = (uint8_t)next_ec;

		for (int b = a + 1; b < ZDPI_ALPHABET_SIZE; b++) {
			if (assigned[b] != 0xFF)
				continue;

			bool same = true;
			for (uint32_t s = 0; s < num_states; s++) {
				if (trans[s * 256 + a] !=
				    trans[s * 256 + b]) {
					same = false;
					break;
				}
			}

			if (same) {
				assigned[b] = (uint8_t)next_ec;
				out->byte_to_ec[b] = (uint8_t)next_ec;
			}
		}

		next_ec++;
		if (next_ec > ZDPI_MAX_EC)
			return ZDPI_ERR_OVERFLOW;
	}

	out->num_ec = next_ec;
	return ZDPI_OK;
}

void ec_table_free(struct ec_table *t)
{
	free(t->table);
	free(t->accept);
	free(t->rule_ids);
	memset(t, 0, sizeof(*t));
}
