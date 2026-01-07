/**
 * @file linearize.c
 * @brief DFA table linearization into BPF arena binary format.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.1
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include "linearize.h"

#include <stdlib.h>
#include <string.h>

int linearize(const struct ec_map *ec_map, const struct ec_table *table,
	      struct arena_blob *out)
{
	memset(out, 0, sizeof(*out));

	uint32_t num_states = table->num_states;
	uint32_t num_ec = table->num_ec;

	/* Compute sizes */
	uint32_t table_size = num_states * num_ec * sizeof(uint32_t);
	uint32_t accept_size = (num_states + 7) / 8;
	uint32_t rule_id_size = num_states * sizeof(uint32_t);

	uint32_t table_offset = ZDPI_TABLE_OFFSET;
	uint32_t accept_offset = table_offset + table_size;
	uint32_t rule_id_offset = accept_offset + accept_size;
	uint32_t total_size = rule_id_offset + rule_id_size;

	/* Align total to page boundary */
	total_size = (total_size + ZDPI_ARENA_PAGE_SIZE - 1) &
		     ~(ZDPI_ARENA_PAGE_SIZE - 1);

	out->data = calloc(1, total_size);
	if (!out->data)
		return ZDPI_ERR_NOMEM;

	out->size = total_size;

	/* Fill header */
	struct zdpi_table_header *hdr =
		(struct zdpi_table_header *)out->data;
	hdr->magic = ZDPI_MAGIC;
	hdr->version_major = 0;
	hdr->version_minor = 0;
	hdr->version_patch = 1;
	hdr->num_states = num_states;
	hdr->num_ec = (uint16_t)num_ec;
	hdr->num_rules = 0;
	hdr->table_offset = table_offset;
	hdr->table_size = table_size;
	hdr->accept_offset = accept_offset;
	hdr->accept_size = accept_size;
	hdr->rule_id_offset = rule_id_offset;
	hdr->rule_id_size = rule_id_size;
	hdr->total_size = total_size;
	hdr->table_ready = 1;

	out->header = *hdr;

	/* Copy EC map */
	memcpy(out->data + ZDPI_EC_MAP_OFFSET, ec_map->byte_to_ec,
	       ZDPI_EC_MAP_SIZE);

	/* Copy transition table */
	memcpy(out->data + table_offset, table->table, table_size);

	/* Pack accept bitset */
	uint8_t *accept_bits = out->data + accept_offset;
	for (uint32_t s = 0; s < num_states; s++) {
		if (table->accept[s])
			accept_bits[s / 8] |= (1 << (s % 8));
	}

	/* Copy rule IDs */
	memcpy(out->data + rule_id_offset, table->rule_ids, rule_id_size);

	return ZDPI_OK;
}

int linearize_parallel(const struct ec_map *ec_map,
		       const struct ec_table *tables, uint32_t num_dfas,
		       const uint32_t *rule_ids, struct arena_blob *out)
{
	memset(out, 0, sizeof(*out));

	if (num_dfas == 0 || num_dfas > ZDPI_MAX_PARALLEL_DFAS)
		return ZDPI_ERR_OVERFLOW;

	uint16_t num_ec = (uint16_t)tables[0].num_ec;

	/* Compute directory + per-DFA data sizes */
	uint32_t dir_size = num_dfas * ZDPI_DFA_DIR_ENTRY_SIZE;
	uint32_t dir_offset = ZDPI_DFA_DIR_OFFSET;

	/* Align data start to 64-byte boundary after directory */
	uint32_t data_start = dir_offset + dir_size;
	data_start = (data_start + ZDPI_TABLE_ALIGN - 1) &
		     ~(ZDPI_TABLE_ALIGN - 1);

	/* Compute offsets for each DFA's table + accept bits */
	uint32_t cursor = data_start;
	uint32_t *table_offsets = calloc(num_dfas, sizeof(uint32_t));
	uint32_t *accept_offsets = calloc(num_dfas, sizeof(uint32_t));
	if (!table_offsets || !accept_offsets) {
		free(table_offsets);
		free(accept_offsets);
		return ZDPI_ERR_NOMEM;
	}

	for (uint32_t i = 0; i < num_dfas; i++) {
		uint32_t ns = tables[i].num_states;
		uint32_t tbl_sz = ns * num_ec * sizeof(uint16_t);
		uint32_t acc_sz = (ns + 7) / 8;

		table_offsets[i] = cursor;
		cursor += tbl_sz;
		accept_offsets[i] = cursor;
		cursor += acc_sz;

		/* Align next DFA to 4 bytes */
		cursor = (cursor + 3) & ~3u;
	}

	uint32_t total_size = (cursor + ZDPI_ARENA_PAGE_SIZE - 1) &
			      ~(ZDPI_ARENA_PAGE_SIZE - 1);

	out->data = calloc(1, total_size);
	if (!out->data) {
		free(table_offsets);
		free(accept_offsets);
		return ZDPI_ERR_NOMEM;
	}
	out->size = total_size;

	/* Fill v2 header */
	struct zdpi_table_header_v2 *hdr =
		(struct zdpi_table_header_v2 *)out->data;
	hdr->magic = ZDPI_MAGIC;
	hdr->version_major = 0;
	hdr->version_minor = 1;
	hdr->num_ec = num_ec;
	hdr->num_dfas = (uint16_t)num_dfas;
	hdr->dfa_dir_offset = dir_offset;
	hdr->ec_map_offset = ZDPI_EC_MAP_V2_OFFSET;
	hdr->total_size = total_size;
	hdr->table_ready = 1;

	/* Copy v1 header fields for backward compat logging */
	out->header.magic = ZDPI_MAGIC;
	out->header.version_major = 0;
	out->header.version_minor = 1;
	out->header.num_ec = num_ec;
	out->header.total_size = total_size;
	out->header.table_ready = 1;

	/* Copy shared EC map */
	memcpy(out->data + ZDPI_EC_MAP_V2_OFFSET,
	       ec_map->byte_to_ec, ZDPI_EC_MAP_SIZE);

	/* Fill DFA directory and per-DFA data */
	struct zdpi_dfa_dir_entry *dir =
		(struct zdpi_dfa_dir_entry *)(out->data + dir_offset);

	for (uint32_t i = 0; i < num_dfas; i++) {
		uint32_t ns = tables[i].num_states;

		dir[i].table_offset = table_offsets[i];
		dir[i].accept_offset = accept_offsets[i];
		dir[i].num_states = (uint16_t)ns;
		dir[i].rule_id = (uint16_t)rule_ids[i];

		/* Copy transition table as uint16_t */
		uint16_t *dst = (uint16_t *)(out->data +
					     table_offsets[i]);
		for (uint32_t s = 0; s < ns; s++) {
			for (uint32_t e = 0; e < num_ec; e++) {
				dst[s * num_ec + e] =
					(uint16_t)tables[i]
						.table[s * num_ec + e];
			}
		}

		/* Pack accept bitset */
		uint8_t *acc = out->data + accept_offsets[i];
		for (uint32_t s = 0; s < ns; s++) {
			if (tables[i].accept[s])
				acc[s / 8] |= (1 << (s % 8));
		}
	}

	free(table_offsets);
	free(accept_offsets);
	return ZDPI_OK;
}

int linearize_parallel_simulate(const struct arena_blob *blob,
				const uint8_t *input, uint32_t len)
{
	const struct zdpi_table_header_v2 *hdr =
		(const struct zdpi_table_header_v2 *)blob->data;

	if (hdr->magic != ZDPI_MAGIC || !hdr->table_ready)
		return ZDPI_ACTION_PASS;
	if (hdr->version_minor != 1)
		return ZDPI_ACTION_PASS;

	uint16_t num_ec = hdr->num_ec;
	uint16_t num_dfas = hdr->num_dfas;

	const uint8_t *ecm = blob->data + hdr->ec_map_offset;
	const struct zdpi_dfa_dir_entry *dir =
		(const struct zdpi_dfa_dir_entry *)(blob->data +
						    hdr->dfa_dir_offset);

	/* Initialize per-DFA state */
	uint16_t *states = calloc(num_dfas, sizeof(uint16_t));
	if (!states)
		return ZDPI_ACTION_PASS;
	for (uint16_t i = 0; i < num_dfas; i++)
		states[i] = ZDPI_START_STATE;

	for (uint32_t byte_i = 0; byte_i < len; byte_i++) {
		uint8_t ec = ecm[input[byte_i]];
		if (ec >= num_ec)
			break;

		for (uint16_t di = 0; di < num_dfas; di++) {
			if (states[di] == ZDPI_DEAD_STATE)
				continue;

			const uint16_t *tbl =
				(const uint16_t *)(blob->data +
						   dir[di].table_offset);
			uint16_t ns = dir[di].num_states;

			if (states[di] >= ns) {
				states[di] = ZDPI_DEAD_STATE;
				continue;
			}

			states[di] =
				tbl[states[di] * num_ec + ec];

			if (states[di] != ZDPI_DEAD_STATE &&
			    states[di] < ns) {
				const uint8_t *acc =
					blob->data +
					dir[di].accept_offset;
				if (acc[states[di] / 8] &
				    (1 << (states[di] % 8))) {
					free(states);
					return ZDPI_ACTION_DROP;
				}
			}
		}
	}

	free(states);
	return ZDPI_ACTION_PASS;
}

int linearize_mfsa(const struct ec_map *ec_map,
		   const struct mfsa_merged *merged,
		   struct arena_blob *out)
{
	memset(out, 0, sizeof(*out));

	uint32_t ns = merged->num_states;
	uint32_t ne = ec_map->num_ec;
	uint32_t nstarts = merged->num_starts;

	/* Compute layout */
	uint32_t starts_offset = ZDPI_STARTS_V3_OFFSET;
	uint32_t starts_size = nstarts * sizeof(uint16_t);

	/* Align table to 64 bytes */
	uint32_t table_offset = starts_offset + starts_size;
	table_offset = (table_offset + ZDPI_TABLE_ALIGN - 1) &
		       ~(ZDPI_TABLE_ALIGN - 1);

	uint32_t table_size = ns * ne * sizeof(uint16_t);
	uint32_t accept_offset = table_offset + table_size;
	uint32_t accept_size = (ns + 7) / 8;
	uint32_t rule_id_offset = accept_offset + accept_size;
	/* Align rule_id to 4 bytes */
	rule_id_offset = (rule_id_offset + 3) & ~3u;
	uint32_t rule_id_size = ns * sizeof(uint32_t);
	uint32_t total_size = rule_id_offset + rule_id_size;

	/* Page-align */
	total_size = (total_size + ZDPI_ARENA_PAGE_SIZE - 1) &
		     ~(ZDPI_ARENA_PAGE_SIZE - 1);

	out->data = calloc(1, total_size);
	if (!out->data)
		return ZDPI_ERR_NOMEM;
	out->size = total_size;

	/* Fill v3 header */
	struct zdpi_table_header_v3 *hdr =
		(struct zdpi_table_header_v3 *)out->data;
	hdr->magic = ZDPI_MAGIC;
	hdr->version_major = 0;
	hdr->version_minor = 2;
	hdr->num_ec = (uint16_t)ne;
	hdr->num_starts = (uint16_t)nstarts;
	hdr->num_states = ns;
	hdr->starts_offset = starts_offset;
	hdr->table_offset = table_offset;
	hdr->accept_offset = accept_offset;
	hdr->rule_id_offset = rule_id_offset;
	hdr->total_size = total_size;
	hdr->table_ready = 1;

	/* Backward compat header copy */
	out->header.magic = ZDPI_MAGIC;
	out->header.version_major = 0;
	out->header.version_minor = 2;
	out->header.num_ec = (uint16_t)ne;
	out->header.num_states = ns;
	out->header.total_size = total_size;
	out->header.table_ready = 1;

	/* Copy EC map */
	memcpy(out->data + ZDPI_EC_MAP_V3_OFFSET,
	       ec_map->byte_to_ec, ZDPI_EC_MAP_SIZE);

	/* Copy start states */
	uint16_t *starts = (uint16_t *)(out->data + starts_offset);
	for (uint32_t i = 0; i < nstarts; i++)
		starts[i] = merged->starts[i];

	/* Build EC-compressed transition table (uint16_t) */
	uint16_t *tbl = (uint16_t *)(out->data + table_offset);
	for (uint32_t s = 0; s < ns; s++) {
		for (uint32_t e = 0; e < ne; e++) {
			/* Find any byte mapping to this EC */
			uint32_t next = ZDPI_DEAD_STATE;
			for (int c = 0; c < 256; c++) {
				if (ec_map->byte_to_ec[c] == e) {
					next = merged->trans[s * 256 + c];
					break;
				}
			}
			tbl[s * ne + e] = (uint16_t)next;
		}
	}

	/* Pack accept bitset */
	uint8_t *acc = out->data + accept_offset;
	for (uint32_t s = 0; s < ns; s++) {
		if (merged->accept[s])
			acc[s / 8] |= (1 << (s % 8));
	}

	/* Copy rule IDs */
	uint32_t *rids = (uint32_t *)(out->data + rule_id_offset);
	memcpy(rids, merged->rule_ids, ns * sizeof(uint32_t));

	return ZDPI_OK;
}

int linearize_mfsa_simulate(const struct arena_blob *blob,
			    const uint8_t *input, uint32_t len)
{
	const struct zdpi_table_header_v3 *hdr =
		(const struct zdpi_table_header_v3 *)blob->data;

	if (hdr->magic != ZDPI_MAGIC || !hdr->table_ready)
		return ZDPI_ACTION_PASS;
	if (hdr->version_minor != 2)
		return ZDPI_ACTION_PASS;

	uint16_t ne = hdr->num_ec;
	uint16_t nstarts = hdr->num_starts;
	uint32_t ns = hdr->num_states;

	const uint8_t *ecm = blob->data + ZDPI_EC_MAP_V3_OFFSET;
	const uint16_t *starts =
		(const uint16_t *)(blob->data + hdr->starts_offset);
	const uint16_t *tbl =
		(const uint16_t *)(blob->data + hdr->table_offset);
	const uint8_t *acc = blob->data + hdr->accept_offset;

	/* Active state bitset */
	uint32_t bitset_bytes = (ns + 7) / 8;
	uint8_t *active = calloc(1, bitset_bytes);
	uint8_t *next_active = calloc(1, bitset_bytes);
	uint8_t *start_mask = calloc(1, bitset_bytes);
	if (!active || !next_active || !start_mask) {
		free(active); free(next_active); free(start_mask);
		return ZDPI_ACTION_PASS;
	}

	/* Initialize start mask */
	for (uint16_t i = 0; i < nstarts; i++) {
		uint16_t s = starts[i];
		if (s < ns)
			start_mask[s / 8] |= (1 << (s % 8));
	}

	/* Start with all start states active */
	memcpy(active, start_mask, bitset_bytes);

	for (uint32_t byte_i = 0; byte_i < len; byte_i++) {
		uint8_t ec = ecm[input[byte_i]];
		if (ec >= ne)
			break;

		memset(next_active, 0, bitset_bytes);

		for (uint32_t s = 0; s < ns; s++) {
			if (!(active[s / 8] & (1 << (s % 8))))
				continue;

			uint16_t next = tbl[s * ne + ec];
			if (next < ns) {
				next_active[next / 8] |=
					(1 << (next % 8));

				/* Check accept */
				if (acc[next / 8] &
				    (1 << (next % 8))) {
					free(active);
					free(next_active);
					free(start_mask);
					return ZDPI_ACTION_DROP;
				}
			}
		}

		/* Re-add start states (unanchored matching) */
		for (uint32_t i = 0;
		     i < bitset_bytes / sizeof(uint64_t); i++)
			((uint64_t *)next_active)[i] |=
				((uint64_t *)start_mask)[i];
		/* Handle remaining bytes */
		for (uint32_t i = (bitset_bytes / 8) * 8;
		     i < bitset_bytes; i++)
			next_active[i] |= start_mask[i];

		/* Swap */
		uint8_t *tmp = active;
		active = next_active;
		next_active = tmp;
	}

	free(active);
	free(next_active);
	free(start_mask);
	return ZDPI_ACTION_PASS;
}

int linearize_v4(const struct ec_map *ac_ecm,
		 const struct ec_table *ac_table,
		 const struct ac_match_info *match_info,
		 const struct ec_map *mfsa_ecm,
		 const struct ec_table *mfsa_tables,
		 uint32_t num_mfsa_dfas,
		 const uint32_t *rule_ids,
		 const uint16_t *always_run_indices,
		 uint32_t always_run_count,
		 struct arena_blob *out)
{
	memset(out, 0, sizeof(*out));

	uint32_t ac_ns = ac_table->num_states;
	uint32_t ac_ne = ac_table->num_ec;
	uint16_t mfsa_ne = mfsa_tables ? (uint16_t)mfsa_tables[0].num_ec : 0;

	/* --- Compute AC section layout --- */
	uint32_t ac_ec_offset = ZDPI_HEADER_V4_SIZE;		/* 128 */
	uint32_t ac_table_offset = ac_ec_offset + ZDPI_EC_MAP_SIZE; /* 384 */
	/* AC table uses uint16_t entries states always fit in 16 bits
	 * (AC DFA for 1000 ET rules has ~7K states).  Halves table size
	 * for better cache performance in XDP. */
	uint32_t ac_table_size = ac_ns * ac_ne * sizeof(uint16_t);
	uint32_t ac_accept_offset = ac_table_offset + ac_table_size;
	uint32_t ac_accept_size = (ac_ns + 7) / 8;
	uint32_t ac_matchdir_offset = ac_accept_offset + ac_accept_size;
	/* Align matchdir to 4B */
	ac_matchdir_offset = (ac_matchdir_offset + 3) & ~3u;
	uint32_t ac_matchdir_size = ac_ns * sizeof(uint32_t);
	uint32_t ac_matchlist_offset = ac_matchdir_offset + ac_matchdir_size;
	uint32_t ac_matchlist_size =
		match_info->total_matches * sizeof(uint16_t);

	/* Always-run list */
	uint32_t always_run_off = ac_matchlist_offset + ac_matchlist_size;
	/* Align to 2B */
	always_run_off = (always_run_off + 1) & ~1u;
	uint32_t always_run_size = always_run_count * sizeof(uint16_t);

	/* Align MFSA section start to 64B */
	uint32_t mfsa_section_start = always_run_off + always_run_size;
	mfsa_section_start = (mfsa_section_start + ZDPI_TABLE_ALIGN - 1) &
			     ~(ZDPI_TABLE_ALIGN - 1);

	/* --- Compute MFSA section layout --- */
	uint32_t mfsa_ec_offset = mfsa_section_start;
	uint32_t mfsa_dir_offset = mfsa_ec_offset + ZDPI_EC_MAP_SIZE;
	uint32_t mfsa_dir_size = num_mfsa_dfas * ZDPI_DFA_DIR_ENTRY_SIZE;

	/* Align data start after directory */
	uint32_t mfsa_data_start = mfsa_dir_offset + mfsa_dir_size;
	mfsa_data_start = (mfsa_data_start + ZDPI_TABLE_ALIGN - 1) &
			  ~(ZDPI_TABLE_ALIGN - 1);

	/* Compute per-MFSA-DFA offsets */
	uint32_t *mtbl_offsets = calloc(num_mfsa_dfas, sizeof(uint32_t));
	uint32_t *macc_offsets = calloc(num_mfsa_dfas, sizeof(uint32_t));
	if (!mtbl_offsets || !macc_offsets) {
		free(mtbl_offsets);
		free(macc_offsets);
		return ZDPI_ERR_NOMEM;
	}

	uint32_t cursor = mfsa_data_start;
	for (uint32_t i = 0; i < num_mfsa_dfas; i++) {
		uint32_t ns = mfsa_tables[i].num_states;
		uint32_t tbl_sz = ns * mfsa_ne * sizeof(uint16_t);
		uint32_t acc_sz = (ns + 7) / 8;

		mtbl_offsets[i] = cursor;
		cursor += tbl_sz;
		macc_offsets[i] = cursor;
		cursor += acc_sz;
		cursor = (cursor + 3) & ~3u;
	}

	uint32_t total_size = (cursor + ZDPI_ARENA_PAGE_SIZE - 1) &
			      ~(ZDPI_ARENA_PAGE_SIZE - 1);

	out->data = calloc(1, total_size);
	if (!out->data) {
		free(mtbl_offsets);
		free(macc_offsets);
		return ZDPI_ERR_NOMEM;
	}
	out->size = total_size;

	/* --- Fill V4 header --- */
	struct zdpi_table_header_v4 *hdr =
		(struct zdpi_table_header_v4 *)out->data;
	hdr->magic = ZDPI_MAGIC;
	hdr->version_major = 0;
	hdr->version_minor = 3;
	hdr->ac_num_ec = (uint16_t)ac_ne;
	hdr->ac_num_states = ac_ns;
	hdr->ac_table_offset = ac_table_offset;
	hdr->ac_accept_offset = ac_accept_offset;
	hdr->ac_matchdir_offset = ac_matchdir_offset;
	hdr->ac_matchlist_offset = ac_matchlist_offset;
	hdr->ac_matchlist_count = match_info->total_matches;
	hdr->mfsa_num_ec = mfsa_ne;
	hdr->mfsa_num_dfas = (uint16_t)num_mfsa_dfas;
	hdr->mfsa_ec_offset = mfsa_ec_offset;
	hdr->mfsa_dir_offset = mfsa_dir_offset;
	hdr->always_run_offset = always_run_off;
	hdr->always_run_count = always_run_count;
	hdr->total_size = total_size;
	hdr->table_ready = 1;

	/* Backward compat header copy */
	out->header.magic = ZDPI_MAGIC;
	out->header.version_major = 0;
	out->header.version_minor = 3;
	out->header.num_ec = (uint16_t)ac_ne;
	out->header.num_states = ac_ns;
	out->header.total_size = total_size;
	out->header.table_ready = 1;

	/* --- Copy AC EC map --- */
	memcpy(out->data + ac_ec_offset,
	       ac_ecm->byte_to_ec, ZDPI_EC_MAP_SIZE);

	/* --- Copy AC transition table (downcast uint32_t → uint16_t) --- */
	uint16_t *ac_tbl_out =
		(uint16_t *)(out->data + ac_table_offset);
	for (uint32_t i = 0; i < ac_ns * ac_ne; i++)
		ac_tbl_out[i] = (uint16_t)ac_table->table[i];

	/* --- Pack AC accept bitset --- */
	uint8_t *ac_acc = out->data + ac_accept_offset;
	for (uint32_t s = 0; s < ac_ns; s++) {
		if (ac_table->accept[s])
			ac_acc[s / 8] |= (1 << (s % 8));
	}

	/* --- Fill AC match directory ---
	 * Each entry: (offset << 16) | count
	 * where offset is into the match list array */
	uint32_t *matchdir = (uint32_t *)(out->data + ac_matchdir_offset);
	for (uint32_t s = 0; s < ac_ns; s++) {
		uint32_t off = match_info->state_offsets[s];
		uint32_t cnt = match_info->state_counts[s];
		matchdir[s] = (off << 16) | (cnt & 0xFFFF);
	}

	/* --- Fill AC match list (uint16_t MFSA DFA indices) --- */
	uint16_t *matchlist =
		(uint16_t *)(out->data + ac_matchlist_offset);
	for (uint32_t i = 0; i < match_info->total_matches; i++)
		matchlist[i] = (uint16_t)match_info->pattern_ids[i];

	/* --- Fill always-run list --- */
	uint16_t *always_run_list =
		(uint16_t *)(out->data + always_run_off);
	for (uint32_t i = 0; i < always_run_count; i++)
		always_run_list[i] = always_run_indices[i];

	/* --- Copy MFSA EC map --- */
	if (mfsa_ecm)
		memcpy(out->data + mfsa_ec_offset,
		       mfsa_ecm->byte_to_ec, ZDPI_EC_MAP_SIZE);

	/* --- Fill MFSA directory and per-DFA data --- */
	struct zdpi_dfa_dir_entry *mdir =
		(struct zdpi_dfa_dir_entry *)(out->data + mfsa_dir_offset);

	for (uint32_t i = 0; i < num_mfsa_dfas; i++) {
		uint32_t ns = mfsa_tables[i].num_states;

		mdir[i].table_offset = mtbl_offsets[i];
		mdir[i].accept_offset = macc_offsets[i];
		mdir[i].num_states = (uint16_t)ns;
		mdir[i].rule_id = (uint16_t)rule_ids[i];

		/* Copy transition table as uint16_t */
		uint16_t *dst = (uint16_t *)(out->data + mtbl_offsets[i]);
		for (uint32_t s = 0; s < ns; s++) {
			for (uint32_t e = 0; e < mfsa_ne; e++) {
				dst[s * mfsa_ne + e] =
					(uint16_t)mfsa_tables[i]
						.table[s * mfsa_ne + e];
			}
		}

		/* Pack accept bitset */
		uint8_t *acc = out->data + macc_offsets[i];
		for (uint32_t s = 0; s < ns; s++) {
			if (mfsa_tables[i].accept[s])
				acc[s / 8] |= (1 << (s % 8));
		}
	}

	free(mtbl_offsets);
	free(macc_offsets);
	return ZDPI_OK;
}

int linearize_v4_simulate(const struct arena_blob *blob,
			   const uint8_t *input, uint32_t len)
{
	const struct zdpi_table_header_v4 *hdr =
		(const struct zdpi_table_header_v4 *)blob->data;

	if (hdr->magic != ZDPI_MAGIC || !hdr->table_ready)
		return ZDPI_ACTION_PASS;
	if (hdr->version_minor != 3)
		return ZDPI_ACTION_PASS;

	uint16_t ac_ne = hdr->ac_num_ec;
	uint32_t ac_ns = hdr->ac_num_states;
	uint16_t mfsa_ne = hdr->mfsa_num_ec;
	uint16_t mfsa_nd = hdr->mfsa_num_dfas;

	/* --- Stage 1: AC traversal --- */
	const uint8_t *ac_ecm = blob->data + ZDPI_HEADER_V4_SIZE;
	const uint16_t *ac_tbl =
		(const uint16_t *)(blob->data + hdr->ac_table_offset);
	const uint8_t *ac_acc = blob->data + hdr->ac_accept_offset;
	const uint32_t *matchdir =
		(const uint32_t *)(blob->data + hdr->ac_matchdir_offset);
	const uint16_t *matchlist =
		(const uint16_t *)(blob->data + hdr->ac_matchlist_offset);

	/* MFSA DFA bitmask: which DFAs to run in stage 2 */
	uint32_t bitmask_bytes = (mfsa_nd + 7) / 8;
	uint8_t *matched_dfas = calloc(1, bitmask_bytes ? bitmask_bytes : 1);
	if (!matched_dfas)
		return ZDPI_ACTION_PASS;

	/* Run AC DFA over input */
	uint32_t state = ZDPI_START_STATE;
	for (uint32_t i = 0; i < len; i++) {
		uint8_t ec = ac_ecm[input[i]];
		if (ec >= ac_ne || state >= ac_ns)
			break;
		state = ac_tbl[state * ac_ne + ec];
		if (state == ZDPI_DEAD_STATE)
			break;

		/* Check accept collect matched MFSA indices */
		if (state < ac_ns &&
		    (ac_acc[state / 8] & (1 << (state % 8)))) {
			uint32_t entry = matchdir[state];
			uint32_t off = entry >> 16;
			uint32_t cnt = entry & 0xFFFF;
			for (uint32_t m = 0; m < cnt; m++) {
				uint16_t idx = matchlist[off + m];
				if (idx < mfsa_nd)
					matched_dfas[idx / 8] |=
						(1 << (idx % 8));
			}
		}
	}

	/* OR in always-run MFSA DFAs */
	const uint16_t *always_run =
		(const uint16_t *)(blob->data + hdr->always_run_offset);
	for (uint32_t i = 0; i < hdr->always_run_count; i++) {
		uint16_t idx = always_run[i];
		if (idx < mfsa_nd)
			matched_dfas[idx / 8] |= (1 << (idx % 8));
	}

	/* Quick check: any bits set? */
	int any_matched = 0;
	for (uint32_t i = 0; i < bitmask_bytes; i++) {
		if (matched_dfas[i]) {
			any_matched = 1;
			break;
		}
	}
	if (!any_matched) {
		free(matched_dfas);
		return ZDPI_ACTION_PASS;
	}

	/* --- Stage 2: MFSA parallel DFA traversal --- */
	const uint8_t *mfsa_ecm =
		blob->data + hdr->mfsa_ec_offset;
	const struct zdpi_dfa_dir_entry *mdir =
		(const struct zdpi_dfa_dir_entry *)(blob->data +
						    hdr->mfsa_dir_offset);

	for (uint16_t di = 0; di < mfsa_nd; di++) {
		/* Skip DFAs not matched by AC */
		if (!(matched_dfas[di / 8] & (1 << (di % 8))))
			continue;

		const uint16_t *tbl =
			(const uint16_t *)(blob->data +
					   mdir[di].table_offset);
		const uint8_t *acc =
			blob->data + mdir[di].accept_offset;
		uint16_t ns = mdir[di].num_states;

		uint16_t dfa_state = ZDPI_START_STATE;
		for (uint32_t i = 0; i < len; i++) {
			uint8_t ec = mfsa_ecm[input[i]];
			if (ec >= mfsa_ne || dfa_state >= ns)
				break;
			dfa_state = tbl[dfa_state * mfsa_ne + ec];
			if (dfa_state == ZDPI_DEAD_STATE)
				break;
			if (dfa_state < ns &&
			    (acc[dfa_state / 8] &
			     (1 << (dfa_state % 8)))) {
				free(matched_dfas);
				return ZDPI_ACTION_DROP;
			}
		}
	}

	free(matched_dfas);
	return ZDPI_ACTION_PASS;
}

void arena_blob_free(struct arena_blob *b)
{
	free(b->data);
	memset(b, 0, sizeof(*b));
}

int linearize_simulate(const struct arena_blob *blob, const uint8_t *input,
		       uint32_t len)
{
	const struct zdpi_table_header *hdr =
		(const struct zdpi_table_header *)blob->data;

	if (hdr->magic != ZDPI_MAGIC || !hdr->table_ready)
		return ZDPI_ACTION_PASS;

	const uint8_t *ec_map = blob->data + ZDPI_EC_MAP_OFFSET;
	const uint32_t *table =
		(const uint32_t *)(blob->data + hdr->table_offset);
	const uint8_t *accept = blob->data + hdr->accept_offset;

	uint16_t num_ec = hdr->num_ec;
	uint32_t num_states = hdr->num_states;

	uint32_t state = ZDPI_START_STATE;
	for (uint32_t i = 0; i < len; i++) {
		uint8_t ec = ec_map[input[i]];
		if (ec >= num_ec || state >= num_states)
			break;
		state = table[(uint32_t)state * num_ec + ec];
		if (state == ZDPI_DEAD_STATE)
			break;
		/* Check accept immediately pattern may match
		 * mid-payload before later bytes send us to dead. */
		uint32_t byte_idx = state / 8;
		uint8_t bit_mask = 1 << (state % 8);
		if (accept[byte_idx] & bit_mask)
			return ZDPI_ACTION_DROP;
	}

	return ZDPI_ACTION_PASS;
}
