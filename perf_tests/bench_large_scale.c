/**
 * @file bench_large_scale.c
 * @brief Large-scale benchmark: 10K-100K diverse synthetic rules.
 *
 * Generates diverse synthetic regex patterns that resist DFA state
 * minimization, then benchmarks the full pipeline at multiple scales.
 * Reports compile time, DFA states, EC count, blob size, NFA states,
 * and traversal throughput.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.1
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "zdpi_types.h"
#include "regex_parser.h"
#include "nfa.h"
#include "dfa.h"
#include "ec_compress.h"
#include "linearize.h"

#define WARMUP_RUNS	3
#define BENCH_RUNS	5
#define TRAVERSE_PAYLOADS 1000
#define MAX_PAYLOAD	1500
#define MAX_PATTERN_LEN	128

/* --- Seeded PRNG (xorshift32) for reproducibility --- */

static uint32_t xorshift_state = 0xCAFEBABE;

static uint32_t xorshift32(void)
{
	uint32_t x = xorshift_state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	xorshift_state = x;
	return x;
}

/* --- Diverse pattern generation --- */

/*
 * Strategy: each pattern is built from 3-5 "fragments" combined with
 * regex operators. Fragment types:
 *   - 2-4 random literal bytes (unique sequences)
 *   - character class [X-Y] with random ranges
 *   - alternation of two short literals (ab|cd)
 *   - wildcard .{1-3} sequences
 *
 * Fragments are joined by concatenation, with random quantifiers
 * (*,+,?) applied to some fragments. The per-pattern seed ensures
 * each pattern produces unique DFA transitions and resists merging.
 */

static void append_char(char *buf, uint32_t *pos, uint32_t max, char c)
{
	if (*pos < max - 1)
		buf[(*pos)++] = c;
}

/* Generate a random printable byte that is safe inside regex */
static char rand_literal(void)
{
	/* Use letters and digits to avoid regex metacharacter issues */
	static const char safe[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"0123456789";
	return safe[xorshift32() % (sizeof(safe) - 1)];
}

static void gen_fragment_literal(char *buf, uint32_t *pos, uint32_t max)
{
	uint32_t len = 2 + (xorshift32() % 3); /* 2-4 chars */
	for (uint32_t i = 0; i < len; i++)
		append_char(buf, pos, max, rand_literal());
}

static void gen_fragment_class(char *buf, uint32_t *pos, uint32_t max)
{
	/* [X-Y] with a random range within a-z or A-Z or 0-9 */
	uint32_t kind = xorshift32() % 3;
	char lo, hi;

	if (kind == 0) {
		lo = 'a' + (char)(xorshift32() % 13);
		hi = lo + 1 + (char)(xorshift32() % (('z' - lo)));
		if (hi > 'z')
			hi = 'z';
	} else if (kind == 1) {
		lo = 'A' + (char)(xorshift32() % 13);
		hi = lo + 1 + (char)(xorshift32() % (('Z' - lo)));
		if (hi > 'Z')
			hi = 'Z';
	} else {
		lo = '0' + (char)(xorshift32() % 5);
		hi = lo + 1 + (char)(xorshift32() % (('9' - lo)));
		if (hi > '9')
			hi = '9';
	}

	append_char(buf, pos, max, '[');
	append_char(buf, pos, max, lo);
	append_char(buf, pos, max, '-');
	append_char(buf, pos, max, hi);
	append_char(buf, pos, max, ']');
}

static void gen_fragment_alternation(char *buf, uint32_t *pos, uint32_t max)
{
	/* (XX|YY) with 2-char random literals on each side */
	append_char(buf, pos, max, '(');
	append_char(buf, pos, max, rand_literal());
	append_char(buf, pos, max, rand_literal());
	append_char(buf, pos, max, '|');
	append_char(buf, pos, max, rand_literal());
	append_char(buf, pos, max, rand_literal());
	append_char(buf, pos, max, ')');
}

static void gen_fragment_wildcard(char *buf, uint32_t *pos, uint32_t max)
{
	/* 1-3 dots */
	uint32_t len = 1 + (xorshift32() % 3);
	for (uint32_t i = 0; i < len; i++)
		append_char(buf, pos, max, '.');
}

static void gen_diverse_pattern(char *buf, uint32_t max, uint32_t index)
{
	/*
	 * Seed the PRNG uniquely per pattern so the sequence of
	 * fragments is deterministic and distinct for each index.
	 */
	uint32_t saved = xorshift_state;
	xorshift_state = 0xCAFEBABE ^ (index * 2654435761u);
	if (xorshift_state == 0)
		xorshift_state = 1;
	/* Burn a few rounds */
	xorshift32();
	xorshift32();

	uint32_t pos = 0;
	uint32_t num_frags = 3 + (xorshift32() % 3); /* 3-5 fragments */

	for (uint32_t f = 0; f < num_frags; f++) {
		uint32_t ftype = xorshift32() % 4;

		switch (ftype) {
		case 0:
			gen_fragment_literal(buf, &pos, max);
			break;
		case 1:
			gen_fragment_class(buf, &pos, max);
			break;
		case 2:
			gen_fragment_alternation(buf, &pos, max);
			break;
		case 3:
			gen_fragment_wildcard(buf, &pos, max);
			break;
		}

		/* Maybe add a quantifier after this fragment */
		uint32_t q = xorshift32() % 5;
		if (q == 0)
			append_char(buf, &pos, max, '*');
		else if (q == 1)
			append_char(buf, &pos, max, '+');
		else if (q == 2)
			append_char(buf, &pos, max, '?');
		/* else: no quantifier */
	}

	buf[pos] = '\0';
	xorshift_state = saved;
}

/* --- Timing helpers --- */

static double time_diff_ms(struct timespec *start, struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) * 1000.0 +
	       (end->tv_nsec - start->tv_nsec) / 1e6;
}

static double time_diff_us(struct timespec *start, struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) * 1e6 +
	       (end->tv_nsec - start->tv_nsec) / 1e3;
}

/* --- Compile result --- */

struct compile_result {
	double time_ms;
	uint32_t num_dfa_states;
	uint32_t num_ec;
	uint32_t blob_size;
	uint32_t nfa_states;
	int rc;
};

/*
 * Generate N diverse patterns, parse them, then run the full
 * pipeline: nfa_build_union -> dfa_build -> dfa_minimize ->
 * ec_compute -> ec_table_build -> linearize.
 *
 * Returns compile metrics. The blob is freed internally;
 * only metrics are returned.
 */
static struct compile_result compile_n_rules(uint32_t n)
{
	struct compile_result res = { 0 };
	struct timespec t0, t1;
	char pat_buf[MAX_PATTERN_LEN];

	struct re_token_stream *streams = calloc(n, sizeof(*streams));
	uint32_t *rule_ids = calloc(n, sizeof(*rule_ids));
	if (!streams || !rule_ids) {
		res.rc = ZDPI_ERR_NOMEM;
		free(streams);
		free(rule_ids);
		return res;
	}

	/* Generate and parse all patterns */
	for (uint32_t i = 0; i < n; i++) {
		gen_diverse_pattern(pat_buf, MAX_PATTERN_LEN, i);
		res.rc = regex_parse(pat_buf, &streams[i]);
		if (res.rc) {
			fprintf(stderr,
				"  parse failed at pattern %u: rc=%d\n",
				i, res.rc);
			free(streams);
			free(rule_ids);
			return res;
		}
		rule_ids[i] = i + 1;
	}

	struct nfa nfa_g;
	struct dfa dfa_g;
	struct ec_map ecm;
	struct ec_table ect;
	struct arena_blob blob;

	clock_gettime(CLOCK_MONOTONIC, &t0);

	/* NFA build */
	res.rc = nfa_alloc(&nfa_g, NFA_DEFAULT_CAPACITY);
	if (res.rc)
		goto out;

	res.rc = nfa_build_union(streams, n, rule_ids, &nfa_g);
	if (res.rc) {
		nfa_free(&nfa_g);
		goto out;
	}
	res.nfa_states = nfa_g.num_states;

	/* DFA build */
	res.rc = dfa_alloc(&dfa_g, ZDPI_MAX_STATES);
	if (res.rc) {
		nfa_free(&nfa_g);
		goto out;
	}

	res.rc = dfa_build(&nfa_g, &dfa_g);
	nfa_free(&nfa_g);
	if (res.rc) {
		dfa_free(&dfa_g);
		goto out;
	}

	/* Minimize */
	res.rc = dfa_minimize(&dfa_g);
	if (res.rc) {
		dfa_free(&dfa_g);
		goto out;
	}

	/* EC compress */
	res.rc = ec_compute(&dfa_g, &ecm);
	if (res.rc) {
		dfa_free(&dfa_g);
		goto out;
	}

	res.rc = ec_table_build(&dfa_g, &ecm, &ect);
	if (res.rc) {
		dfa_free(&dfa_g);
		goto out;
	}

	/* Linearize */
	res.rc = linearize(&ecm, &ect, &blob);

	clock_gettime(CLOCK_MONOTONIC, &t1);

	res.time_ms = time_diff_ms(&t0, &t1);
	res.num_dfa_states = dfa_g.num_states;
	res.num_ec = ecm.num_ec;
	if (res.rc == 0)
		res.blob_size = blob.size;

	dfa_free(&dfa_g);
	ec_table_free(&ect);
	if (res.rc == 0)
		arena_blob_free(&blob);

out:
	free(streams);
	free(rule_ids);
	return res;
}

/*
 * Build a blob for N rules, then traverse TRAVERSE_PAYLOADS
 * random payloads and measure throughput.
 */
static void bench_traverse_at_scale(uint32_t n)
{
	char pat_buf[MAX_PATTERN_LEN];

	struct re_token_stream *streams = calloc(n, sizeof(*streams));
	uint32_t *rule_ids = calloc(n, sizeof(*rule_ids));
	if (!streams || !rule_ids) {
		fprintf(stderr, "  alloc failed for traverse (n=%u)\n", n);
		free(streams);
		free(rule_ids);
		return;
	}

	for (uint32_t i = 0; i < n; i++) {
		gen_diverse_pattern(pat_buf, MAX_PATTERN_LEN, i);
		int rc = regex_parse(pat_buf, &streams[i]);
		if (rc) {
			free(streams);
			free(rule_ids);
			return;
		}
		rule_ids[i] = i + 1;
	}

	struct nfa nfa_g;
	struct dfa dfa_g;
	struct ec_map ecm;
	struct ec_table ect;
	struct arena_blob blob;
	int rc;

	rc = nfa_alloc(&nfa_g, NFA_DEFAULT_CAPACITY);
	if (rc)
		goto out_free;

	rc = nfa_build_union(streams, n, rule_ids, &nfa_g);
	if (rc) {
		nfa_free(&nfa_g);
		goto out_free;
	}

	rc = dfa_alloc(&dfa_g, ZDPI_MAX_STATES);
	if (rc) {
		nfa_free(&nfa_g);
		goto out_free;
	}

	rc = dfa_build(&nfa_g, &dfa_g);
	nfa_free(&nfa_g);
	if (rc) {
		dfa_free(&dfa_g);
		goto out_free;
	}

	rc = dfa_minimize(&dfa_g);
	if (rc) {
		dfa_free(&dfa_g);
		goto out_free;
	}

	rc = ec_compute(&dfa_g, &ecm);
	if (rc) {
		dfa_free(&dfa_g);
		goto out_free;
	}

	rc = ec_table_build(&dfa_g, &ecm, &ect);
	if (rc) {
		dfa_free(&dfa_g);
		goto out_free;
	}

	rc = linearize(&ecm, &ect, &blob);
	dfa_free(&dfa_g);
	ec_table_free(&ect);
	if (rc)
		goto out_free;

	/* Prepare random payloads */
	uint8_t *payload = malloc(MAX_PAYLOAD);
	if (!payload) {
		arena_blob_free(&blob);
		goto out_free;
	}

	uint32_t saved_prng = xorshift_state;

	for (int iter = 0; iter < WARMUP_RUNS + BENCH_RUNS; iter++) {
		/* Reset PRNG for each run so payloads are identical */
		xorshift_state = 0xF00DCAFE;

		struct timespec t0, t1;
		uint32_t drops = 0;
		uint32_t total_bytes = 0;

		clock_gettime(CLOCK_MONOTONIC, &t0);

		for (int p = 0; p < TRAVERSE_PAYLOADS; p++) {
			uint32_t plen = 64 + (xorshift32() %
					      (MAX_PAYLOAD - 64));
			for (uint32_t b = 0; b < plen; b++)
				payload[b] = (uint8_t)(xorshift32() & 0xFF);

			int act = linearize_simulate(&blob, payload, plen);
			if (act == ZDPI_ACTION_DROP)
				drops++;
			total_bytes += plen;
		}

		clock_gettime(CLOCK_MONOTONIC, &t1);

		if (iter >= WARMUP_RUNS) {
			int run = iter - WARMUP_RUNS;
			double elapsed_us = time_diff_us(&t0, &t1);
			double mb_per_sec =
				(double)total_bytes / elapsed_us;
			double ns_per_pkt =
				elapsed_us * 1e3 / TRAVERSE_PAYLOADS;

			printf("large_traverse,throughput_%u_rules_MBps,"
			       "n%u,%d,%.2f\n",
			       n, n, run, mb_per_sec);
			printf("large_traverse,latency_%u_rules_ns,"
			       "n%u,%d,%.2f\n",
			       n, n, run, ns_per_pkt);
			if (run == 0)
				printf("large_traverse,drops_%u_rules,"
				       "n%u,0,%.4f\n",
				       n, n,
				       (double)drops / TRAVERSE_PAYLOADS);
		}
	}

	xorshift_state = saved_prng;
	free(payload);
	arena_blob_free(&blob);

out_free:
	free(streams);
	free(rule_ids);
}

/* --- Main benchmark driver --- */

int main(void)
{
	printf("test,description,variant,run,value\n");

	uint32_t scales[] = { 100, 500, 1000, 5000, 10000, 50000, 100000 };
	uint32_t num_scales = sizeof(scales) / sizeof(scales[0]);

	/* Phase 1: Compile scaling */
	fprintf(stderr, "=== Large-Scale Compile Benchmarks ===\n");

	for (uint32_t si = 0; si < num_scales; si++) {
		uint32_t n = scales[si];
		fprintf(stderr, "  Scale: %u rules\n", n);

		for (int iter = 0; iter < WARMUP_RUNS + BENCH_RUNS;
		     iter++) {
			struct compile_result r = compile_n_rules(n);

			if (r.rc == ZDPI_ERR_OVERFLOW) {
				fprintf(stderr,
					"  DFA state explosion at n=%u "
					"(ZDPI_ERR_OVERFLOW)\n", n);
				if (iter >= WARMUP_RUNS) {
					int run = iter - WARMUP_RUNS;
					printf("large_compile,"
					       "compile_%u_rules,"
					       "n%u,%d,-1\n",
					       n, n, run);
					printf("large_compile,"
					       "overflow_%u_rules,"
					       "n%u,%d,1\n",
					       n, n, run);
				}
				continue;
			}

			if (r.rc != 0) {
				fprintf(stderr,
					"  compile failed: n=%u rc=%d\n",
					n, r.rc);
				if (iter >= WARMUP_RUNS) {
					int run = iter - WARMUP_RUNS;
					printf("large_compile,"
					       "error_%u_rules,"
					       "n%u,%d,%d\n",
					       n, n, run, r.rc);
				}
				continue;
			}

			if (iter >= WARMUP_RUNS) {
				int run = iter - WARMUP_RUNS;
				printf("large_compile,"
				       "compile_time_%u_rules,"
				       "n%u,%d,%.4f\n",
				       n, n, run, r.time_ms);
				printf("large_compile,"
				       "dfa_states_%u_rules,"
				       "n%u,%d,%u\n",
				       n, n, run, r.num_dfa_states);
				printf("large_compile,"
				       "num_ec_%u_rules,"
				       "n%u,%d,%u\n",
				       n, n, run, r.num_ec);
				printf("large_compile,"
				       "blob_size_%u_rules,"
				       "n%u,%d,%u\n",
				       n, n, run, r.blob_size);
				printf("large_compile,"
				       "nfa_states_%u_rules,"
				       "n%u,%d,%u\n",
				       n, n, run, r.nfa_states);
			}
		}
	}

	/* Phase 2: Traversal throughput at each scale */
	fprintf(stderr, "=== Large-Scale Traversal Benchmarks ===\n");

	for (uint32_t si = 0; si < num_scales; si++) {
		uint32_t n = scales[si];
		fprintf(stderr, "  Traverse scale: %u rules\n", n);
		bench_traverse_at_scale(n);
	}

	fprintf(stderr, "=== Large-Scale Benchmarks Complete ===\n");
	return 0;
}
