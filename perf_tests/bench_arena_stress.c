/**
 * @file bench_arena_stress.c
 * @brief Arena stress test: produce DFA tables exceeding regular BPF map limits.
 *
 * Uses .*X.*Y patterns to force exponential DFA state explosion. Each
 * pattern's characters are permanently matched (no backtracking) because
 * of the .* between them, so the DFA must track progress in ALL patterns
 * simultaneously. With N patterns, this produces 3^N product states:
 * each pattern is in one of {not-started, saw-X, saw-X-then-Y(accept)}.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.3
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

#define WARMUP_RUNS	1
#define MEASURE_RUNS	2

/*
 * BPF map limits for comparison reference.
 * Regular BPF_MAP_TYPE_ARRAY: max ~32KB per value, ~4MB total per map.
 * BPF Arena: up to 4GB contiguous (ZDPI_ARENA_PAGES * PAGE_SIZE).
 */
#define BPF_MAP_VALUE_MAX	(32U * 1024U)
#define BPF_MAP_TOTAL_MAX	(4U * 1024U * 1024U)

static double time_diff_ms(struct timespec *start, struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) * 1000.0 +
	       (end->tv_nsec - start->tv_nsec) / 1e6;
}

/*
 * Pattern format: ".*X.*Y" where X and Y are unique per pattern.
 * Each pattern uses 2 chars from a-z, assigned sequentially:
 *   pattern 0: .*a.*b
 *   pattern 1: .*c.*d
 *   pattern 2: .*e.*f
 *   ...
 *   pattern 12: .*y.*z
 *
 * This ensures all characters are disjoint across patterns,
 * maximizing the product state explosion during subset construction.
 *
 * With N patterns, DFA has up to 3^N states because each pattern
 * independently tracks: {not-started, saw-first-char, accepted}.
 */
#define MAX_PATTERNS	13

static uint32_t build_patterns(uint32_t n, char patterns[][16])
{
	if (n > MAX_PATTERNS)
		n = MAX_PATTERNS;

	for (uint32_t i = 0; i < n; i++) {
		char c1 = 'a' + (char)(i * 2);
		char c2 = 'a' + (char)(i * 2 + 1);

		snprintf(patterns[i], 16, ".*%c.*%c", c1, c2);
	}
	return n;
}

struct stress_level {
	const char *name;
	uint32_t num_patterns;
	uint32_t dfa_capacity;
};

/*
 * Stress levels. Expected DFA states = 3^N (product of per-pattern
 * state spaces). Actual may be slightly less due to unreachable
 * combinations and minimization.
 *
 *   tiny:    4 patterns -> ~    49 states, ~   1.8 KB table
 *   small:   6 patterns -> ~   257 states, ~  13.4 KB table
 *   medium:  8 patterns -> ~ 1,281 states, ~  85   KB table (>32KB!)
 *   large:  10 patterns -> ~ 6,145 states, ~ 504   KB table
 *   huge:   12 patterns -> ~32,000 states, ~   3   MB table
 *   max:    13 patterns -> ~74,000 states, ~   7   MB table (>4MB!)
 */
static const struct stress_level levels[] = {
	{ "tiny",    4,    4096 },
	{ "small",   6,    4096 },
	{ "medium",  8,   16384 },
	{ "large",  10,   65536 },
	{ "huge",   12,  131072 },
	{ "max",    13,  524288 },
};
#define NUM_LEVELS (sizeof(levels) / sizeof(levels[0]))

struct arena_result {
	double compile_time_ms;
	uint32_t num_states;
	uint32_t num_ec;
	uint64_t table_size;
	uint32_t blob_size;
	int rc;
};

static struct arena_result run_compile(uint32_t num_patterns,
				       char patterns[][16],
				       uint32_t dfa_cap)
{
	struct arena_result res = { 0 };
	struct timespec t0, t1;

	struct re_token_stream *streams = calloc(num_patterns,
						 sizeof(*streams));
	uint32_t *rule_ids = calloc(num_patterns, sizeof(*rule_ids));
	if (!streams || !rule_ids) {
		res.rc = ZDPI_ERR_NOMEM;
		free(streams);
		free(rule_ids);
		return res;
	}

	for (uint32_t i = 0; i < num_patterns; i++) {
		res.rc = regex_parse(patterns[i], &streams[i]);
		if (res.rc) {
			fprintf(stderr,
				"parse failed: [%u]=\"%s\" rc=%d\n",
				i, patterns[i], res.rc);
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

	res.rc = nfa_alloc(&nfa_g, NFA_DEFAULT_CAPACITY);
	if (res.rc)
		goto out;

	res.rc = nfa_build_union(streams, num_patterns, rule_ids, &nfa_g);
	if (res.rc) {
		nfa_free(&nfa_g);
		goto out;
	}

	res.rc = dfa_alloc(&dfa_g, dfa_cap);
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

	res.rc = dfa_minimize(&dfa_g);
	if (res.rc) {
		dfa_free(&dfa_g);
		goto out;
	}

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

	res.rc = linearize(&ecm, &ect, &blob);

	clock_gettime(CLOCK_MONOTONIC, &t1);

	res.compile_time_ms = time_diff_ms(&t0, &t1);
	res.num_states = dfa_g.num_states;
	res.num_ec = ecm.num_ec;

	res.table_size = (uint64_t)dfa_g.num_states * ecm.num_ec *
			 sizeof(uint32_t);

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

static void bench_level(const struct stress_level *lvl)
{
	char patterns[MAX_PATTERNS][16];
	uint32_t actual = build_patterns(lvl->num_patterns, patterns);

	fprintf(stderr, "--- Level %s: %u patterns, "
		"DFA cap %u, expected ~%u states ---\n",
		lvl->name, actual, lvl->dfa_capacity,
		(uint32_t)1); /* placeholder, computed below */

	/* Compute expected states = 3^N */
	uint64_t expected = 1;
	for (uint32_t i = 0; i < actual; i++)
		expected *= 3;
	fprintf(stderr, "  Expected 3^%u = %llu product states\n",
		actual, (unsigned long long)expected);

	for (uint32_t i = 0; i < actual; i++)
		fprintf(stderr, "  [%u] \"%s\"\n", i, patterns[i]);

	for (int iter = 0; iter < WARMUP_RUNS + MEASURE_RUNS; iter++) {
		struct arena_result r = run_compile(actual, patterns,
						    lvl->dfa_capacity);

		if (r.rc == ZDPI_ERR_OVERFLOW) {
			if (iter >= WARMUP_RUNS) {
				int run = iter - WARMUP_RUNS;
				printf("arena_stress,overflow_%s,"
				       "%s,%d,-1\n",
				       lvl->name, lvl->name, run);
			}
			if (iter == 0)
				fprintf(stderr,
					"  OVERFLOW: DFA exceeded cap %u "
					"(3^%u=%llu > %u)\n",
					lvl->dfa_capacity, actual,
					(unsigned long long)expected,
					lvl->dfa_capacity);
			continue;
		}

		if (r.rc != 0) {
			fprintf(stderr,
				"  compile failed at %s: rc=%d\n",
				lvl->name, r.rc);
			continue;
		}

		if (iter < WARMUP_RUNS)
			continue;

		int run = iter - WARMUP_RUNS;

		printf("arena_stress,table_size_%s,"
		       "%s,%d,%llu\n",
		       lvl->name, lvl->name, run,
		       (unsigned long long)r.table_size);
		printf("arena_stress,states_%s,"
		       "%s,%d,%u\n",
		       lvl->name, lvl->name, run, r.num_states);
		printf("arena_stress,ec_%s,"
		       "%s,%d,%u\n",
		       lvl->name, lvl->name, run, r.num_ec);
		printf("arena_stress,compile_ms_%s,"
		       "%s,%d,%.4f\n",
		       lvl->name, lvl->name, run, r.compile_time_ms);
		printf("arena_stress,blob_size_%s,"
		       "%s,%d,%u\n",
		       lvl->name, lvl->name, run, r.blob_size);

		uint64_t arena_total = (uint64_t)ZDPI_ARENA_PAGES *
				       ZDPI_ARENA_PAGE_SIZE;
		double util_pct = 100.0 * (double)r.blob_size /
				  (double)arena_total;
		printf("arena_stress,arena_util_pct_%s,"
		       "%s,%d,%.6f\n",
		       lvl->name, lvl->name, run, util_pct);

		int exceeds_value = (r.table_size > BPF_MAP_VALUE_MAX) ? 1 : 0;
		int exceeds_map = (r.table_size > BPF_MAP_TOTAL_MAX) ? 1 : 0;

		printf("arena_stress,exceeds_bpf_value_%s,"
		       "%s,%d,%d\n",
		       lvl->name, lvl->name, run, exceeds_value);
		printf("arena_stress,exceeds_bpf_map_%s,"
		       "%s,%d,%d\n",
		       lvl->name, lvl->name, run, exceeds_map);

		if (run == 0) {
			fprintf(stderr,
				"  %s: states=%u ec=%u "
				"table=%lluKB blob=%uKB "
				"compile=%.1fms "
				"arena=%.4f%% "
				"exceeds_val=%d exceeds_map=%d\n",
				lvl->name, r.num_states, r.num_ec,
				(unsigned long long)r.table_size / 1024,
				r.blob_size / 1024,
				r.compile_time_ms,
				util_pct,
				exceeds_value, exceeds_map);
		}
	}
}

int main(void)
{
	printf("test,description,variant,run,value\n");

	fprintf(stderr, "=== Arena Stress Test ===\n");
	fprintf(stderr, "Arena capacity: %u pages * %u bytes = %llu MB\n",
		ZDPI_ARENA_PAGES, ZDPI_ARENA_PAGE_SIZE,
		(unsigned long long)ZDPI_ARENA_PAGES *
			ZDPI_ARENA_PAGE_SIZE / (1024 * 1024));
	fprintf(stderr, "BPF map value max: %u KB\n",
		BPF_MAP_VALUE_MAX / 1024);
	fprintf(stderr, "BPF map total max: %u MB\n",
		BPF_MAP_TOTAL_MAX / (1024 * 1024));
	fprintf(stderr, "ZDPI_MAX_STATES: %u\n\n", ZDPI_MAX_STATES);

	for (uint32_t i = 0; i < NUM_LEVELS; i++)
		bench_level(&levels[i]);

	return 0;
}
