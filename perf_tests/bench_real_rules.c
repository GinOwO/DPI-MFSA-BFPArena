/**
 * @file bench_real_rules.c
 * @brief DFA scaling benchmark using real IDS ruleset patterns.
 *
 * Reads PCRE patterns extracted from the Emerging Threats open
 * Suricata ruleset, progressively unions them into a combined DFA,
 * and reports table size at each step. Demonstrates that real IDS
 * rulesets quickly exceed BPF map limits (32KB/4MB).
 *
 * Usage: bench_real_rules <patterns_file> [max_rules]
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

#define BPF_MAP_VALUE_MAX	(32U * 1024U)
#define BPF_MAP_TOTAL_MAX	(4U * 1024U * 1024U)
#define MAX_PATTERN_LEN		512
#define MAX_PATTERNS		4096

static double time_diff_ms(struct timespec *a, struct timespec *b)
{
	return (b->tv_sec - a->tv_sec) * 1000.0 +
	       (b->tv_nsec - a->tv_nsec) / 1e6;
}

struct pattern_set {
	char patterns[MAX_PATTERNS][MAX_PATTERN_LEN];
	uint32_t count;
};

static int load_patterns(const char *path, struct pattern_set *ps)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "Cannot open %s\n", path);
		return -1;
	}

	ps->count = 0;
	char line[MAX_PATTERN_LEN];
	while (fgets(line, sizeof(line), f) && ps->count < MAX_PATTERNS) {
		/* Strip newline */
		size_t len = strlen(line);
		while (len > 0 && (line[len - 1] == '\n' ||
				   line[len - 1] == '\r'))
			line[--len] = '\0';
		if (len == 0)
			continue;
		strncpy(ps->patterns[ps->count], line,
			MAX_PATTERN_LEN - 1);
		ps->count++;
	}
	fclose(f);
	return 0;
}

/*
 * Try to parse a pattern. Returns 0 on success.
 * Some ET patterns use features our parser doesn't support,
 * so we filter by trying and catching errors.
 */
static int try_parse(const char *pattern, struct re_token_stream *out)
{
	return regex_parse(pattern, out);
}

struct compile_result {
	uint32_t num_rules;
	uint32_t num_states;
	uint32_t num_ec;
	uint64_t table_size;
	uint32_t blob_size;
	double compile_ms;
	int exceeds_value;
	int exceeds_map;
	int rc;
};

static struct compile_result compile_rules(
	struct re_token_stream *streams,
	uint32_t count, uint32_t dfa_cap)
{
	struct compile_result res = { .num_rules = count };
	struct timespec t0, t1;
	uint32_t *rule_ids = calloc(count, sizeof(*rule_ids));
	if (!rule_ids) {
		res.rc = ZDPI_ERR_NOMEM;
		return res;
	}
	for (uint32_t i = 0; i < count; i++)
		rule_ids[i] = i + 1;

	struct nfa nfa_g;
	struct dfa dfa_g;
	struct ec_map ecm;
	struct ec_table ect;
	struct arena_blob blob;

	clock_gettime(CLOCK_MONOTONIC, &t0);

	uint32_t nfa_cap = NFA_DEFAULT_CAPACITY;
	if (count > 50)
		nfa_cap = count * 256;
	res.rc = nfa_alloc(&nfa_g, nfa_cap);
	if (res.rc)
		goto out;

	res.rc = nfa_build_union(streams, count, rule_ids, &nfa_g);
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

	res.compile_ms = time_diff_ms(&t0, &t1);
	res.num_states = dfa_g.num_states;
	res.num_ec = ecm.num_ec;
	res.table_size = (uint64_t)dfa_g.num_states * ecm.num_ec *
			 sizeof(uint32_t);

	if (res.rc == 0)
		res.blob_size = blob.size;

	res.exceeds_value = (res.table_size > BPF_MAP_VALUE_MAX);
	res.exceeds_map = (res.table_size > BPF_MAP_TOTAL_MAX);

	dfa_free(&dfa_g);
	ec_table_free(&ect);
	if (res.rc == 0)
		arena_blob_free(&blob);

out:
	free(rule_ids);
	return res;
}

/*
 * Steps at which to measure: 1, 2, 5, 10, 20, 50, 100, 200, 500...
 */
static const uint32_t steps[] = {
	1, 2, 3, 5, 8, 10, 15, 20, 30, 50,
	75, 100, 150, 200, 300, 500, 750, 1000
};
#define NUM_STEPS (sizeof(steps) / sizeof(steps[0]))

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr,
			"Usage: %s <patterns_file> [max_rules]\n",
			argv[0]);
		return 1;
	}

	uint32_t max_rules = 1000;
	if (argc >= 3)
		max_rules = (uint32_t)atoi(argv[2]);

	struct pattern_set *ps = calloc(1, sizeof(*ps));
	if (!ps || load_patterns(argv[1], ps) != 0)
		return 1;

	fprintf(stderr, "Loaded %u patterns from %s\n",
		ps->count, argv[1]);

	/* Parse all patterns, keeping only ones that succeed */
	struct re_token_stream *streams =
		calloc(ps->count, sizeof(*streams));
	uint32_t parsed = 0;
	uint32_t failed = 0;

	for (uint32_t i = 0; i < ps->count && parsed < max_rules; i++) {
		struct re_token_stream tmp;
		if (try_parse(ps->patterns[i], &tmp) == 0) {
			streams[parsed] = tmp;
			parsed++;
		} else {
			failed++;
		}
	}

	fprintf(stderr, "Parsed: %u ok, %u failed (%.0f%% compatible)\n",
		parsed, failed,
		100.0 * parsed / (parsed + failed));
	fprintf(stderr, "BPF map value max: %u KB\n",
		BPF_MAP_VALUE_MAX / 1024);
	fprintf(stderr, "BPF map total max: %u MB\n\n",
		BPF_MAP_TOTAL_MAX / (1024 * 1024));

	printf("test,description,variant,run,value\n");

	uint32_t dfa_cap = ZDPI_MAX_STATES;

	for (uint32_t si = 0; si < NUM_STEPS; si++) {
		uint32_t n = steps[si];
		if (n > parsed)
			break;

		fprintf(stderr, "--- %u real ET rules ---\n", n);

		struct compile_result r =
			compile_rules(streams, n, dfa_cap);

		if (r.rc == ZDPI_ERR_OVERFLOW) {
			fprintf(stderr,
				"  OVERFLOW at %u rules (DFA > %u)\n",
				n, dfa_cap);
			printf("real_rules,overflow,%u,0,-1\n", n);
			break;
		}

		if (r.rc != 0) {
			fprintf(stderr,
				"  compile failed: rc=%d\n", r.rc);
			printf("real_rules,error,%u,0,%d\n",
			       n, r.rc);
			continue;
		}

		fprintf(stderr,
			"  states=%u ec=%u table=%lluKB "
			"blob=%uKB compile=%.1fms "
			"exceeds_val=%d exceeds_map=%d\n",
			r.num_states, r.num_ec,
			(unsigned long long)r.table_size / 1024,
			r.blob_size / 1024,
			r.compile_ms,
			r.exceeds_value, r.exceeds_map);

		printf("real_rules,states,%u,0,%u\n",
		       n, r.num_states);
		printf("real_rules,ec,%u,0,%u\n",
		       n, r.num_ec);
		printf("real_rules,table_kb,%u,0,%llu\n",
		       n,
		       (unsigned long long)r.table_size / 1024);
		printf("real_rules,blob_kb,%u,0,%u\n",
		       n, r.blob_size / 1024);
		printf("real_rules,compile_ms,%u,0,%.1f\n",
		       n, r.compile_ms);
		printf("real_rules,exceeds_bpf_val,%u,0,%d\n",
		       n, r.exceeds_value);
		printf("real_rules,exceeds_bpf_map,%u,0,%d\n",
		       n, r.exceeds_map);
	}

	free(streams);
	free(ps);
	fprintf(stderr, "\nDone.\n");
	return 0;
}
