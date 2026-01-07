/**
 * @file bench_multi_dfa.c
 * @brief Benchmark: multi-rule DFA compilation via NFA union.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "zdpi_types.h"
#include "regex_parser.h"
#include "nfa.h"
#include "dfa.h"
#include "ec_compress.h"
#include "linearize.h"

#define WARMUP_RUNS 5
#define BENCH_RUNS 100

static const char *patterns[] = {
	"\\.\\./",
	"etc/passwd",
	"cmd\\.exe",
	"<script",
	"UNION\\s+SELECT",
};
#define NUM_PATTERNS (sizeof(patterns) / sizeof(patterns[0]))

static double time_diff_ms(struct timespec *start, struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) * 1000.0 +
	       (end->tv_nsec - start->tv_nsec) / 1e6;
}

int main(void)
{
	printf("test,description,variant,run,time_ms\n");

	for (uint32_t n = 1; n <= NUM_PATTERNS; n++) {
		for (int iter = 0; iter < WARMUP_RUNS + BENCH_RUNS;
		     iter++) {
			struct re_token_stream streams[NUM_PATTERNS];
			uint32_t rule_ids[NUM_PATTERNS];
			struct nfa nfa_g;
			struct dfa dfa_g;
			struct ec_map ecm;
			struct ec_table ect;
			struct arena_blob blob;
			struct timespec t0, t1;

			for (uint32_t i = 0; i < n; i++) {
				regex_parse(patterns[i], &streams[i]);
				rule_ids[i] = i + 1;
			}

			clock_gettime(CLOCK_MONOTONIC, &t0);

			nfa_alloc(&nfa_g, NFA_DEFAULT_CAPACITY);
			nfa_build_union(streams, n, rule_ids, &nfa_g);
			dfa_alloc(&dfa_g, ZDPI_MAX_STATES);
			dfa_build(&nfa_g, &dfa_g);
			dfa_minimize(&dfa_g);
			ec_compute(&dfa_g, &ecm);
			ec_table_build(&dfa_g, &ecm, &ect);
			linearize(&ecm, &ect, &blob);

			clock_gettime(CLOCK_MONOTONIC, &t1);

			if (iter >= WARMUP_RUNS) {
				int run = iter - WARMUP_RUNS;
				printf("multi_dfa,compile_%u_rules,"
				       "n%u,%d,%.4f\n",
				       n, n, run,
				       time_diff_ms(&t0, &t1));
				printf("multi_dfa,states_%u_rules,"
				       "n%u,%d,%u\n",
				       n, n, run, dfa_g.num_states);
				printf("multi_dfa,ec_%u_rules,"
				       "n%u,%d,%u\n",
				       n, n, run, ecm.num_ec);
			}

			nfa_free(&nfa_g);
			dfa_free(&dfa_g);
			ec_table_free(&ect);
			arena_blob_free(&blob);
		}
	}

	return 0;
}
