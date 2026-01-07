/**
 * @file bench_single_dfa.c
 * @brief Benchmark: single-rule DFA compile + traverse.
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

#define WARMUP_RUNS 10
#define BENCH_RUNS 500
#define PAYLOAD_LEN 1024

static double time_diff_ms(struct timespec *start, struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) * 1000.0 +
	       (end->tv_nsec - start->tv_nsec) / 1e6;
}

int main(void)
{
	const char *pattern = "\\.\\./";
	struct timespec t0, t1;

	printf("test,description,variant,run,time_ms\n");

	for (int iter = 0; iter < WARMUP_RUNS + BENCH_RUNS; iter++) {
		struct re_token_stream tokens;
		struct nfa nfa_g;
		struct dfa dfa_g;
		struct ec_map ecm;
		struct ec_table ect;
		struct arena_blob blob;

		clock_gettime(CLOCK_MONOTONIC, &t0);

		regex_parse(pattern, &tokens);
		nfa_alloc(&nfa_g, NFA_DEFAULT_CAPACITY);
		nfa_build(&tokens, &nfa_g);
		dfa_alloc(&dfa_g, ZDPI_MAX_STATES);
		dfa_build(&nfa_g, &dfa_g);
		dfa_minimize(&dfa_g);
		ec_compute(&dfa_g, &ecm);
		ec_table_build(&dfa_g, &ecm, &ect);
		linearize(&ecm, &ect, &blob);

		clock_gettime(CLOCK_MONOTONIC, &t1);

		if (iter >= WARMUP_RUNS) {
			int run = iter - WARMUP_RUNS;
			printf("single_dfa,compile,compile,%d,%.4f\n",
			       run, time_diff_ms(&t0, &t1));
		}

		/* Traverse benchmark */
		uint8_t payload[PAYLOAD_LEN];
		memset(payload, 'A', PAYLOAD_LEN);

		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (int i = 0; i < 10000; i++)
			linearize_simulate(&blob, payload, PAYLOAD_LEN);
		clock_gettime(CLOCK_MONOTONIC, &t1);

		if (iter >= WARMUP_RUNS) {
			int run = iter - WARMUP_RUNS;
			printf("single_dfa,traverse_10K,traverse,%d,%.4f\n",
			       run, time_diff_ms(&t0, &t1));
		}

		nfa_free(&nfa_g);
		dfa_free(&dfa_g);
		ec_table_free(&ect);
		arena_blob_free(&blob);
	}

	return 0;
}
