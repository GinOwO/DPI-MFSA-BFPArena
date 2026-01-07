/**
 * @file bench_fuzz.c
 * @brief Fuzz test: random/adversarial patterns and payloads.
 *
 * Generates randomized regex patterns and payloads to stress-test
 * the full pipeline for crashes, assertion failures, and edge cases.
 * Reports pass/fail counts and any errors encountered.
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

#define FUZZ_PATTERN_RUNS	1000
#define FUZZ_PAYLOAD_RUNS	5000
#define MAX_FUZZ_PATTERN_LEN	64
#define MAX_FUZZ_PAYLOAD_LEN	1500

static double time_diff_ms(struct timespec *start, struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) * 1000.0 +
	       (end->tv_nsec - start->tv_nsec) / 1e6;
}

static uint32_t xorshift_state;

static uint32_t xorshift32(void)
{
	uint32_t x = xorshift_state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	xorshift_state = x;
	return x;
}

/* Characters that appear in regex patterns */
static const char literal_chars[] =
	"abcdefghijklmnopqrstuvwxyz"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"0123456789"
	" /.-_:;=&?#%@!~^{}";

static void gen_random_pattern(char *buf, uint32_t maxlen)
{
	uint32_t len = 1 + (xorshift32() % (maxlen - 1));
	uint32_t paren_depth = 0;

	for (uint32_t i = 0; i < len; i++) {
		uint32_t r = xorshift32() % 100;

		if (r < 50) {
			/* Literal char */
			buf[i] = literal_chars[xorshift32() %
					       (sizeof(literal_chars) - 1)];
		} else if (r < 60) {
			buf[i] = '.';
		} else if (r < 70 && i > 0) {
			/* Quantifier (not at start) */
			uint32_t q = xorshift32() % 3;
			buf[i] = q == 0 ? '*' : (q == 1 ? '+' : '?');
		} else if (r < 75 && paren_depth < 3) {
			buf[i] = '(';
			paren_depth++;
		} else if (r < 80 && paren_depth > 0) {
			buf[i] = ')';
			paren_depth--;
		} else if (r < 85) {
			buf[i] = '|';
		} else if (r < 90 && i + 3 < len) {
			/* Simple char class */
			buf[i] = '[';
			buf[i + 1] = 'a';
			buf[i + 2] = '-';
			buf[i + 3] = 'z';
			i += 3;
			if (i + 1 < len) {
				buf[i + 1] = ']';
				i++;
			}
		} else if (r < 95 && i + 1 < len) {
			/* Escape sequence */
			buf[i] = '\\';
			uint32_t e = xorshift32() % 6;
			const char esc[] = "dwsDWS";
			buf[i + 1] = esc[e];
			i++;
		} else {
			buf[i] = literal_chars[xorshift32() %
					       (sizeof(literal_chars) - 1)];
		}
	}

	/* Close unclosed parens */
	uint32_t pos = len;
	while (paren_depth > 0 && pos < maxlen - 1) {
		buf[pos++] = ')';
		paren_depth--;
	}
	buf[pos] = '\0';
}

static void gen_random_payload(uint8_t *buf, uint32_t len)
{
	uint32_t mode = xorshift32() % 5;

	switch (mode) {
	case 0: /* Pure random bytes */
		for (uint32_t i = 0; i < len; i++)
			buf[i] = (uint8_t)(xorshift32() & 0xFF);
		break;
	case 1: /* Printable ASCII */
		for (uint32_t i = 0; i < len; i++)
			buf[i] = (uint8_t)(32 + (xorshift32() % 95));
		break;
	case 2: /* Mostly nulls with sprinkled data */
		memset(buf, 0, len);
		for (uint32_t i = 0; i < len / 10; i++) {
			uint32_t pos = xorshift32() % len;
			buf[pos] = (uint8_t)(xorshift32() & 0xFF);
		}
		break;
	case 3: /* Repeated pattern */
		for (uint32_t i = 0; i < len; i++)
			buf[i] = (uint8_t)(i & 0xFF);
		break;
	case 4: /* All 0xFF */
		memset(buf, 0xFF, len);
		break;
	}
}

/* Adversarial patterns designed to stress the DFA */
static const char *adversarial_patterns[] = {
	"a*a*a*a*a*b",
	"(a|b)*c",
	"(a*)*",
	"(a|aa)*b",
	".*.*.*.b",
	"[a-z]*[0-9]*[A-Z]*",
	"(ab|cd|ef|gh|ij|kl)*",
	"a?a?a?a?a?a?a?a?aaaaaaaa",
	"(a|b|c|d|e)(f|g|h|i|j)",
	"[^a][^b][^c]",
};
#define NUM_ADVERSARIAL \
	(sizeof(adversarial_patterns) / sizeof(adversarial_patterns[0]))

struct fuzz_stats {
	uint32_t total;
	uint32_t parse_ok;
	uint32_t nfa_ok;
	uint32_t dfa_ok;
	uint32_t minimize_ok;
	uint32_t ec_ok;
	uint32_t linearize_ok;
	uint32_t traverse_ok;
	uint32_t parse_err;
	uint32_t overflow_err;
	uint32_t other_err;
};

static int fuzz_pipeline(const char *pattern, const uint8_t *payload,
			 uint32_t payload_len, struct fuzz_stats *stats)
{
	struct re_token_stream tokens;
	struct nfa nfa_g;
	struct dfa dfa_g;
	struct ec_map ecm;
	struct ec_table ect;
	struct arena_blob blob;
	int rc;

	stats->total++;

	rc = regex_parse(pattern, &tokens);
	if (rc) {
		if (rc == ZDPI_ERR_PARSE)
			stats->parse_err++;
		else if (rc == ZDPI_ERR_OVERFLOW)
			stats->overflow_err++;
		else
			stats->other_err++;
		return rc;
	}
	stats->parse_ok++;

	if (tokens.len == 0)
		return -1;

	rc = nfa_alloc(&nfa_g, NFA_DEFAULT_CAPACITY);
	if (rc) {
		stats->other_err++;
		return rc;
	}

	rc = nfa_build(&tokens, &nfa_g);
	if (rc) {
		stats->other_err++;
		nfa_free(&nfa_g);
		return rc;
	}
	stats->nfa_ok++;

	rc = dfa_alloc(&dfa_g, ZDPI_MAX_STATES);
	if (rc) {
		stats->other_err++;
		nfa_free(&nfa_g);
		return rc;
	}

	rc = dfa_build(&nfa_g, &dfa_g);
	nfa_free(&nfa_g);
	if (rc) {
		if (rc == ZDPI_ERR_OVERFLOW)
			stats->overflow_err++;
		else
			stats->other_err++;
		dfa_free(&dfa_g);
		return rc;
	}
	stats->dfa_ok++;

	rc = dfa_minimize(&dfa_g);
	if (rc) {
		stats->other_err++;
		dfa_free(&dfa_g);
		return rc;
	}
	stats->minimize_ok++;

	rc = ec_compute(&dfa_g, &ecm);
	if (rc) {
		stats->other_err++;
		dfa_free(&dfa_g);
		return rc;
	}
	stats->ec_ok++;

	rc = ec_table_build(&dfa_g, &ecm, &ect);
	if (rc) {
		stats->other_err++;
		dfa_free(&dfa_g);
		return rc;
	}

	rc = linearize(&ecm, &ect, &blob);
	dfa_free(&dfa_g);
	ec_table_free(&ect);
	if (rc) {
		stats->other_err++;
		return rc;
	}
	stats->linearize_ok++;

	/* Traverse should never crash regardless of input */
	linearize_simulate(&blob, payload, payload_len);
	stats->traverse_ok++;

	arena_blob_free(&blob);
	return 0;
}

int main(void)
{
	struct timespec seed_ts;
	clock_gettime(CLOCK_REALTIME, &seed_ts);
	xorshift_state = (uint32_t)(seed_ts.tv_nsec ^ seed_ts.tv_sec);
	if (xorshift_state == 0)
		xorshift_state = 0xDEADBEEF;

	printf("test,description,variant,run,value\n");

	/* Phase 1: Random pattern fuzzing */
	fprintf(stderr, "=== Random Pattern Fuzz (%d runs) ===\n",
		FUZZ_PATTERN_RUNS);
	struct fuzz_stats random_stats = { 0 };
	char pattern_buf[MAX_FUZZ_PATTERN_LEN + 16];
	uint8_t payload_buf[MAX_FUZZ_PAYLOAD_LEN];

	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);

	for (int i = 0; i < FUZZ_PATTERN_RUNS; i++) {
		gen_random_pattern(pattern_buf, MAX_FUZZ_PATTERN_LEN);
		uint32_t plen = 64 + (xorshift32() % (MAX_FUZZ_PAYLOAD_LEN - 64));
		gen_random_payload(payload_buf, plen);
		fuzz_pipeline(pattern_buf, payload_buf, plen, &random_stats);
	}

	clock_gettime(CLOCK_MONOTONIC, &t1);
	double random_elapsed = time_diff_ms(&t0, &t1);

	printf("fuzz,random_total,random,0,%u\n", random_stats.total);
	printf("fuzz,random_parse_ok,random,0,%u\n", random_stats.parse_ok);
	printf("fuzz,random_nfa_ok,random,0,%u\n", random_stats.nfa_ok);
	printf("fuzz,random_dfa_ok,random,0,%u\n", random_stats.dfa_ok);
	printf("fuzz,random_minimize_ok,random,0,%u\n",
	       random_stats.minimize_ok);
	printf("fuzz,random_linearize_ok,random,0,%u\n",
	       random_stats.linearize_ok);
	printf("fuzz,random_traverse_ok,random,0,%u\n",
	       random_stats.traverse_ok);
	printf("fuzz,random_parse_err,random,0,%u\n",
	       random_stats.parse_err);
	printf("fuzz,random_overflow_err,random,0,%u\n",
	       random_stats.overflow_err);
	printf("fuzz,random_other_err,random,0,%u\n",
	       random_stats.other_err);
	printf("fuzz,random_elapsed_ms,random,0,%.2f\n", random_elapsed);

	fprintf(stderr,
		"  Total: %u, Parse OK: %u, Full pipeline: %u, "
		"Parse err: %u, Overflow: %u, Other: %u\n",
		random_stats.total, random_stats.parse_ok,
		random_stats.traverse_ok, random_stats.parse_err,
		random_stats.overflow_err, random_stats.other_err);

	/* Phase 2: Adversarial pattern fuzzing */
	fprintf(stderr, "=== Adversarial Pattern Fuzz (%lu patterns) ===\n",
		(unsigned long)NUM_ADVERSARIAL);
	struct fuzz_stats adv_stats = { 0 };

	clock_gettime(CLOCK_MONOTONIC, &t0);

	for (uint32_t i = 0; i < NUM_ADVERSARIAL; i++) {
		for (int run = 0; run < 100; run++) {
			uint32_t plen = 64 + (xorshift32() %
					      (MAX_FUZZ_PAYLOAD_LEN - 64));
			gen_random_payload(payload_buf, plen);
			fuzz_pipeline(adversarial_patterns[i], payload_buf,
				      plen, &adv_stats);
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &t1);
	double adv_elapsed = time_diff_ms(&t0, &t1);

	printf("fuzz,adversarial_total,adversarial,0,%u\n", adv_stats.total);
	printf("fuzz,adversarial_parse_ok,adversarial,0,%u\n",
	       adv_stats.parse_ok);
	printf("fuzz,adversarial_traverse_ok,adversarial,0,%u\n",
	       adv_stats.traverse_ok);
	printf("fuzz,adversarial_overflow_err,adversarial,0,%u\n",
	       adv_stats.overflow_err);
	printf("fuzz,adversarial_elapsed_ms,adversarial,0,%.2f\n",
	       adv_elapsed);

	fprintf(stderr,
		"  Total: %u, Full pipeline: %u, Overflow: %u\n",
		adv_stats.total, adv_stats.traverse_ok,
		adv_stats.overflow_err);

	/* Phase 3: Edge case payloads with known-good patterns */
	fprintf(stderr, "=== Edge Case Payloads ===\n");
	struct fuzz_stats edge_stats = { 0 };

	clock_gettime(CLOCK_MONOTONIC, &t0);

	const char *good_patterns[] = {
		"\\.\\./", "GET", "<script", "etc/passwd",
	};
	uint32_t num_good = sizeof(good_patterns) / sizeof(good_patterns[0]);

	for (uint32_t pi = 0; pi < num_good; pi++) {
		/* Empty payload */
		fuzz_pipeline(good_patterns[pi], payload_buf, 0, &edge_stats);

		/* Single byte */
		payload_buf[0] = 'A';
		fuzz_pipeline(good_patterns[pi], payload_buf, 1, &edge_stats);

		/* Max payload */
		gen_random_payload(payload_buf, MAX_FUZZ_PAYLOAD_LEN);
		fuzz_pipeline(good_patterns[pi], payload_buf,
			      MAX_FUZZ_PAYLOAD_LEN, &edge_stats);

		/* All nulls */
		memset(payload_buf, 0, MAX_FUZZ_PAYLOAD_LEN);
		fuzz_pipeline(good_patterns[pi], payload_buf,
			      MAX_FUZZ_PAYLOAD_LEN, &edge_stats);

		/* All 0xFF */
		memset(payload_buf, 0xFF, MAX_FUZZ_PAYLOAD_LEN);
		fuzz_pipeline(good_patterns[pi], payload_buf,
			      MAX_FUZZ_PAYLOAD_LEN, &edge_stats);

		/* Lots of random payloads */
		for (int run = 0; run < FUZZ_PAYLOAD_RUNS / (int)num_good;
		     run++) {
			uint32_t plen =
				xorshift32() % (MAX_FUZZ_PAYLOAD_LEN + 1);
			gen_random_payload(payload_buf, plen);
			fuzz_pipeline(good_patterns[pi], payload_buf, plen,
				      &edge_stats);
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &t1);
	double edge_elapsed = time_diff_ms(&t0, &t1);

	printf("fuzz,edge_total,edge,0,%u\n", edge_stats.total);
	printf("fuzz,edge_traverse_ok,edge,0,%u\n", edge_stats.traverse_ok);
	printf("fuzz,edge_elapsed_ms,edge,0,%.2f\n", edge_elapsed);

	fprintf(stderr,
		"  Total: %u, All traversals OK: %u\n",
		edge_stats.total, edge_stats.traverse_ok);

	/* Summary */
	uint32_t grand_total = random_stats.total + adv_stats.total +
			       edge_stats.total;
	uint32_t grand_ok = random_stats.traverse_ok +
			    adv_stats.traverse_ok + edge_stats.traverse_ok;
	double grand_elapsed = random_elapsed + adv_elapsed + edge_elapsed;

	printf("fuzz,grand_total,summary,0,%u\n", grand_total);
	printf("fuzz,grand_pipeline_ok,summary,0,%u\n", grand_ok);
	printf("fuzz,grand_elapsed_ms,summary,0,%.2f\n", grand_elapsed);

	fprintf(stderr,
		"\n=== FUZZ SUMMARY ===\n"
		"Total tests:       %u\n"
		"Full pipeline OK:  %u (%.1f%%)\n"
		"Total time:        %.1f ms\n"
		"NO CRASHES.\n",
		grand_total, grand_ok,
		grand_total > 0 ? 100.0 * grand_ok / grand_total : 0.0,
		grand_elapsed);

	return 0;
}
