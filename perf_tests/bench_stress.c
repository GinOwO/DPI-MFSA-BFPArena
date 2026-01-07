/**
 * @file bench_stress.c
 * @brief Stress test: large rulesets, varied payloads, scaling analysis.
 *
 * Tests the full pipeline with 30+ realistic patterns at various
 * rule counts, payload sizes, and payload types. Reports compile time,
 * state/EC counts, blob size, traversal throughput (MB/s, pkts/s).
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

#define WARMUP_RUNS	5
#define COMPILE_RUNS	50
#define TRAVERSE_RUNS	200
#define TRAVERSE_ITERS	10000
#define MAX_PAYLOAD	1500

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

/* Realistic patterns derived from common Snort/ET signatures */
static const char *patterns[] = {
	/* Path traversal */
	"\\.\\./",
	"\\.\\.\\.\\./",
	/* SQL injection */
	"UNION",
	"SELECT",
	"DROP",
	"INSERT",
	"DELETE",
	"UPDATE",
	/* XSS */
	"<script",
	"javascript:",
	"onerror",
	"onload",
	/* Shell commands */
	"/bin/sh",
	"/bin/bash",
	"cmd\\.exe",
	/* HTTP methods / headers */
	"GET",
	"POST",
	"PUT",
	/* File inclusions */
	"etc/passwd",
	"etc/shadow",
	"proc/self",
	/* Web shells / backdoors */
	"eval\\(",
	"exec\\(",
	"system\\(",
	/* Protocol patterns */
	"HTTP/1",
	"HTTP/2",
	"User-Agent:",
	/* Wildcard patterns for substring matching */
	".*\\.\\./.*",
	".*etc/passwd.*",
	".*<script.*",
	".*UNION.*SELECT.*",
};
#define NUM_PATTERNS (sizeof(patterns) / sizeof(patterns[0]))

/* Payload types for traversal benchmarks */
enum payload_type {
	PAYLOAD_ZEROS,
	PAYLOAD_RANDOM,
	PAYLOAD_ASCII_TEXT,
	PAYLOAD_HTTP_GET,
	PAYLOAD_HTTP_POST,
	PAYLOAD_ATTACK_PATH,
	PAYLOAD_ATTACK_SQL,
	PAYLOAD_ATTACK_XSS,
	PAYLOAD_BINARY_MIXED,
	PAYLOAD_WORST_CASE,
	NUM_PAYLOAD_TYPES,
};

static const char *payload_names[] = {
	"zeros", "random", "ascii_text", "http_get", "http_post",
	"attack_path", "attack_sql", "attack_xss", "binary_mixed",
	"worst_case",
};

static uint32_t xorshift_state = 0xDEADBEEF;

static uint32_t xorshift32(void)
{
	uint32_t x = xorshift_state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	xorshift_state = x;
	return x;
}

static void fill_payload(uint8_t *buf, uint32_t len, enum payload_type type)
{
	switch (type) {
	case PAYLOAD_ZEROS:
		memset(buf, 0, len);
		break;

	case PAYLOAD_RANDOM:
		for (uint32_t i = 0; i < len; i++)
			buf[i] = (uint8_t)(xorshift32() & 0xFF);
		break;

	case PAYLOAD_ASCII_TEXT:
		for (uint32_t i = 0; i < len; i++)
			buf[i] = (uint8_t)(32 + (xorshift32() % 95));
		break;

	case PAYLOAD_HTTP_GET: {
		const char *req = "GET /index.html HTTP/1.1\r\n"
				  "Host: example.com\r\n"
				  "User-Agent: Mozilla/5.0\r\n"
				  "Accept: text/html\r\n\r\n";
		uint32_t rlen = (uint32_t)strlen(req);
		for (uint32_t i = 0; i < len; i++)
			buf[i] = (uint8_t)req[i % rlen];
		break;
	}

	case PAYLOAD_HTTP_POST: {
		const char *req = "POST /api/login HTTP/1.1\r\n"
				  "Host: example.com\r\n"
				  "Content-Type: application/json\r\n"
				  "Content-Length: 42\r\n\r\n"
				  "{\"user\":\"admin\",\"pass\":\"secret123\"}";
		uint32_t rlen = (uint32_t)strlen(req);
		for (uint32_t i = 0; i < len; i++)
			buf[i] = (uint8_t)req[i % rlen];
		break;
	}

	case PAYLOAD_ATTACK_PATH: {
		const char *atk = "GET /../../etc/passwd HTTP/1.1\r\n"
				  "Host: target.com\r\n\r\n";
		uint32_t alen = (uint32_t)strlen(atk);
		for (uint32_t i = 0; i < len; i++)
			buf[i] = (uint8_t)atk[i % alen];
		break;
	}

	case PAYLOAD_ATTACK_SQL: {
		const char *atk = "GET /search?q=1' UNION SELECT * FROM "
				  "users-- HTTP/1.1\r\nHost: target.com"
				  "\r\n\r\n";
		uint32_t alen = (uint32_t)strlen(atk);
		for (uint32_t i = 0; i < len; i++)
			buf[i] = (uint8_t)atk[i % alen];
		break;
	}

	case PAYLOAD_ATTACK_XSS: {
		const char *atk = "GET /page?q=<script>alert(1)</script>"
				  " HTTP/1.1\r\nHost: target.com\r\n\r\n";
		uint32_t alen = (uint32_t)strlen(atk);
		for (uint32_t i = 0; i < len; i++)
			buf[i] = (uint8_t)atk[i % alen];
		break;
	}

	case PAYLOAD_BINARY_MIXED:
		for (uint32_t i = 0; i < len; i++) {
			if (i % 4 == 0)
				buf[i] = 0x00;
			else if (i % 4 == 1)
				buf[i] = 0xFF;
			else
				buf[i] = (uint8_t)(xorshift32() & 0xFF);
		}
		break;

	case PAYLOAD_WORST_CASE:
		/* Alternating chars that keep DFA near transitions */
		for (uint32_t i = 0; i < len; i++)
			buf[i] = (i % 2 == 0) ? '.' : '/';
		break;

	default:
		memset(buf, 'A', len);
		break;
	}
}

struct compile_result {
	double time_ms;
	uint32_t num_states;
	uint32_t num_ec;
	uint32_t blob_size;
	int rc;
};

static struct compile_result compile_rules(uint32_t n)
{
	struct compile_result res = { 0 };
	struct timespec t0, t1;

	struct re_token_stream *streams = calloc(n, sizeof(*streams));
	uint32_t *rule_ids = calloc(n, sizeof(*rule_ids));
	if (!streams || !rule_ids) {
		res.rc = ZDPI_ERR_NOMEM;
		free(streams);
		free(rule_ids);
		return res;
	}

	for (uint32_t i = 0; i < n; i++) {
		res.rc = regex_parse(patterns[i % NUM_PATTERNS],
				     &streams[i]);
		if (res.rc) {
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

	if (n == 1)
		res.rc = nfa_build(&streams[0], &nfa_g);
	else
		res.rc = nfa_build_union(streams, n, rule_ids, &nfa_g);

	if (res.rc) {
		nfa_free(&nfa_g);
		goto out;
	}

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

	res.time_ms = time_diff_ms(&t0, &t1);
	res.num_states = dfa_g.num_states;
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

static void bench_compile_scaling(void)
{
	uint32_t rule_counts[] = { 1, 2, 5, 10, 15, 20, 25, 30 };
	uint32_t num_counts = sizeof(rule_counts) / sizeof(rule_counts[0]);

	for (uint32_t ci = 0; ci < num_counts; ci++) {
		uint32_t n = rule_counts[ci];
		if (n > NUM_PATTERNS)
			n = NUM_PATTERNS;

		for (int iter = 0; iter < WARMUP_RUNS + COMPILE_RUNS;
		     iter++) {
			struct compile_result r = compile_rules(n);
			if (r.rc != 0) {
				fprintf(stderr,
					"compile failed: n=%u rc=%d\n",
					n, r.rc);
				continue;
			}
			if (iter >= WARMUP_RUNS) {
				int run = iter - WARMUP_RUNS;
				printf("stress_compile,compile_%u_rules,"
				       "n%u,%d,%.4f\n",
				       n, n, run, r.time_ms);
				printf("stress_compile,states_%u_rules,"
				       "n%u,%d,%u\n",
				       n, n, run, r.num_states);
				printf("stress_compile,ec_%u_rules,"
				       "n%u,%d,%u\n",
				       n, n, run, r.num_ec);
				printf("stress_compile,blob_%u_rules,"
				       "n%u,%d,%u\n",
				       n, n, run, r.blob_size);
			}
		}
	}
}

static void bench_traverse_payloads(void)
{
	/* Build a combined DFA from 10 rules */
	uint32_t n = 10;
	struct re_token_stream streams[10];
	uint32_t rule_ids[10];
	struct nfa nfa_g;
	struct dfa dfa_g;
	struct ec_map ecm;
	struct ec_table ect;
	struct arena_blob blob;
	int rc;

	for (uint32_t i = 0; i < n; i++) {
		rc = regex_parse(patterns[i], &streams[i]);
		if (rc) {
			fprintf(stderr, "parse failed: %d\n", rc);
			return;
		}
		rule_ids[i] = i + 1;
	}

	rc = nfa_alloc(&nfa_g, NFA_DEFAULT_CAPACITY);
	if (rc)
		return;
	rc = nfa_build_union(streams, n, rule_ids, &nfa_g);
	if (rc) {
		nfa_free(&nfa_g);
		return;
	}
	rc = dfa_alloc(&dfa_g, ZDPI_MAX_STATES);
	if (rc) {
		nfa_free(&nfa_g);
		return;
	}
	rc = dfa_build(&nfa_g, &dfa_g);
	nfa_free(&nfa_g);
	if (rc) {
		dfa_free(&dfa_g);
		return;
	}
	rc = dfa_minimize(&dfa_g);
	if (rc) {
		dfa_free(&dfa_g);
		return;
	}
	rc = ec_compute(&dfa_g, &ecm);
	if (rc) {
		dfa_free(&dfa_g);
		return;
	}
	rc = ec_table_build(&dfa_g, &ecm, &ect);
	if (rc) {
		dfa_free(&dfa_g);
		return;
	}
	rc = linearize(&ecm, &ect, &blob);
	dfa_free(&dfa_g);
	ec_table_free(&ect);
	if (rc)
		return;

	/* Test each payload type at various sizes */
	uint32_t payload_sizes[] = { 64, 128, 256, 512, 1024, 1500 };
	uint32_t num_sizes = sizeof(payload_sizes) / sizeof(payload_sizes[0]);

	uint8_t *payload = malloc(MAX_PAYLOAD);
	if (!payload) {
		arena_blob_free(&blob);
		return;
	}

	for (uint32_t pi = 0; pi < NUM_PAYLOAD_TYPES; pi++) {
		for (uint32_t si = 0; si < num_sizes; si++) {
			uint32_t plen = payload_sizes[si];
			fill_payload(payload, plen,
				     (enum payload_type)pi);

			for (int iter = 0;
			     iter < WARMUP_RUNS + TRAVERSE_RUNS;
			     iter++) {
				struct timespec t0, t1;
				uint32_t drops = 0;

				clock_gettime(CLOCK_MONOTONIC, &t0);
				for (int i = 0; i < TRAVERSE_ITERS; i++) {
					int act = linearize_simulate(
						&blob, payload, plen);
					if (act == ZDPI_ACTION_DROP)
						drops++;
				}
				clock_gettime(CLOCK_MONOTONIC, &t1);

				if (iter < WARMUP_RUNS)
					continue;

				int run = iter - WARMUP_RUNS;
				double elapsed_us =
					time_diff_us(&t0, &t1);
				double bytes_total =
					(double)plen * TRAVERSE_ITERS;
				double mb_per_sec =
					bytes_total / elapsed_us;
				double ns_per_pkt =
					elapsed_us * 1e3 / TRAVERSE_ITERS;

				printf("stress_traverse,%s_%uB,%s_%u,"
				       "%d,%.4f\n",
				       payload_names[pi], plen,
				       payload_names[pi], plen,
				       run, elapsed_us / 1e3);
				printf("stress_throughput,%s_%uB_MBps,"
				       "%s_%u,%d,%.2f\n",
				       payload_names[pi], plen,
				       payload_names[pi], plen,
				       run, mb_per_sec);
				printf("stress_latency,%s_%uB_ns,"
				       "%s_%u,%d,%.2f\n",
				       payload_names[pi], plen,
				       payload_names[pi], plen,
				       run, ns_per_pkt);
				if (run == 0)
					printf("stress_drops,%s_%uB_rate,"
					       "%s_%u,0,%.4f\n",
					       payload_names[pi], plen,
					       payload_names[pi], plen,
					       (double)drops /
						       TRAVERSE_ITERS);
			}
		}
	}

	free(payload);
	arena_blob_free(&blob);
}

int main(void)
{
	printf("test,description,variant,run,value\n");

	fprintf(stderr, "=== Compile Scaling ===\n");
	bench_compile_scaling();

	fprintf(stderr, "=== Traverse Payloads ===\n");
	bench_traverse_payloads();

	return 0;
}
