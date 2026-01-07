/**
 * @file bench_mfsa.c
 * @brief Benchmark comparing MFSA product-state merge vs NFA union DFA.
 *
 * For increasing numbers of patterns (1-100), compares:
 * - MFSA: build individual DFAs + product-state merge
 * - Union: NFA union + single subset construction
 *
 * Reports: state count, EC count, table size, compile time.
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.1.0
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
#include "mfsa.h"
#include "ec_compress.h"
#include "linearize.h"

static double time_diff_ms(struct timespec *a, struct timespec *b)
{
	return (b->tv_sec - a->tv_sec) * 1000.0 +
	       (b->tv_nsec - a->tv_nsec) / 1e6;
}

/* Patterns with shared prefixes to demonstrate MFSA compression */
static const char *patterns[] = {
	"http",	    "https",     "httpd",     "ftp",
	"ftps",	    "ssh",	 "telnet",    "smtp",
	"smtps",    "imap",	 "imaps",     "pop3",
	"dns",	    "dhcp",	 "snmp",      "ntp",
	"GET",	    "POST",	 "PUT",	      "DELETE",
	"HEAD",	    "OPTIONS",	 "CONNECT",   "TRACE",
	"PATCH",    "HTTP/1",	 "HTTP/2",    "User-Agent",
	"Host:",    "Content",	 "Accept",    "Cookie",
	"SELECT",   "INSERT",	 "UPDATE",    "DROP",
	"CREATE",   "ALTER",	 "DELETE FROM", "EXEC",
	"admin",    "root",	 "password",  "login",
	"logout",   "register", "passwd",    "shadow",
	"etc/passwd", "bin/sh", "bin/bash",  "dev/null",
	"alert",    "drop",	 "reject",    "pass",
	"tcp",	    "udp",	 "icmp",      "arp",
	"vlan",	    "mpls",	 "gre",	      "ipsec",
	"tls",	    "ssl",	 "x509",      "cert",
	"key",	    "hash",	 "hmac",      "sha256",
	"md5",	    "aes",	 "rsa",	      "dsa",
	"xml",	    "json",	 "html",      "css",
	"java",	    "php",	 "python",    "ruby",
	"node",	    "npm",	 "yarn",      "webpack",
	"docker",   "kube",	 "helm",      "nginx",
	"apache",   "mysql",	 "postgres",  "redis",
	"mongo",    "elastic",	 "kafka",     "rabbit",
	"cmd.exe",  "powershell", "whoami",  "netstat",
};
#define NUM_PATTERNS (sizeof(patterns) / sizeof(patterns[0]))

static const uint32_t steps[] = {
	1, 2, 3, 5, 8, 10, 15, 20, 30, 50, 75, 100
};
#define NUM_STEPS (sizeof(steps) / sizeof(steps[0]))

struct bench_result {
	uint32_t num_rules;
	uint32_t states;
	uint32_t ec;
	uint64_t table_kb;
	uint32_t blob_kb;
	double compile_ms;
	int rc;
};

static struct bench_result bench_union(struct re_token_stream *streams,
				       uint32_t count)
{
	struct bench_result res = { .num_rules = count };
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
	if (count > 20)
		nfa_cap = count * 256;

	res.rc = nfa_alloc(&nfa_g, nfa_cap);
	if (res.rc)
		goto out;

	res.rc = nfa_build_union(streams, count, rule_ids, &nfa_g);
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

	res.compile_ms = time_diff_ms(&t0, &t1);
	res.states = dfa_g.num_states;
	res.ec = ecm.num_ec;
	res.table_kb = (uint64_t)dfa_g.num_states * ecm.num_ec *
		       sizeof(uint32_t) / 1024;
	if (res.rc == 0)
		res.blob_kb = blob.size / 1024;

	dfa_free(&dfa_g);
	ec_table_free(&ect);
	if (res.rc == 0)
		arena_blob_free(&blob);
out:
	free(rule_ids);
	return res;
}

static struct bench_result bench_mfsa(struct re_token_stream *streams,
				      uint32_t count)
{
	struct bench_result res = { .num_rules = count };
	struct timespec t0, t1;
	uint32_t *rule_ids = calloc(count, sizeof(*rule_ids));
	if (!rule_ids) {
		res.rc = ZDPI_ERR_NOMEM;
		return res;
	}
	for (uint32_t i = 0; i < count; i++)
		rule_ids[i] = i + 1;

	struct mfsa mfsa_g;
	struct arena_blob blob;

	clock_gettime(CLOCK_MONOTONIC, &t0);

	res.rc = mfsa_build(streams, count, rule_ids, &mfsa_g);
	if (res.rc)
		goto out;

	/* Shared EC across all DFAs */
	const struct dfa **dfa_ptrs =
		malloc(mfsa_g.num_dfas * sizeof(struct dfa *));
	if (!dfa_ptrs) {
		mfsa_free(&mfsa_g);
		res.rc = ZDPI_ERR_NOMEM;
		goto out;
	}
	for (uint32_t i = 0; i < mfsa_g.num_dfas; i++)
		dfa_ptrs[i] = &mfsa_g.dfas[i];

	struct ec_map ecm;
	res.rc = ec_compute_multi(dfa_ptrs, mfsa_g.num_dfas, &ecm);
	free(dfa_ptrs);
	if (res.rc) {
		mfsa_free(&mfsa_g);
		goto out;
	}

	/* Per-DFA EC tables */
	struct ec_table *ects =
		calloc(mfsa_g.num_dfas, sizeof(struct ec_table));
	if (!ects) {
		mfsa_free(&mfsa_g);
		res.rc = ZDPI_ERR_NOMEM;
		goto out;
	}
	for (uint32_t i = 0; i < mfsa_g.num_dfas; i++) {
		res.rc = ec_table_build(&mfsa_g.dfas[i], &ecm,
					&ects[i]);
		if (res.rc) {
			for (uint32_t j = 0; j < i; j++)
				ec_table_free(&ects[j]);
			free(ects);
			mfsa_free(&mfsa_g);
			goto out;
		}
	}

	res.rc = linearize_parallel(&ecm, ects, mfsa_g.num_dfas,
				    mfsa_g.rule_ids, &blob);

	clock_gettime(CLOCK_MONOTONIC, &t1);

	res.compile_ms = time_diff_ms(&t0, &t1);

	/* Sum total states across all DFAs */
	res.states = 0;
	for (uint32_t i = 0; i < mfsa_g.num_dfas; i++)
		res.states += mfsa_g.dfas[i].num_states;
	res.ec = ecm.num_ec;
	res.table_kb = 0;
	for (uint32_t i = 0; i < mfsa_g.num_dfas; i++)
		res.table_kb += (uint64_t)mfsa_g.dfas[i].num_states *
				ecm.num_ec * sizeof(uint16_t) / 1024;
	if (res.rc == 0)
		res.blob_kb = blob.size / 1024;

	for (uint32_t i = 0; i < mfsa_g.num_dfas; i++)
		ec_table_free(&ects[i]);
	free(ects);
	mfsa_free(&mfsa_g);
	if (res.rc == 0)
		arena_blob_free(&blob);
out:
	free(rule_ids);
	return res;
}

int main(void)
{
	/* Parse all patterns */
	struct re_token_stream *streams =
		calloc(NUM_PATTERNS, sizeof(*streams));
	if (!streams)
		return 1;

	uint32_t parsed = 0;
	for (uint32_t i = 0; i < NUM_PATTERNS; i++) {
		if (regex_parse(patterns[i], &streams[parsed]) == 0)
			parsed++;
	}

	fprintf(stderr, "Parsed %u/%zu patterns\n", parsed,
		NUM_PATTERNS);

	printf("test,description,variant,run,value\n");

	for (uint32_t si = 0; si < NUM_STEPS; si++) {
		uint32_t n = steps[si];
		if (n > parsed)
			break;

		fprintf(stderr, "\n--- %u rules ---\n", n);

		/* Union approach */
		struct bench_result u = bench_union(streams, n);
		if (u.rc == 0) {
			fprintf(stderr,
				"  UNION:  states=%u ec=%u "
				"table=%lluKB time=%.1fms\n",
				u.states, u.ec,
				(unsigned long long)u.table_kb,
				u.compile_ms);
			printf("mfsa_cmp,union_states,%u,0,%u\n",
			       n, u.states);
			printf("mfsa_cmp,union_table_kb,%u,0,%llu\n",
			       n, (unsigned long long)u.table_kb);
			printf("mfsa_cmp,union_compile_ms,%u,0,%.1f\n",
			       n, u.compile_ms);
		} else {
			fprintf(stderr,
				"  UNION:  FAILED rc=%d\n", u.rc);
			printf("mfsa_cmp,union_error,%u,0,%d\n",
			       n, u.rc);
		}

		/* MFSA approach */
		struct bench_result m = bench_mfsa(streams, n);
		if (m.rc == 0) {
			fprintf(stderr,
				"  MFSA:   states=%u ec=%u "
				"table=%lluKB time=%.1fms\n",
				m.states, m.ec,
				(unsigned long long)m.table_kb,
				m.compile_ms);
			printf("mfsa_cmp,mfsa_states,%u,0,%u\n",
			       n, m.states);
			printf("mfsa_cmp,mfsa_table_kb,%u,0,%llu\n",
			       n, (unsigned long long)m.table_kb);
			printf("mfsa_cmp,mfsa_compile_ms,%u,0,%.1f\n",
			       n, m.compile_ms);
		} else {
			fprintf(stderr,
				"  MFSA:   FAILED rc=%d\n", m.rc);
			printf("mfsa_cmp,mfsa_error,%u,0,%d\n",
			       n, m.rc);
		}

		/* Compression ratio */
		if (u.rc == 0 && m.rc == 0 && u.states > 0) {
			double ratio = 1.0 - (double)m.states / u.states;
			fprintf(stderr,
				"  RATIO:  %.1f%% state reduction, "
				"%.1fx faster\n",
				ratio * 100,
				u.compile_ms / m.compile_ms);
			printf("mfsa_cmp,state_reduction_pct,%u,0,%.1f\n",
			       n, ratio * 100);
			printf("mfsa_cmp,speedup,%u,0,%.2f\n",
			       n, u.compile_ms / m.compile_ms);
		}
	}

	free(streams);
	fprintf(stderr, "\nDone.\n");
	return 0;
}
