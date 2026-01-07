/**
 * @file bench_arena_throughput.c
 * @brief Synthetic large-DFA throughput benchmark for BPF Arena.
 *
 * Constructs synthetic DFA blobs from 4MB to 768MB (bypassing
 * NFA->DFA compilation) and measures packet traversal throughput.
 * Demonstrates that BPF Arena enables DFA tables far exceeding
 * the 32KB/4MB BPF map limits, with measurable packet throughput.
 *
 * The DFA traversal is a serial pointer-chasing pattern: each
 * table lookup depends on the previous state. This makes it
 * memory-latency bound small tables that fit in L3 cache
 * achieve high throughput, while large tables that spill to DRAM
 * show the latency cost. But they WORK, which is impossible
 * with regular BPF maps (32KB value / 4MB total limit).
 *
 * Three traversal modes:
 *   1. Serial (baseline): one packet at a time via linearize_simulate()
 *   2. Batched: K packets processed in lockstep, exploiting
 *      memory-level parallelism (MLP) for independent DRAM requests
 *   3. Realistic: transitions biased toward hot states (simulating
 *      a real DFA where most input doesn't advance the match)
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.0.2
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "zdpi_types.h"
#include "linearize.h"

#define WARMUP_SEC	1.0
#define MEASURE_SEC	5.0
#define INPUT_BUF_SIZE	(64U * 1024 * 1024)
#define BATCH_SIZE	8

enum dfa_mode {
	MODE_RANDOM,
	MODE_REALISTIC,
};

struct throughput_level {
	const char *name;
	uint32_t num_states;
	uint32_t num_ec;
	uint32_t pkt_size;
	int batched;
	enum dfa_mode mode;
};

/*
 * Table size = num_states * num_ec * sizeof(uint32_t).
 * 256 ECs = full byte alphabet (identity mapping).
 * This is worst-case for cache: each row = 1024 bytes.
 *
 *   4 MB:    4096 states (fits BPF map total limit + L3 cache)
 *  32 MB:   32768 states (exceeds BPF map, partially fits L3)
 * 128 MB:  131072 states (exceeds typical L3 cache)
 * 512 MB:  524288 states (deep Arena territory)
 * 768 MB:  786432 states (near Arena 1GB limit)
 *
 * DNS variant (64-byte packets) tests per-packet overhead.
 * MTU variant (1500-byte packets) tests sustained throughput.
 */
static const struct throughput_level levels[] = {
	/* --- Serial traversal, random DFA (worst case) --- */
	{ "4mb_mtu",      4096, 256, 1500, 0, MODE_RANDOM },
	{ "4mb_dns",      4096, 256,   64, 0, MODE_RANDOM },
	{ "32mb_mtu",    32768, 256, 1500, 0, MODE_RANDOM },
	{ "128mb_mtu",  131072, 256, 1500, 0, MODE_RANDOM },
	{ "512mb_mtu",  524288, 256, 1500, 0, MODE_RANDOM },
	{ "768mb_mtu",  786432, 256, 1500, 0, MODE_RANDOM },

	/* --- Batched traversal (8 packets, MLP) --- */
	{ "512mb_batch", 524288, 256, 1500, 1, MODE_RANDOM },
	{ "768mb_batch", 786432, 256, 1500, 1, MODE_RANDOM },

	/*
	 * Realistic DFA: 90% of transitions go to hot states
	 * [1..1024] (~1MB working set fits in L3), simulating
	 * a real regex where most bytes don't advance the match.
	 */
	{ "512mb_real",  524288, 256, 1500, 0, MODE_REALISTIC },
	{ "768mb_real",  786432, 256, 1500, 0, MODE_REALISTIC },

	/* Best case: batched + realistic (cache-friendly + MLP) */
	{ "512mb_best", 524288, 256, 1500, 1, MODE_REALISTIC },
	{ "768mb_best", 786432, 256, 1500, 1, MODE_REALISTIC },
};
#define NUM_LEVELS (sizeof(levels) / sizeof(levels[0]))

static double time_diff_sec(struct timespec *a, struct timespec *b)
{
	return (b->tv_sec - a->tv_sec) +
	       (b->tv_nsec - a->tv_nsec) / 1e9;
}

/*
 * Build a synthetic DFA blob of the requested size.
 *
 * The transition table uses Knuth multiplicative hash to spread
 * next-states across the full range [1..num_states-1], ensuring
 * traversal never hits dead state 0 (which would cause early
 * termination). This creates worst-case cache behavior: each
 * lookup jumps to a pseudo-random row in the table.
 *
 * Accept states: ~0.1% (every 1000th state).
 */
static int build_synthetic_blob(uint32_t num_states, uint32_t num_ec,
				enum dfa_mode mode,
				struct arena_blob *out)
{
	memset(out, 0, sizeof(*out));

	uint32_t table_size = num_states * num_ec *
			      (uint32_t)sizeof(uint32_t);
	uint32_t accept_size = (num_states + 7) / 8;
	uint32_t rule_id_size = num_states * (uint32_t)sizeof(uint32_t);

	uint32_t table_offset = ZDPI_TABLE_OFFSET;
	uint32_t accept_offset = table_offset + table_size;
	uint32_t rule_id_offset = accept_offset + accept_size;
	uint32_t total_size = rule_id_offset + rule_id_size;

	total_size = (total_size + ZDPI_ARENA_PAGE_SIZE - 1) &
		     ~(ZDPI_ARENA_PAGE_SIZE - 1);

	out->data = calloc(1, total_size);
	if (!out->data)
		return ZDPI_ERR_NOMEM;
	out->size = total_size;

	struct zdpi_table_header *hdr =
		(struct zdpi_table_header *)out->data;
	hdr->magic = ZDPI_MAGIC;
	hdr->version_major = 0;
	hdr->version_minor = 0;
	hdr->version_patch = 1;
	hdr->num_states = num_states;
	hdr->num_ec = (uint16_t)num_ec;
	hdr->num_rules = 1;
	hdr->table_offset = table_offset;
	hdr->table_size = table_size;
	hdr->accept_offset = accept_offset;
	hdr->accept_size = accept_size;
	hdr->rule_id_offset = rule_id_offset;
	hdr->rule_id_size = rule_id_size;
	hdr->total_size = total_size;
	hdr->table_ready = 1;
	out->header = *hdr;

	uint8_t *ec_map = out->data + ZDPI_EC_MAP_OFFSET;
	for (int i = 0; i < 256; i++)
		ec_map[i] = (uint8_t)(i % num_ec);

	uint32_t *table =
		(uint32_t *)(out->data + table_offset);
	uint32_t live = num_states - 1;

	if (mode == MODE_REALISTIC) {
		/*
		 * Realistic: 90% of transitions go to hot states
		 * [1..1024] (working set ~1MB in L3 cache).
		 * 10% jump to random deep states. Simulates a real
		 * regex DFA where most input doesn't advance the
		 * match the automaton stays near the start.
		 */
		uint32_t hot_max = 1024;
		if (hot_max >= num_states)
			hot_max = num_states / 2;

		for (uint32_t s = 1; s < num_states; s++) {
			uint32_t rng = s * 2654435761u + 1;
			for (uint32_t e = 0; e < num_ec; e++) {
				rng = rng * 1664525u + 1013904223u;
				if ((rng % 100) < 90)
					table[(uint64_t)s * num_ec + e] =
						(rng >> 8) % hot_max + 1;
				else
					table[(uint64_t)s * num_ec + e] =
						(uint32_t)((uint64_t)rng %
							   live) + 1;
			}
		}
	} else {
		for (uint32_t s = 1; s < num_states; s++) {
			uint64_t h = (uint64_t)s * 2654435761ULL;
			for (uint32_t e = 0; e < num_ec; e++) {
				table[(uint64_t)s * num_ec + e] =
					(uint32_t)((h + e * 40503ULL) %
						   live) + 1;
			}
		}
	}

	uint8_t *accept_bits = out->data + accept_offset;
	uint32_t *rule_ids =
		(uint32_t *)(out->data + rule_id_offset);
	for (uint32_t s = 1000; s < num_states; s += 1000) {
		accept_bits[s / 8] |= (1 << (s % 8));
		rule_ids[s] = s / 1000;
	}

	return ZDPI_OK;
}

/*
 * Batched DFA traversal: process BATCH_SIZE packets in lockstep.
 *
 * Each table lookup for packet B is independent of packet A's state,
 * so the CPU can issue multiple outstanding DRAM requests (MLP).
 * Modern x86 CPUs support 10-20 concurrent memory requests,
 * so batching 8 packets should nearly saturate the memory bus.
 */
static void batch_simulate(const struct arena_blob *blob,
			   const uint8_t *pkts[BATCH_SIZE],
			   uint32_t len, int results[BATCH_SIZE])
{
	const struct zdpi_table_header *hdr =
		(const struct zdpi_table_header *)blob->data;
	const uint8_t *ec_map = blob->data + ZDPI_EC_MAP_OFFSET;
	const uint32_t *table =
		(const uint32_t *)(blob->data + hdr->table_offset);
	const uint8_t *accept = blob->data + hdr->accept_offset;
	uint16_t num_ec = hdr->num_ec;
	uint32_t num_states = hdr->num_states;

	uint32_t state[BATCH_SIZE];
	for (int b = 0; b < BATCH_SIZE; b++)
		state[b] = ZDPI_START_STATE;

	for (uint32_t i = 0; i < len; i++) {
		for (int b = 0; b < BATCH_SIZE; b++) {
			if (state[b] == ZDPI_DEAD_STATE)
				continue;
			uint8_t ec = ec_map[pkts[b][i]];
			state[b] = table[(uint32_t)state[b] *
					 num_ec + ec];
		}
	}

	for (int b = 0; b < BATCH_SIZE; b++) {
		results[b] = ZDPI_ACTION_PASS;
		if (state[b] > ZDPI_DEAD_STATE &&
		    state[b] < num_states) {
			uint32_t bi = state[b] / 8;
			uint8_t bm = 1 << (state[b] % 8);
			if (accept[bi] & bm)
				results[b] = ZDPI_ACTION_DROP;
		}
	}
}

static void run_serial(const struct arena_blob *blob,
		       const uint8_t *input, uint32_t pkt,
		       uint32_t max_off, double sec,
		       uint64_t *out_pkts, uint64_t *out_match)
{
	struct timespec t0, t1;
	uint32_t off = 0;
	uint64_t packets = 0, matches = 0;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (;;) {
		int r = linearize_simulate(blob,
					   input + off, pkt);
		if (r == ZDPI_ACTION_DROP)
			matches++;
		off = (off + pkt) % max_off;
		packets++;
		if ((packets & 0x3FF) == 0) {
			clock_gettime(CLOCK_MONOTONIC, &t1);
			if (time_diff_sec(&t0, &t1) >= sec)
				break;
		}
	}
	*out_pkts = packets;
	*out_match = matches;
}

static void run_batched(const struct arena_blob *blob,
			const uint8_t *input, uint32_t pkt,
			uint32_t max_off, double sec,
			uint64_t *out_pkts, uint64_t *out_match)
{
	struct timespec t0, t1;
	uint32_t off = 0;
	uint64_t packets = 0, matches = 0;
	const uint8_t *pkts[BATCH_SIZE];
	int results[BATCH_SIZE];

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (;;) {
		for (int b = 0; b < BATCH_SIZE; b++) {
			pkts[b] = input + off;
			off = (off + pkt) % max_off;
		}
		batch_simulate(blob, pkts, pkt, results);
		for (int b = 0; b < BATCH_SIZE; b++) {
			if (results[b] == ZDPI_ACTION_DROP)
				matches++;
		}
		packets += BATCH_SIZE;
		if ((packets & 0x3FF) == 0) {
			clock_gettime(CLOCK_MONOTONIC, &t1);
			if (time_diff_sec(&t0, &t1) >= sec)
				break;
		}
	}
	*out_pkts = packets;
	*out_match = matches;
}

static void bench_level(const struct throughput_level *lvl)
{
	struct arena_blob blob;
	struct timespec t0, t1;
	uint64_t table_mb = (uint64_t)lvl->num_states * lvl->num_ec *
			    4 / (1024 * 1024);
	const char *mode_str = lvl->mode == MODE_REALISTIC ?
			       "realistic" : "random";

	fprintf(stderr,
		"\n--- %s: %uK states, %u ECs, ~%lluMB, "
		"%u-byte pkts, %s%s ---\n",
		lvl->name, lvl->num_states / 1024, lvl->num_ec,
		(unsigned long long)table_mb, lvl->pkt_size,
		lvl->batched ? "batch8, " : "",
		mode_str);

	clock_gettime(CLOCK_MONOTONIC, &t0);
	int rc = build_synthetic_blob(lvl->num_states, lvl->num_ec,
				      lvl->mode, &blob);
	clock_gettime(CLOCK_MONOTONIC, &t1);

	if (rc) {
		fprintf(stderr,
			"  FAILED: alloc %lluMB (rc=%d)\n",
			(unsigned long long)table_mb, rc);
		return;
	}

	fprintf(stderr, "  Blob: %u MB, built in %.1f sec\n",
		blob.size / (1024 * 1024),
		time_diff_sec(&t0, &t1));

	uint8_t *input = malloc(INPUT_BUF_SIZE);
	if (!input) {
		fprintf(stderr, "  FAILED: input alloc\n");
		arena_blob_free(&blob);
		return;
	}

	uint64_t rng = 0xDEADBEEFCAFE1234ULL;
	for (uint32_t i = 0; i < INPUT_BUF_SIZE; i += 8) {
		rng ^= rng << 13;
		rng ^= rng >> 7;
		rng ^= rng << 17;
		memcpy(input + i, &rng, 8);
	}

	uint32_t pkt = lvl->pkt_size;
	uint32_t max_off = INPUT_BUF_SIZE - pkt;
	uint64_t dummy_p, dummy_m;

	fprintf(stderr, "  Warming up...\n");
	if (lvl->batched)
		run_batched(&blob, input, pkt, max_off,
			    WARMUP_SEC, &dummy_p, &dummy_m);
	else
		run_serial(&blob, input, pkt, max_off,
			   WARMUP_SEC, &dummy_p, &dummy_m);

	fprintf(stderr, "  Measuring (%.0fs)...\n", MEASURE_SEC);
	uint64_t packets, matches;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	if (lvl->batched)
		run_batched(&blob, input, pkt, max_off,
			    MEASURE_SEC, &packets, &matches);
	else
		run_serial(&blob, input, pkt, max_off,
			   MEASURE_SEC, &packets, &matches);
	clock_gettime(CLOCK_MONOTONIC, &t1);

	double elapsed = time_diff_sec(&t0, &t1);
	uint64_t total_bytes = packets * pkt;
	double gbps = (double)total_bytes * 8.0 /
		      elapsed / 1e9;
	double mpps = (double)packets / elapsed / 1e6;
	double ns_byte = elapsed * 1e9 / (double)total_bytes;
	double match_pct = 100.0 * (double)matches /
			   (double)packets;
	uint64_t arena_total = (uint64_t)ZDPI_ARENA_PAGES *
			       ZDPI_ARENA_PAGE_SIZE;
	double arena_pct = 100.0 * (double)blob.size /
			   (double)arena_total;

	fprintf(stderr,
		"  %.2f Gbps | %.3f Mpps | %.1f ns/byte | "
		"%.2f%% match | arena=%.1f%%\n",
		gbps, mpps, ns_byte, match_pct, arena_pct);

	printf("arena_throughput,gbps_%s,%s,0,%.4f\n",
	       lvl->name, lvl->name, gbps);
	printf("arena_throughput,mpps_%s,%s,0,%.6f\n",
	       lvl->name, lvl->name, mpps);
	printf("arena_throughput,ns_byte_%s,%s,0,%.4f\n",
	       lvl->name, lvl->name, ns_byte);
	printf("arena_throughput,blob_mb_%s,%s,0,%u\n",
	       lvl->name, lvl->name,
	       blob.size / (1024 * 1024));
	printf("arena_throughput,table_mb_%s,%s,0,%llu\n",
	       lvl->name, lvl->name,
	       (unsigned long long)table_mb);
	printf("arena_throughput,arena_pct_%s,%s,0,%.4f\n",
	       lvl->name, lvl->name, arena_pct);
	printf("arena_throughput,match_pct_%s,%s,0,%.4f\n",
	       lvl->name, lvl->name, match_pct);
	printf("arena_throughput,packets_%s,%s,0,%llu\n",
	       lvl->name, lvl->name,
	       (unsigned long long)packets);

	free(input);
	arena_blob_free(&blob);
}

int main(void)
{
	printf("test,description,variant,run,value\n");

	fprintf(stderr, "=== Arena Throughput Benchmark ===\n");
	fprintf(stderr,
		"Arena capacity: %u pages * %u = %llu MB\n",
		ZDPI_ARENA_PAGES, ZDPI_ARENA_PAGE_SIZE,
		(unsigned long long)ZDPI_ARENA_PAGES *
			ZDPI_ARENA_PAGE_SIZE / (1024 * 1024));
	fprintf(stderr,
		"BPF map limits: 32KB value, 4MB total\n");
	fprintf(stderr,
		"Traversal: serial lookup chain "
		"(memory-latency bound)\n");
	fprintf(stderr,
		"Measure: %.0fs per level after "
		"%.0fs warmup\n", MEASURE_SEC, WARMUP_SEC);

	for (uint32_t i = 0; i < NUM_LEVELS; i++)
		bench_level(&levels[i]);

	fprintf(stderr, "\n=== Done ===\n");
	return 0;
}
