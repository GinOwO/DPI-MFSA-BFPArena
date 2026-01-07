/**
 * @file main.c
 * @brief ZDPI CLI entry point.
 *
 * Parses command-line arguments, compiles Snort rules through the
 * full pipeline, flashes the table to the BPF arena, and attaches
 * the XDP program.
 *
 * Supports two compilation modes:
 * - Union (-u): NFA union -> single DFA -> minimize
 * - MFSA (default): individual DFAs -> parallel v2 arena
 *
 * @author Kiran P Das
 * @date 2026-02-21
 * @version 0.3.0
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>

#include "zdpi_types.h"
#include "zdpi_log.h"
#include "rule_parser.h"
#include "regex_parser.h"
#include "nfa.h"
#include "dfa.h"
#include "mfsa.h"
#include "ac.h"
#include "ec_compress.h"
#include "linearize.h"
#include "arena_flash.h"

static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t print_stats_flag = 0;
static struct zdpi_handle *g_handle = NULL;

static void sig_handler(int sig)
{
	if (sig == SIGUSR1)
		print_stats_flag = 1;
	else
		running = 0;
}

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -r <rules_file> -i <interface> [options]\n"
		"\n"
		"Options:\n"
		"  -r <file>      Snort rule file\n"
		"  -i <iface>     Network interface to attach XDP\n"
		"  -u             Use NFA union mode (default: AC+MFSA)\n"
		"  --no-ac        Disable AC pre-filter (force V2 MFSA)\n"
		"  -v, --verbose  Verbose output (show DEBUG messages)\n"
		"  -w, --warnings Show WARNING messages\n"
		"  -d             Dry run (compile only, no BPF)\n"
		"  -V             Print version and exit\n"
		"  -h             Show this help\n",
		prog);
}

static void print_version(void)
{
	printf("zdpi-cli v%s.%s.%s\n", ZDPI_VERSION_MAJOR,
	       ZDPI_VERSION_MINOR, ZDPI_VERSION_PATCH);
}

static double timespec_diff_ms(struct timespec *a, struct timespec *b)
{
	return (b->tv_sec - a->tv_sec) * 1000.0 +
	       (b->tv_nsec - a->tv_nsec) / 1e6;
}

/*
 * Union pipeline: NFA union -> single DFA -> minimize.
 * The original approach works but scales poorly with many rules.
 */
static int compile_union(struct re_token_stream *streams,
			 uint32_t *rule_ids, uint32_t num_rules,
			 struct dfa *out)
{
	struct nfa nfa_graph;
	uint32_t nfa_cap = NFA_DEFAULT_CAPACITY;
	if (num_rules > 20)
		nfa_cap = num_rules * 256;

	int rc = nfa_alloc(&nfa_graph, nfa_cap);
	if (rc)
		return rc;

	if (num_rules == 1) {
		rc = nfa_build(&streams[0], &nfa_graph);
		if (rc == ZDPI_OK)
			nfa_graph.states[nfa_graph.accept].rule_id =
				rule_ids[0];
	} else {
		rc = nfa_build_union(streams, num_rules, rule_ids,
				     &nfa_graph);
	}

	if (rc) {
		nfa_free(&nfa_graph);
		return rc;
	}
	LOG_DBG("NFA: %u states", nfa_graph.num_states);

	rc = dfa_alloc(out, ZDPI_MAX_STATES);
	if (rc) {
		nfa_free(&nfa_graph);
		return rc;
	}

	rc = dfa_build(&nfa_graph, out);
	nfa_free(&nfa_graph);
	if (rc) {
		dfa_free(out);
		return rc;
	}
	LOG_DBG("DFA: %u states (before minimization)",
		out->num_states);

	rc = dfa_minimize(out);
	if (rc) {
		dfa_free(out);
		return rc;
	}
	LOG_DBG("DFA: %u states (after minimization)",
		out->num_states);

	return ZDPI_OK;
}

/*
 * MFSA pipeline: build individual minimized DFAs.
 * Returns the DFA array in `out`; caller owns the mfsa struct.
 */
static int compile_mfsa(struct re_token_stream *streams,
			uint32_t *rule_ids, uint32_t num_rules,
			struct mfsa *out)
{
	return mfsa_build(streams, num_rules, rule_ids, out);
}

static const struct option long_opts[] = {
	{ "verbose",  no_argument, NULL, 'v' },
	{ "warnings", no_argument, NULL, 'w' },
	{ "no-ac",    no_argument, NULL, 'A' },
	{ "help",     no_argument, NULL, 'h' },
	{ "version",  no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 }
};

int main(int argc, char **argv)
{
	const char *rules_path = NULL;
	const char *ifname = NULL;
	int dry_run = 0;
	int use_mfsa = 1;
	int no_ac = 0;
	enum zdpi_log_level log_level = ZDPI_LOG_INFO;
	int opt;

	while ((opt = getopt_long(argc, argv, "r:i:uvwdVh",
				  long_opts, NULL)) != -1) {
		switch (opt) {
		case 'r':
			rules_path = optarg;
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'u':
			use_mfsa = 0;
			break;
		case 'A':
			no_ac = 1;
			break;
		case 'v':
			log_level = ZDPI_LOG_DEBUG;
			break;
		case 'w':
			if (log_level > ZDPI_LOG_WARN)
				log_level = ZDPI_LOG_WARN;
			break;
		case 'd':
			dry_run = 1;
			break;
		case 'V':
			print_version();
			return 0;
		case 'h':
		default:
			print_usage(argv[0]);
			return (opt == 'h') ? 0 : 1;
		}
	}

	zdpi_log_init(log_level, 1);

	if (!rules_path) {
		LOG_ERR("-r <rules_file> required");
		print_usage(argv[0]);
		return 1;
	}

	if (!ifname && !dry_run) {
		LOG_ERR("-i <interface> required (or use -d for dry run)");
		print_usage(argv[0]);
		return 1;
	}

	/* Parse rules */
	struct zdpi_ruleset ruleset;
	int rc = ruleset_alloc(&ruleset, ZDPI_MAX_RULES);
	if (rc) {
		LOG_ERR("Ruleset alloc failed");
		return 1;
	}
	rc = ruleset_parse_file(rules_path, &ruleset);
	if (rc) {
		LOG_ERR("Failed to parse rules: %d", rc);
		ruleset_free(&ruleset);
		return 1;
	}

	if (ruleset.num_rules == 0) {
		LOG_ERR("No rules found in %s", rules_path);
		ruleset_free(&ruleset);
		return 1;
	}

	LOG_INF("Parsed %u rules from %s",
		ruleset.num_rules, rules_path);

	/* Parse regex patterns and collect content keywords */
	struct re_token_stream *streams =
		calloc(ruleset.num_rules, sizeof(struct re_token_stream));
	uint32_t *rule_ids =
		calloc(ruleset.num_rules, sizeof(uint32_t));
	/* Per-rule: index of longest content keyword, or -1 if none */
	int *content_rule_map =
		calloc(ruleset.num_rules, sizeof(int));
	/* Per-rule: copy of longest content (owned) */
	struct zdpi_content *best_contents =
		calloc(ruleset.num_rules,
		       sizeof(struct zdpi_content));
	/* Track which rules have content */
	int *has_content =
		calloc(ruleset.num_rules, sizeof(int));
	if (!streams || !rule_ids || !content_rule_map ||
	    !best_contents || !has_content) {
		LOG_ERR("Out of memory");
		free(streams);
		free(rule_ids);
		free(content_rule_map);
		free(best_contents);
		free(has_content);
		ruleset_free(&ruleset);
		return 1;
	}

	uint32_t valid = 0;
	uint32_t skipped = 0;
	uint32_t rules_with_content = 0;
	for (uint32_t i = 0; i < ruleset.num_rules; i++) {
		rc = regex_parse(ruleset.rules[i].pcre, &streams[valid]);
		if (rc) {
			LOG_DBG("Skip SID %u: regex parse error %d",
				ruleset.rules[i].sid, rc);
			skipped++;
			continue;
		}
		rule_ids[valid] = ruleset.rules[i].sid;

		/* Find longest content keyword for this rule */
		content_rule_map[valid] = -1;
		has_content[valid] = 0;
		if (ruleset.rules[i].num_contents > 0) {
			uint32_t best_len = 0;
			struct zdpi_content *best = NULL;
			for (uint32_t ci = 0;
			     ci < ruleset.rules[i].num_contents;
			     ci++) {
				struct zdpi_content *c =
					&ruleset.rules[i].contents[ci];
				if (!c->negated &&
				    c->len > best_len) {
					best_len = c->len;
					best = c;
				}
			}
			if (best) {
				best_contents[valid] = *best;
				has_content[valid] = 1;
				rules_with_content++;
				content_rule_map[valid] = (int)valid;
			}
		}

		LOG_DBG("SID %u: pcre='%s' -> %u tokens, "
			"%u contents",
			ruleset.rules[i].sid,
			ruleset.rules[i].pcre,
			streams[valid].len,
			ruleset.rules[i].num_contents);
		valid++;
	}

	/* Determine pipeline mode */
	int use_v4 = use_mfsa && !no_ac && rules_with_content > 0;
	const char *mode_str = use_mfsa ?
		(use_v4 ? "AC+MFSA (v4)" : "MFSA (parallel v2)") :
		"union";

	if (use_mfsa && !no_ac && rules_with_content == 0)
		LOG_DBG("No content keywords found, using V2 MFSA");

	ruleset_free(&ruleset);

	if (skipped > 0)
		LOG_WRN("Skipped %u rules due to regex parse errors",
			skipped);

	if (valid == 0) {
		LOG_ERR("No valid regex patterns found");
		free(streams);
		free(rule_ids);
		free(content_rule_map);
		free(best_contents);
		free(has_content);
		return 1;
	}

	LOG_INF("Compiling %u rules via %s...", valid, mode_str);

	/* Compile */
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);

	struct arena_blob blob;
	memset(&blob, 0, sizeof(blob));

	if (use_v4) {
		/* V4 pipeline: AC + MFSA two-stage */

		/* Step 1: Build MFSA DFAs (same as V2) */
		struct mfsa mfsa_g;
		rc = compile_mfsa(streams, rule_ids, valid, &mfsa_g);
		free(streams);
		if (rc) {
			LOG_ERR("MFSA compilation failed: %d", rc);
			free(rule_ids);
			free(content_rule_map);
			free(best_contents);
		free(has_content);
			return 1;
		}

		/* Step 2: Build AC patterns from content keywords.
		 * pattern_id = MFSA DFA index */
		struct ac_pattern *ac_pats =
			calloc(valid, sizeof(struct ac_pattern));
		uint16_t *always_run_indices =
			calloc(valid, sizeof(uint16_t));
		if (!ac_pats || !always_run_indices) {
			LOG_ERR("Out of memory");
			free(ac_pats);
			free(always_run_indices);
			free(rule_ids);
			free(content_rule_map);
			free(best_contents);
		free(has_content);
			mfsa_free(&mfsa_g);
			return 1;
		}

		uint32_t num_ac_pats = 0;
		uint32_t num_always_run = 0;
		for (uint32_t i = 0; i < mfsa_g.num_dfas; i++) {
			if (i < valid && has_content[i]) {
				ac_pats[num_ac_pats].data =
					best_contents[i].data;
				ac_pats[num_ac_pats].len =
					best_contents[i].len;
				ac_pats[num_ac_pats].pattern_id = i;
				num_ac_pats++;
			} else {
				always_run_indices[num_always_run++] =
					(uint16_t)i;
			}
		}

		LOG_INF("AC: %u content patterns, %u always-run DFAs",
			num_ac_pats, num_always_run);

		/* Step 3: Build AC DFA */
		struct dfa ac_dfa;
		struct ac_match_info match_info;
		if (num_ac_pats > 0) {
			rc = ac_build(ac_pats, num_ac_pats,
				      &ac_dfa, &match_info);
		} else {
			/* No AC patterns create trivial DFA */
			rc = dfa_alloc(&ac_dfa, 2);
			if (!rc) {
				ac_dfa.num_states = 2;
				memset(&match_info, 0,
				       sizeof(match_info));
				match_info.num_states = 2;
				match_info.state_offsets =
					calloc(2, sizeof(uint32_t));
				match_info.state_counts =
					calloc(2, sizeof(uint32_t));
			}
		}
		free(ac_pats);
		if (rc) {
			LOG_ERR("AC build failed: %d", rc);
			free(always_run_indices);
			free(rule_ids);
			free(content_rule_map);
			free(best_contents);
		free(has_content);
			mfsa_free(&mfsa_g);
			return 1;
		}

		LOG_INF("AC DFA: %u states", ac_dfa.num_states);

		/* Step 4: EC compress AC DFA */
		struct ec_map ac_ecm;
		rc = ec_compute(&ac_dfa, &ac_ecm);
		if (rc) {
			LOG_ERR("AC EC compute failed: %d", rc);
			dfa_free(&ac_dfa);
			ac_match_info_free(&match_info);
			free(always_run_indices);
			free(rule_ids);
			free(content_rule_map);
			free(best_contents);
		free(has_content);
			mfsa_free(&mfsa_g);
			return 1;
		}

		struct ec_table ac_ect;
		rc = ec_table_build(&ac_dfa, &ac_ecm, &ac_ect);
		dfa_free(&ac_dfa);
		if (rc) {
			LOG_ERR("AC EC table build failed: %d", rc);
			ac_match_info_free(&match_info);
			free(always_run_indices);
			free(rule_ids);
			free(content_rule_map);
			free(best_contents);
		free(has_content);
			mfsa_free(&mfsa_g);
			return 1;
		}

		/* Step 5: EC compress MFSA DFAs (shared EC) */
		const struct dfa **dfa_ptrs =
			calloc(mfsa_g.num_dfas, sizeof(struct dfa *));
		if (!dfa_ptrs) {
			LOG_ERR("Out of memory");
			ec_table_free(&ac_ect);
			ac_match_info_free(&match_info);
			free(always_run_indices);
			free(rule_ids);
			free(content_rule_map);
			free(best_contents);
		free(has_content);
			mfsa_free(&mfsa_g);
			return 1;
		}
		for (uint32_t i = 0; i < mfsa_g.num_dfas; i++)
			dfa_ptrs[i] = &mfsa_g.dfas[i];

		struct ec_map mfsa_ecm;
		rc = ec_compute_multi(dfa_ptrs, mfsa_g.num_dfas,
				      &mfsa_ecm);
		free(dfa_ptrs);
		if (rc) {
			LOG_ERR("MFSA EC compute failed: %d", rc);
			ec_table_free(&ac_ect);
			ac_match_info_free(&match_info);
			free(always_run_indices);
			free(rule_ids);
			free(content_rule_map);
			free(best_contents);
		free(has_content);
			mfsa_free(&mfsa_g);
			return 1;
		}

		struct ec_table *mfsa_ects =
			calloc(mfsa_g.num_dfas,
			       sizeof(struct ec_table));
		if (!mfsa_ects) {
			LOG_ERR("Out of memory");
			ec_table_free(&ac_ect);
			ac_match_info_free(&match_info);
			free(always_run_indices);
			free(rule_ids);
			free(content_rule_map);
			free(best_contents);
		free(has_content);
			mfsa_free(&mfsa_g);
			return 1;
		}
		for (uint32_t i = 0; i < mfsa_g.num_dfas; i++) {
			rc = ec_table_build(&mfsa_g.dfas[i],
					    &mfsa_ecm,
					    &mfsa_ects[i]);
			if (rc) {
				LOG_ERR("MFSA EC table build failed "
					"DFA %u: %d", i, rc);
				for (uint32_t j = 0; j < i; j++)
					ec_table_free(&mfsa_ects[j]);
				free(mfsa_ects);
				ec_table_free(&ac_ect);
				ac_match_info_free(&match_info);
				free(always_run_indices);
				free(rule_ids);
				free(content_rule_map);
				free(best_contents);
		free(has_content);
				mfsa_free(&mfsa_g);
				return 1;
			}
		}

		/* Step 6: Linearize V4 */
		rc = linearize_v4(&ac_ecm, &ac_ect, &match_info,
				  &mfsa_ecm, mfsa_ects,
				  mfsa_g.num_dfas,
				  mfsa_g.rule_ids,
				  always_run_indices,
				  num_always_run, &blob);

		for (uint32_t i = 0; i < mfsa_g.num_dfas; i++)
			ec_table_free(&mfsa_ects[i]);
		free(mfsa_ects);
		ec_table_free(&ac_ect);
		ac_match_info_free(&match_info);
		free(always_run_indices);
		free(rule_ids);
		free(content_rule_map);
		free(best_contents);
		free(has_content);
		mfsa_free(&mfsa_g);
		if (rc) {
			LOG_ERR("V4 linearization failed: %d", rc);
			return 1;
		}
	} else if (use_mfsa) {
		free(content_rule_map);
		free(best_contents);
		free(has_content);

		struct mfsa mfsa_g;
		rc = compile_mfsa(streams, rule_ids, valid, &mfsa_g);
		free(streams);
		free(rule_ids);
		if (rc) {
			LOG_ERR("MFSA compilation failed: %d", rc);
			return 1;
		}

		/* V2 parallel DFA: individual minimized DFAs with
		 * shared EC map, linearized into v2 arena format. */

		/* Shared EC across all DFAs */
		const struct dfa **dfa_ptrs =
			calloc(mfsa_g.num_dfas, sizeof(struct dfa *));
		if (!dfa_ptrs) {
			LOG_ERR("Out of memory");
			mfsa_free(&mfsa_g);
			return 1;
		}
		for (uint32_t i = 0; i < mfsa_g.num_dfas; i++)
			dfa_ptrs[i] = &mfsa_g.dfas[i];

		struct ec_map ecm;
		rc = ec_compute_multi(dfa_ptrs, mfsa_g.num_dfas,
				      &ecm);
		free(dfa_ptrs);
		if (rc) {
			LOG_ERR("EC compute failed: %d", rc);
			mfsa_free(&mfsa_g);
			return 1;
		}

		/* Per-DFA EC tables */
		struct ec_table *ects =
			calloc(mfsa_g.num_dfas, sizeof(struct ec_table));
		if (!ects) {
			LOG_ERR("Out of memory");
			mfsa_free(&mfsa_g);
			return 1;
		}
		for (uint32_t i = 0; i < mfsa_g.num_dfas; i++) {
			rc = ec_table_build(&mfsa_g.dfas[i], &ecm,
					    &ects[i]);
			if (rc) {
				LOG_ERR("EC table build failed for "
					"DFA %u: %d", i, rc);
				for (uint32_t j = 0; j < i; j++)
					ec_table_free(&ects[j]);
				free(ects);
				mfsa_free(&mfsa_g);
				return 1;
			}
		}

		rc = linearize_parallel(&ecm, ects, mfsa_g.num_dfas,
					mfsa_g.rule_ids, &blob);
		for (uint32_t i = 0; i < mfsa_g.num_dfas; i++)
			ec_table_free(&ects[i]);
		free(ects);
		mfsa_free(&mfsa_g);
		if (rc) {
			LOG_ERR("Parallel linearization failed: %d",
				rc);
			return 1;
		}
	} else {
		free(content_rule_map);
		free(best_contents);
		free(has_content);

		struct dfa dfa_graph;
		rc = compile_union(streams, rule_ids, valid,
				   &dfa_graph);
		free(streams);
		free(rule_ids);
		if (rc) {
			LOG_ERR("Union compilation failed: %d", rc);
			return 1;
		}

		/* Unanchor single DFA */
		for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
			if (dfa_graph.states[ZDPI_START_STATE]
				    .trans[c] == ZDPI_DEAD_STATE)
				dfa_graph.states[ZDPI_START_STATE]
					.trans[c] = ZDPI_START_STATE;
		}
		for (uint32_t s = 2; s < dfa_graph.num_states; s++) {
			for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
				if (dfa_graph.states[s].trans[c] ==
				    ZDPI_DEAD_STATE)
					dfa_graph.states[s].trans[c] =
						dfa_graph.states
						[ZDPI_START_STATE]
							.trans[c];
			}
		}

		struct ec_map ecm;
		rc = ec_compute(&dfa_graph, &ecm);
		if (rc) {
			LOG_ERR("EC failed: %d", rc);
			dfa_free(&dfa_graph);
			return 1;
		}

		struct ec_table ect;
		rc = ec_table_build(&dfa_graph, &ecm, &ect);
		dfa_free(&dfa_graph);
		if (rc) {
			LOG_ERR("EC table build failed: %d", rc);
			return 1;
		}

		rc = linearize(&ecm, &ect, &blob);
		ec_table_free(&ect);
		if (rc) {
			LOG_ERR("Linearization failed: %d", rc);
			return 1;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &t1);

	LOG_INF("Compiled: %u bytes (%.1f MB), %.1f ms",
		blob.size, blob.size / (1024.0 * 1024.0),
		timespec_diff_ms(&t0, &t1));

	if (dry_run) {
		printf("Dry run complete. Table compiled "
		       "successfully.\n");
		printf("  Mode:      %s\n", mode_str);
		printf("  Blob size: %u bytes (%.1f MB)\n",
		       blob.size, blob.size / (1024.0 * 1024.0));
		printf("  Time:      %.1f ms\n",
		       timespec_diff_ms(&t0, &t1));
		arena_blob_free(&blob);
		return 0;
	}

	/* Flash to BPF arena + attach XDP */
	struct zdpi_handle handle;
	rc = arena_flash(&blob, ifname,
			 use_v4 ? ZDPI_XDP_V4 : ZDPI_XDP_V2, &handle);
	arena_blob_free(&blob);
	if (rc) {
		LOG_ERR("BPF flash failed: %d", rc);
		return 1;
	}

	g_handle = &handle;
	LOG_INF("XDP attached to %s. Ctrl+C to detach.", ifname);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGUSR1, sig_handler);

	int tick = 0;
	while (running) {
		sleep(1);
		if (print_stats_flag || ++tick >= 2) {
			print_stats_flag = 0;
			tick = 0;
			arena_print_stats(&handle);
		}
	}

	LOG_INF("Detaching...");
	arena_print_stats(&handle);
	arena_detach(&handle);

	return 0;
}
