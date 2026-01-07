/**
 * @file test_e2e.cpp
 * @brief End-to-end integration tests for the full ZDPI pipeline.
 *
 * Tests the complete flow: rule file -> parse -> NFA -> DFA ->
 * EC compress -> linearize -> simulate traversal on payloads.
 * No BPF/root required.
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "zdpi_types.h"
#include "rule_parser.h"
#include "regex_parser.h"
#include "nfa.h"
#include "dfa.h"
#include "mfsa.h"
#include "ec_compress.h"
#include "linearize.h"
}

class E2eTest : public ::testing::Test {
protected:
	void SetUp() override
	{
		memset(&blob_, 0, sizeof(blob_));
	}

	void TearDown() override
	{
		arena_blob_free(&blob_);
	}

	int build_from_pattern(const char *pattern)
	{
		struct re_token_stream tokens;
		struct nfa nfa_graph;
		struct dfa dfa_graph;
		struct ec_map ecm;
		struct ec_table ect;

		int rc = regex_parse(pattern, &tokens);
		if (rc)
			return rc;

		rc = nfa_alloc(&nfa_graph, NFA_DEFAULT_CAPACITY);
		if (rc)
			return rc;

		rc = nfa_build(&tokens, &nfa_graph);
		if (rc) {
			nfa_free(&nfa_graph);
			return rc;
		}

		rc = dfa_alloc(&dfa_graph, 4096);
		if (rc) {
			nfa_free(&nfa_graph);
			return rc;
		}

		rc = dfa_build(&nfa_graph, &dfa_graph);
		nfa_free(&nfa_graph);
		if (rc) {
			dfa_free(&dfa_graph);
			return rc;
		}

		rc = dfa_minimize(&dfa_graph);
		if (rc) {
			dfa_free(&dfa_graph);
			return rc;
		}

		rc = ec_compute(&dfa_graph, &ecm);
		if (rc) {
			dfa_free(&dfa_graph);
			return rc;
		}

		rc = ec_table_build(&dfa_graph, &ecm, &ect);
		dfa_free(&dfa_graph);
		if (rc)
			return rc;

		rc = linearize(&ecm, &ect, &blob_);
		ec_table_free(&ect);
		return rc;
	}

	int simulate(const char *payload)
	{
		return linearize_simulate(
			&blob_, (const uint8_t *)payload,
			(uint32_t)strlen(payload));
	}

	struct arena_blob blob_;
};

TEST_F(E2eTest, SimplePatternMatch)
{
	int rc = build_from_pattern("abc");
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_EQ(simulate("abc"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("xyz"), ZDPI_ACTION_PASS);
	EXPECT_EQ(simulate("ab"), ZDPI_ACTION_PASS);
}

TEST_F(E2eTest, PathTraversalPattern)
{
	int rc = build_from_pattern("\\.\\./");
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_EQ(simulate("../"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("normal/path"), ZDPI_ACTION_PASS);
}

TEST_F(E2eTest, AlternationPattern)
{
	int rc = build_from_pattern("GET|POST");
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_EQ(simulate("GET"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("POST"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("PUT"), ZDPI_ACTION_PASS);
}

TEST_F(E2eTest, WildcardPattern)
{
	int rc = build_from_pattern("a.c");
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_EQ(simulate("abc"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("axc"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("ac"), ZDPI_ACTION_PASS);
}

TEST_F(E2eTest, RepetitionPattern)
{
	int rc = build_from_pattern("ab+c");
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_EQ(simulate("abc"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("abbc"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("abbbc"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("ac"), ZDPI_ACTION_PASS);
}

TEST_F(E2eTest, OptionalPattern)
{
	int rc = build_from_pattern("ab?c");
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_EQ(simulate("ac"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("abc"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("abbc"), ZDPI_ACTION_PASS);
}

TEST_F(E2eTest, CharClassPattern)
{
	int rc = build_from_pattern("[a-z]+");
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_EQ(simulate("hello"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("a"), ZDPI_ACTION_DROP);
}

TEST_F(E2eTest, RuleFileParsing)
{
	struct zdpi_ruleset ruleset;
	int rc = ruleset_alloc(&ruleset, 64);
	ASSERT_EQ(rc, ZDPI_OK);
	rc = ruleset_parse_file(
		ZDPI_TEST_DATA_DIR "/rules/single.rules", &ruleset);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(ruleset.num_rules, 1u);
	EXPECT_GT(ruleset.rules[0].pcre_len, 0u);
	ruleset_free(&ruleset);
}

TEST_F(E2eTest, MultiRuleFileParsing)
{
	struct zdpi_ruleset ruleset;
	int rc = ruleset_alloc(&ruleset, 64);
	ASSERT_EQ(rc, ZDPI_OK);
	rc = ruleset_parse_file(
		ZDPI_TEST_DATA_DIR "/rules/multi.rules", &ruleset);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_GE(ruleset.num_rules, 2u);
	ruleset_free(&ruleset);
}

/* --- MFSA E2E tests: full pipeline via MFSA merge --- */

class MfsaE2eTest : public ::testing::Test {
protected:
	void SetUp() override
	{
		memset(&blob_, 0, sizeof(blob_));
	}

	void TearDown() override
	{
		arena_blob_free(&blob_);
	}

	int build_mfsa(const char **patterns, uint32_t count)
	{
		struct re_token_stream *streams =
			new struct re_token_stream[count]();
		uint32_t *rule_ids = new uint32_t[count]();
		struct mfsa mfsa_g;

		for (uint32_t i = 0; i < count; i++) {
			int rc = regex_parse(patterns[i], &streams[i]);
			if (rc) {
				delete[] streams;
				delete[] rule_ids;
				return rc;
			}
			rule_ids[i] = i + 1;
		}

		int rc = mfsa_build(streams, count, rule_ids, &mfsa_g);
		delete[] streams;
		if (rc) {
			delete[] rule_ids;
			return rc;
		}

		/* Unanchor each DFA */
		for (uint32_t di = 0; di < mfsa_g.num_dfas; di++) {
			struct dfa *d = &mfsa_g.dfas[di];
			for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
				if (d->states[ZDPI_START_STATE].trans[c]
				    == ZDPI_DEAD_STATE)
					d->states[ZDPI_START_STATE]
						.trans[c] =
						ZDPI_START_STATE;
			}
			for (uint32_t s = 2; s < d->num_states;
			     s++) {
				for (int c = 0;
				     c < ZDPI_ALPHABET_SIZE; c++) {
					if (d->states[s].trans[c] ==
					    ZDPI_DEAD_STATE)
						d->states[s].trans[c] =
							d->states
							[ZDPI_START_STATE]
								.trans[c];
				}
			}
		}

		/* Shared EC across all DFAs */
		const struct dfa **dfa_ptrs =
			new const struct dfa *[mfsa_g.num_dfas];
		for (uint32_t i = 0; i < mfsa_g.num_dfas; i++)
			dfa_ptrs[i] = &mfsa_g.dfas[i];

		struct ec_map ecm;
		rc = ec_compute_multi(dfa_ptrs, mfsa_g.num_dfas,
				      &ecm);
		delete[] dfa_ptrs;
		if (rc) {
			delete[] rule_ids;
			mfsa_free(&mfsa_g);
			return rc;
		}

		/* Per-DFA EC tables */
		struct ec_table *ects =
			new struct ec_table[mfsa_g.num_dfas]();
		for (uint32_t i = 0; i < mfsa_g.num_dfas; i++) {
			rc = ec_table_build(&mfsa_g.dfas[i], &ecm,
					    &ects[i]);
			if (rc) {
				for (uint32_t j = 0; j < i; j++)
					ec_table_free(&ects[j]);
				delete[] ects;
				delete[] rule_ids;
				mfsa_free(&mfsa_g);
				return rc;
			}
		}

		rc = linearize_parallel(&ecm, ects, mfsa_g.num_dfas,
					mfsa_g.rule_ids, &blob_);
		for (uint32_t i = 0; i < mfsa_g.num_dfas; i++)
			ec_table_free(&ects[i]);
		delete[] ects;
		delete[] rule_ids;
		mfsa_free(&mfsa_g);
		return rc;
	}

	int simulate(const char *payload)
	{
		return linearize_parallel_simulate(
			&blob_, (const uint8_t *)payload,
			(uint32_t)strlen(payload));
	}

	struct arena_blob blob_;
};

TEST_F(MfsaE2eTest, TwoDisjointPatterns)
{
	const char *pats[] = { "abc", "xyz" };
	ASSERT_EQ(build_mfsa(pats, 2), ZDPI_OK);

	EXPECT_EQ(simulate("abc"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("xyz"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("qqq"), ZDPI_ACTION_PASS);
}

TEST_F(MfsaE2eTest, SharedPrefixPatterns)
{
	const char *pats[] = { "http", "https", "httpd" };
	ASSERT_EQ(build_mfsa(pats, 3), ZDPI_OK);

	EXPECT_EQ(simulate("http"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("https"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("httpd"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("htt"), ZDPI_ACTION_PASS);
	EXPECT_EQ(simulate("ftp"), ZDPI_ACTION_PASS);
}

TEST_F(MfsaE2eTest, ComplexMixedPatterns)
{
	const char *pats[] = { "GET", "POST", "a+b", "c.d" };
	ASSERT_EQ(build_mfsa(pats, 4), ZDPI_OK);

	EXPECT_EQ(simulate("GET"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("POST"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("ab"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("aaab"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("cxd"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("DELETE"), ZDPI_ACTION_PASS);
}

TEST_F(MfsaE2eTest, MfsaMatchesSameAsUnion)
{
	const char *pats[] = { "\\.\\./", "etc/passwd", "bin/sh" };
	ASSERT_EQ(build_mfsa(pats, 3), ZDPI_OK);

	EXPECT_EQ(simulate("../"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("etc/passwd"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("bin/sh"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("safe/path"), ZDPI_ACTION_PASS);
}
