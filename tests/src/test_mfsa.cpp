/**
 * @file test_mfsa.cpp
 * @brief Unit tests for parallel DFA compilation (MFSA).
 */

#include "test_mfsa.h"

extern "C" {
#include "zdpi_types.h"
}

namespace mfsa_tests {

void MfsaTest::SetUp()
{
	memset(&mfsa_, 0, sizeof(mfsa_));
	mfsa_valid_ = false;
}

void MfsaTest::TearDown()
{
	if (mfsa_valid_)
		mfsa_free(&mfsa_);
}

/* Helper: simulate parallel DFA traversal in pure C.
 * Returns ZDPI_ACTION_DROP if ANY DFA matches, else PASS. */
static int simulate_parallel(const struct mfsa *m,
			     const char *payload)
{
	uint32_t len = (uint32_t)strlen(payload);
	const uint8_t *input = (const uint8_t *)payload;

	for (uint32_t di = 0; di < m->num_dfas; di++) {
		if (dfa_simulate(&m->dfas[di], input, len, NULL))
			return ZDPI_ACTION_DROP;
	}
	return ZDPI_ACTION_PASS;
}

/* --- Build from streams --- */

TEST_F(MfsaTest, SinglePattern)
{
	const char *patterns[] = { "abc" };
	uint32_t rule_ids[] = { 1 };
	struct re_token_stream streams[1];

	ASSERT_EQ(regex_parse(patterns[0], &streams[0]), ZDPI_OK);
	ASSERT_EQ(mfsa_build(streams, 1, rule_ids, &mfsa_), ZDPI_OK);
	mfsa_valid_ = true;

	EXPECT_EQ(mfsa_.num_dfas, 1u);
	EXPECT_TRUE(dfa_simulate(&mfsa_.dfas[0],
				 (const uint8_t *)"abc", 3, NULL));
	EXPECT_FALSE(dfa_simulate(&mfsa_.dfas[0],
				  (const uint8_t *)"xyz", 3, NULL));
}

TEST_F(MfsaTest, TwoDisjointPatterns)
{
	const char *patterns[] = { "abc", "xyz" };
	uint32_t rule_ids[] = { 1, 2 };
	struct re_token_stream streams[2];

	for (int i = 0; i < 2; i++)
		ASSERT_EQ(regex_parse(patterns[i], &streams[i]), ZDPI_OK);

	ASSERT_EQ(mfsa_build(streams, 2, rule_ids, &mfsa_), ZDPI_OK);
	mfsa_valid_ = true;

	EXPECT_EQ(mfsa_.num_dfas, 2u);
	EXPECT_EQ(simulate_parallel(&mfsa_, "abc"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "xyz"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "qqq"), ZDPI_ACTION_PASS);
}

TEST_F(MfsaTest, SharedPrefix)
{
	const char *patterns[] = { "abc", "abd" };
	uint32_t rule_ids[] = { 1, 2 };
	struct re_token_stream streams[2];

	for (int i = 0; i < 2; i++)
		ASSERT_EQ(regex_parse(patterns[i], &streams[i]), ZDPI_OK);

	ASSERT_EQ(mfsa_build(streams, 2, rule_ids, &mfsa_), ZDPI_OK);
	mfsa_valid_ = true;

	EXPECT_EQ(simulate_parallel(&mfsa_, "abc"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "abd"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "abe"), ZDPI_ACTION_PASS);
}

TEST_F(MfsaTest, ThreePatterns)
{
	const char *patterns[] = { "GET", "POST", "PUT" };
	uint32_t rule_ids[] = { 1, 2, 3 };
	struct re_token_stream streams[3];

	for (int i = 0; i < 3; i++)
		ASSERT_EQ(regex_parse(patterns[i], &streams[i]), ZDPI_OK);

	ASSERT_EQ(mfsa_build(streams, 3, rule_ids, &mfsa_), ZDPI_OK);
	mfsa_valid_ = true;

	EXPECT_EQ(mfsa_.num_dfas, 3u);
	EXPECT_EQ(simulate_parallel(&mfsa_, "GET"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "POST"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "PUT"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "DELETE"),
		  ZDPI_ACTION_PASS);
}

TEST_F(MfsaTest, ComplexPatterns)
{
	const char *patterns[] = { "a+b", "c*d", "e|f" };
	uint32_t rule_ids[] = { 1, 2, 3 };
	struct re_token_stream streams[3];

	for (int i = 0; i < 3; i++)
		ASSERT_EQ(regex_parse(patterns[i], &streams[i]), ZDPI_OK);

	ASSERT_EQ(mfsa_build(streams, 3, rule_ids, &mfsa_), ZDPI_OK);
	mfsa_valid_ = true;

	EXPECT_EQ(simulate_parallel(&mfsa_, "ab"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "aaab"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "d"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "ccd"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "e"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "f"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "g"), ZDPI_ACTION_PASS);
}

TEST_F(MfsaTest, RuleIdsPreserved)
{
	const char *patterns[] = { "abc", "xyz" };
	uint32_t rule_ids[] = { 100, 200 };
	struct re_token_stream streams[2];

	for (int i = 0; i < 2; i++)
		ASSERT_EQ(regex_parse(patterns[i], &streams[i]), ZDPI_OK);

	ASSERT_EQ(mfsa_build(streams, 2, rule_ids, &mfsa_), ZDPI_OK);
	mfsa_valid_ = true;

	EXPECT_EQ(mfsa_.rule_ids[0], 100u);
	EXPECT_EQ(mfsa_.rule_ids[1], 200u);
}

TEST_F(MfsaTest, AdditiveStates)
{
	const char *patterns[] = { "http", "https", "httpd" };
	uint32_t rule_ids[] = { 1, 2, 3 };
	struct re_token_stream streams[3];

	for (int i = 0; i < 3; i++)
		ASSERT_EQ(regex_parse(patterns[i], &streams[i]), ZDPI_OK);

	ASSERT_EQ(mfsa_build(streams, 3, rule_ids, &mfsa_), ZDPI_OK);
	mfsa_valid_ = true;

	/* Each individual DFA is small */
	for (uint32_t i = 0; i < mfsa_.num_dfas; i++)
		EXPECT_LT(mfsa_.dfas[i].num_states, 20u);

	/* All patterns still match */
	EXPECT_EQ(simulate_parallel(&mfsa_, "http"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "https"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate_parallel(&mfsa_, "httpd"), ZDPI_ACTION_DROP);
}

TEST_F(MfsaTest, EmptyStreamsError)
{
	int rc = mfsa_build(NULL, 0, NULL, &mfsa_);
	EXPECT_EQ(rc, ZDPI_ERR_PARSE);
}

/* --- MFSA shared merge + v3 simulation tests --- */

TEST_F(MfsaTest, SharedMergeBasic)
{
	const char *patterns[] = { "abc", "xyz", "abd" };
	uint32_t rule_ids[] = { 1, 2, 3 };
	struct re_token_stream streams[3];

	for (int i = 0; i < 3; i++)
		ASSERT_EQ(regex_parse(patterns[i], &streams[i]), ZDPI_OK);

	ASSERT_EQ(mfsa_build(streams, 3, rule_ids, &mfsa_), ZDPI_OK);
	mfsa_valid_ = true;

	/* Shared merge */
	struct mfsa_merged mm;
	ASSERT_EQ(mfsa_merge_shared(&mfsa_, &mm), ZDPI_OK);

	/* Should have fewer states than sum */
	uint32_t sum = 0;
	for (uint32_t i = 0; i < mfsa_.num_dfas; i++)
		sum += mfsa_.dfas[i].num_states;
	EXPECT_LE(mm.num_states, sum);
	EXPECT_EQ(mm.num_starts, 3u);

	/* EC compress + linearize as v3 */
	struct ec_map ecm;
	ASSERT_EQ(ec_compute_raw(mm.trans, mm.num_states, &ecm), ZDPI_OK);

	struct arena_blob blob;
	ASSERT_EQ(linearize_mfsa(&ecm, &mm, &blob), ZDPI_OK);
	mfsa_merged_free(&mm);

	/* Simulate: should match patterns anywhere in payload */
	EXPECT_EQ(linearize_mfsa_simulate(&blob,
		(const uint8_t *)"__abc__", 7), ZDPI_ACTION_DROP);
	EXPECT_EQ(linearize_mfsa_simulate(&blob,
		(const uint8_t *)"__xyz__", 7), ZDPI_ACTION_DROP);
	EXPECT_EQ(linearize_mfsa_simulate(&blob,
		(const uint8_t *)"__abd__", 7), ZDPI_ACTION_DROP);
	EXPECT_EQ(linearize_mfsa_simulate(&blob,
		(const uint8_t *)"__qqq__", 7), ZDPI_ACTION_PASS);

	arena_blob_free(&blob);
}

TEST_F(MfsaTest, SharedMergeRegex)
{
	const char *patterns[] = { "a+b", "c*d", "e|f" };
	uint32_t rule_ids[] = { 1, 2, 3 };
	struct re_token_stream streams[3];

	for (int i = 0; i < 3; i++)
		ASSERT_EQ(regex_parse(patterns[i], &streams[i]), ZDPI_OK);

	ASSERT_EQ(mfsa_build(streams, 3, rule_ids, &mfsa_), ZDPI_OK);
	mfsa_valid_ = true;

	struct mfsa_merged mm;
	ASSERT_EQ(mfsa_merge_shared(&mfsa_, &mm), ZDPI_OK);

	struct ec_map ecm;
	ASSERT_EQ(ec_compute_raw(mm.trans, mm.num_states, &ecm), ZDPI_OK);

	struct arena_blob blob;
	ASSERT_EQ(linearize_mfsa(&ecm, &mm, &blob), ZDPI_OK);
	mfsa_merged_free(&mm);

	/* Patterns should match embedded in payload */
	EXPECT_EQ(linearize_mfsa_simulate(&blob,
		(const uint8_t *)"xxabxx", 6), ZDPI_ACTION_DROP);
	EXPECT_EQ(linearize_mfsa_simulate(&blob,
		(const uint8_t *)"xxaaabxx", 8), ZDPI_ACTION_DROP);
	EXPECT_EQ(linearize_mfsa_simulate(&blob,
		(const uint8_t *)"xxdxx", 5), ZDPI_ACTION_DROP);
	EXPECT_EQ(linearize_mfsa_simulate(&blob,
		(const uint8_t *)"xxexx", 5), ZDPI_ACTION_DROP);
	EXPECT_EQ(linearize_mfsa_simulate(&blob,
		(const uint8_t *)"xxfxx", 5), ZDPI_ACTION_DROP);
	EXPECT_EQ(linearize_mfsa_simulate(&blob,
		(const uint8_t *)"xxgxx", 5), ZDPI_ACTION_PASS);

	arena_blob_free(&blob);
}

} // namespace mfsa_tests
