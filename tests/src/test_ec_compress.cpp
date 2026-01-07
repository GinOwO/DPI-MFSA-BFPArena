/**
 * @file test_ec_compress.cpp
 * @brief Unit tests for equivalence class compression.
 */

#include "test_ec_compress.h"

#include <algorithm>

extern "C" {
#include "zdpi_types.h"
}

namespace ec_tests {

void EcCompressTest::SetUp()
{
	memset(&tokens_, 0, sizeof(tokens_));
	memset(&nfa_, 0, sizeof(nfa_));
	memset(&dfa_, 0, sizeof(dfa_));
	memset(&ecm_, 0, sizeof(ecm_));
	memset(&ect_, 0, sizeof(ect_));
	ASSERT_EQ(nfa_alloc(&nfa_, NFA_DEFAULT_CAPACITY), ZDPI_OK);
}

void EcCompressTest::TearDown()
{
	nfa_free(&nfa_);
	dfa_free(&dfa_);
	ec_table_free(&ect_);
}

static void build_pipeline(EcCompressTest *t, const char *pattern)
{
	int rc = regex_parse(pattern, &t->tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	rc = nfa_build(&t->tokens_, &t->nfa_);
	ASSERT_EQ(rc, ZDPI_OK);
	rc = dfa_alloc(&t->dfa_, 4096);
	ASSERT_EQ(rc, ZDPI_OK);
	rc = dfa_build(&t->nfa_, &t->dfa_);
	ASSERT_EQ(rc, ZDPI_OK);
}

TEST_F(EcCompressTest, BasicCompression)
{
	build_pipeline(this, "abc");

	int rc = ec_compute(&dfa_, &ecm_);
	ASSERT_EQ(rc, ZDPI_OK);

	/* Pattern only uses a, b, c -> 4 ECs max (a, b, c, everything else) */
	EXPECT_LE(ecm_.num_ec, 256u);
	EXPECT_GE(ecm_.num_ec, 2u);
}

TEST_F(EcCompressTest, EquivalentBytesGrouped)
{
	build_pipeline(this, "a");

	int rc = ec_compute(&dfa_, &ecm_);
	ASSERT_EQ(rc, ZDPI_OK);

	/* All non-'a' bytes should map to same EC */
	uint8_t ec_b = ecm_.byte_to_ec['b'];
	uint8_t ec_c = ecm_.byte_to_ec['c'];
	EXPECT_EQ(ec_b, ec_c);

	/* 'a' should be in its own EC */
	EXPECT_NE(ecm_.byte_to_ec['a'], ec_b);
}

TEST_F(EcCompressTest, TableBuild)
{
	build_pipeline(this, "abc");

	int rc = ec_compute(&dfa_, &ecm_);
	ASSERT_EQ(rc, ZDPI_OK);

	rc = ec_table_build(&dfa_, &ecm_, &ect_);
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_EQ(ect_.num_states, dfa_.num_states);
	EXPECT_EQ(ect_.num_ec, ecm_.num_ec);
	EXPECT_NE(ect_.table, nullptr);
}

TEST_F(EcCompressTest, CompressedTransitionsCorrect)
{
	build_pipeline(this, "ab");

	int rc = ec_compute(&dfa_, &ecm_);
	ASSERT_EQ(rc, ZDPI_OK);
	rc = ec_table_build(&dfa_, &ecm_, &ect_);
	ASSERT_EQ(rc, ZDPI_OK);

	/* Simulate on compressed table: start=1, 'a' -> some state,
	 * then 'b' -> accept */
	uint32_t state = ZDPI_START_STATE;
	uint8_t ec_a = ecm_.byte_to_ec['a'];
	state = ect_.table[state * ect_.num_ec + ec_a];
	EXPECT_NE(state, (uint32_t)ZDPI_DEAD_STATE);

	uint8_t ec_b = ecm_.byte_to_ec['b'];
	state = ect_.table[state * ect_.num_ec + ec_b];
	EXPECT_TRUE(ect_.accept[state]);
}

TEST_F(EcCompressTest, MultiDfaSharedEc)
{
	/* Build two DFAs from different patterns */
	build_pipeline(this, "abc");
	struct dfa dfa1 = dfa_;
	memset(&dfa_, 0, sizeof(dfa_));

	struct nfa nfa2;
	memset(&nfa2, 0, sizeof(nfa2));
	ASSERT_EQ(nfa_alloc(&nfa2, NFA_DEFAULT_CAPACITY), ZDPI_OK);

	struct re_token_stream tok2;
	memset(&tok2, 0, sizeof(tok2));
	ASSERT_EQ(regex_parse("xyz", &tok2), ZDPI_OK);
	ASSERT_EQ(nfa_build(&tok2, &nfa2), ZDPI_OK);

	struct dfa dfa2;
	memset(&dfa2, 0, sizeof(dfa2));
	ASSERT_EQ(dfa_alloc(&dfa2, 4096), ZDPI_OK);
	ASSERT_EQ(dfa_build(&nfa2, &dfa2), ZDPI_OK);

	/* Compute shared EC across both DFAs */
	const struct dfa *dfas[] = {&dfa1, &dfa2};
	struct ec_map shared;
	int rc = ec_compute_multi(dfas, 2, &shared);
	ASSERT_EQ(rc, ZDPI_OK);

	/* Shared EC must distinguish a,b,c AND x,y,z */
	EXPECT_NE(shared.byte_to_ec['a'], shared.byte_to_ec['x']);
	EXPECT_NE(shared.byte_to_ec['a'], shared.byte_to_ec['y']);

	/* Compute individual ECs for comparison */
	struct ec_map ec1, ec2;
	ASSERT_EQ(ec_compute(&dfa1, &ec1), ZDPI_OK);
	ASSERT_EQ(ec_compute(&dfa2, &ec2), ZDPI_OK);

	/* Shared EC count >= max of individual counts */
	EXPECT_GE(shared.num_ec,
		  std::max(ec1.num_ec, ec2.num_ec));

	nfa_free(&nfa2);
	dfa_free(&dfa1);
	dfa_free(&dfa2);
}

TEST_F(EcCompressTest, MultiDfaSingleFallback)
{
	build_pipeline(this, "abc");

	const struct dfa *dfas[] = {&dfa_};
	struct ec_map shared;
	struct ec_map single;

	ASSERT_EQ(ec_compute_multi(dfas, 1, &shared), ZDPI_OK);
	ASSERT_EQ(ec_compute(&dfa_, &single), ZDPI_OK);

	/* Single-DFA fallback should produce identical EC map */
	EXPECT_EQ(shared.num_ec, single.num_ec);
	for (int i = 0; i < ZDPI_ALPHABET_SIZE; i++)
		EXPECT_EQ(shared.byte_to_ec[i], single.byte_to_ec[i]);
}

} // namespace ec_tests
