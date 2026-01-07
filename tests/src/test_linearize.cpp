/**
 * @file test_linearize.cpp
 * @brief Unit tests for DFA table linearization.
 */

#include "test_linearize.h"

extern "C" {
#include "zdpi_types.h"
}

namespace linearize_tests {

void LinearizeTest::SetUp()
{
	memset(&tokens_, 0, sizeof(tokens_));
	memset(&nfa_, 0, sizeof(nfa_));
	memset(&dfa_, 0, sizeof(dfa_));
	memset(&ecm_, 0, sizeof(ecm_));
	memset(&ect_, 0, sizeof(ect_));
	memset(&blob_, 0, sizeof(blob_));
	ASSERT_EQ(nfa_alloc(&nfa_, NFA_DEFAULT_CAPACITY), ZDPI_OK);
}

void LinearizeTest::TearDown()
{
	nfa_free(&nfa_);
	dfa_free(&dfa_);
	ec_table_free(&ect_);
	arena_blob_free(&blob_);
}

static void build_full(LinearizeTest *t, const char *pattern)
{
	int rc = regex_parse(pattern, &t->tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	rc = nfa_build(&t->tokens_, &t->nfa_);
	ASSERT_EQ(rc, ZDPI_OK);
	rc = dfa_alloc(&t->dfa_, 4096);
	ASSERT_EQ(rc, ZDPI_OK);
	rc = dfa_build(&t->nfa_, &t->dfa_);
	ASSERT_EQ(rc, ZDPI_OK);
	rc = ec_compute(&t->dfa_, &t->ecm_);
	ASSERT_EQ(rc, ZDPI_OK);
	rc = ec_table_build(&t->dfa_, &t->ecm_, &t->ect_);
	ASSERT_EQ(rc, ZDPI_OK);
}

TEST_F(LinearizeTest, BlobCreation)
{
	build_full(this, "abc");

	int rc = linearize(&ecm_, &ect_, &blob_);
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_NE(blob_.data, nullptr);
	EXPECT_GT(blob_.size, 0u);
}

TEST_F(LinearizeTest, HeaderMagic)
{
	build_full(this, "abc");

	int rc = linearize(&ecm_, &ect_, &blob_);
	ASSERT_EQ(rc, ZDPI_OK);

	const struct zdpi_table_header *hdr =
		(const struct zdpi_table_header *)blob_.data;
	EXPECT_EQ(hdr->magic, (uint32_t)ZDPI_MAGIC);
	EXPECT_EQ(hdr->table_ready, 1u);
	EXPECT_EQ(hdr->num_states, dfa_.num_states);
	EXPECT_EQ(hdr->num_ec, (uint16_t)ecm_.num_ec);
}

TEST_F(LinearizeTest, SimulateMatch)
{
	build_full(this, "abc");

	int rc = linearize(&ecm_, &ect_, &blob_);
	ASSERT_EQ(rc, ZDPI_OK);

	int result = linearize_simulate(&blob_, (const uint8_t *)"abc", 3);
	EXPECT_EQ(result, ZDPI_ACTION_DROP);
}

TEST_F(LinearizeTest, SimulateNoMatch)
{
	build_full(this, "abc");

	int rc = linearize(&ecm_, &ect_, &blob_);
	ASSERT_EQ(rc, ZDPI_OK);

	int result = linearize_simulate(&blob_, (const uint8_t *)"xyz", 3);
	EXPECT_EQ(result, ZDPI_ACTION_PASS);
}

TEST_F(LinearizeTest, SimulatePartialMatch)
{
	build_full(this, "abc");

	int rc = linearize(&ecm_, &ect_, &blob_);
	ASSERT_EQ(rc, ZDPI_OK);

	int result = linearize_simulate(&blob_, (const uint8_t *)"ab", 2);
	EXPECT_EQ(result, ZDPI_ACTION_PASS);
}

TEST_F(LinearizeTest, SimulateDotWildcard)
{
	build_full(this, "a.c");

	int rc = linearize(&ecm_, &ect_, &blob_);
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_EQ(linearize_simulate(&blob_, (const uint8_t *)"abc", 3),
		  ZDPI_ACTION_DROP);
	EXPECT_EQ(linearize_simulate(&blob_, (const uint8_t *)"axc", 3),
		  ZDPI_ACTION_DROP);
	EXPECT_EQ(linearize_simulate(&blob_, (const uint8_t *)"ac", 2),
		  ZDPI_ACTION_PASS);
}

} // namespace linearize_tests
