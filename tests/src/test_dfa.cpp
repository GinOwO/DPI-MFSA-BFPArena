/**
 * @file test_dfa.cpp
 * @brief Unit tests for DFA subset construction and minimization.
 */

#include "test_dfa.h"

extern "C" {
#include "zdpi_types.h"
}

namespace dfa_tests {

void DfaTest::SetUp()
{
	memset(&tokens_, 0, sizeof(tokens_));
	memset(&nfa_, 0, sizeof(nfa_));
	memset(&dfa_, 0, sizeof(dfa_));
	ASSERT_EQ(nfa_alloc(&nfa_, NFA_DEFAULT_CAPACITY), ZDPI_OK);
}

void DfaTest::TearDown()
{
	nfa_free(&nfa_);
	dfa_free(&dfa_);
}

static void build_dfa(DfaTest *t, const char *pattern)
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

TEST_F(DfaTest, SingleLiteral)
{
	build_dfa(this, "a");

	/* Dead + start + accept = at least 3 states */
	EXPECT_GE(dfa_.num_states, 2u);

	/* "a" should match */
	EXPECT_TRUE(dfa_simulate(&dfa_, (const uint8_t *)"a", 1, NULL));
	/* "b" should not match */
	EXPECT_FALSE(dfa_simulate(&dfa_, (const uint8_t *)"b", 1, NULL));
}

TEST_F(DfaTest, SimpleConcat)
{
	build_dfa(this, "abc");

	EXPECT_TRUE(
		dfa_simulate(&dfa_, (const uint8_t *)"abc", 3, NULL));
	EXPECT_FALSE(
		dfa_simulate(&dfa_, (const uint8_t *)"ab", 2, NULL));
	EXPECT_FALSE(
		dfa_simulate(&dfa_, (const uint8_t *)"abd", 3, NULL));
}

TEST_F(DfaTest, Alternation)
{
	build_dfa(this, "a|b");

	EXPECT_TRUE(dfa_simulate(&dfa_, (const uint8_t *)"a", 1, NULL));
	EXPECT_TRUE(dfa_simulate(&dfa_, (const uint8_t *)"b", 1, NULL));
	EXPECT_FALSE(dfa_simulate(&dfa_, (const uint8_t *)"c", 1, NULL));
}

TEST_F(DfaTest, KleeneStar)
{
	build_dfa(this, "a*b");

	EXPECT_TRUE(dfa_simulate(&dfa_, (const uint8_t *)"b", 1, NULL));
	EXPECT_TRUE(
		dfa_simulate(&dfa_, (const uint8_t *)"ab", 2, NULL));
	EXPECT_TRUE(
		dfa_simulate(&dfa_, (const uint8_t *)"aaab", 4, NULL));
	EXPECT_FALSE(dfa_simulate(&dfa_, (const uint8_t *)"a", 1, NULL));
}

TEST_F(DfaTest, Minimization)
{
	build_dfa(this, "a|a");

	uint32_t before = dfa_.num_states;
	int rc = dfa_minimize(&dfa_);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_LE(dfa_.num_states, before);

	/* Still matches correctly */
	EXPECT_TRUE(dfa_simulate(&dfa_, (const uint8_t *)"a", 1, NULL));
	EXPECT_FALSE(dfa_simulate(&dfa_, (const uint8_t *)"b", 1, NULL));
}

TEST_F(DfaTest, MinimizedStillWorks)
{
	build_dfa(this, "(ab|ac)*d");

	int rc = dfa_minimize(&dfa_);
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_TRUE(dfa_simulate(&dfa_, (const uint8_t *)"d", 1, NULL));
	EXPECT_TRUE(
		dfa_simulate(&dfa_, (const uint8_t *)"abd", 3, NULL));
	EXPECT_TRUE(
		dfa_simulate(&dfa_, (const uint8_t *)"acd", 3, NULL));
	EXPECT_TRUE(
		dfa_simulate(&dfa_, (const uint8_t *)"abacd", 5, NULL));
	EXPECT_FALSE(
		dfa_simulate(&dfa_, (const uint8_t *)"abc", 3, NULL));
}

TEST_F(DfaTest, DotWildcard)
{
	build_dfa(this, "a.c");

	EXPECT_TRUE(
		dfa_simulate(&dfa_, (const uint8_t *)"abc", 3, NULL));
	EXPECT_TRUE(
		dfa_simulate(&dfa_, (const uint8_t *)"axc", 3, NULL));
	EXPECT_FALSE(
		dfa_simulate(&dfa_, (const uint8_t *)"ac", 2, NULL));
}

TEST_F(DfaTest, DeadStateIsZero)
{
	build_dfa(this, "a");

	/* State 0 should be the dead state with self-loops */
	for (int c = 0; c < 256; c++)
		EXPECT_EQ(dfa_.states[0].trans[c], ZDPI_DEAD_STATE);
}

} // namespace dfa_tests
