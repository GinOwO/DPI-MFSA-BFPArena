/**
 * @file test_nfa.cpp
 * @brief Unit tests for Thompson's NFA construction.
 */

#include "test_nfa.h"

extern "C" {
#include "zdpi_types.h"
}

namespace nfa_tests {

void NfaTest::SetUp()
{
	memset(&tokens_, 0, sizeof(tokens_));
	memset(&nfa_, 0, sizeof(nfa_));
	ASSERT_EQ(nfa_alloc(&nfa_, NFA_DEFAULT_CAPACITY), ZDPI_OK);
}

void NfaTest::TearDown()
{
	nfa_free(&nfa_);
}

TEST_F(NfaTest, SingleLiteral)
{
	int rc = regex_parse("a", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);

	rc = nfa_build(&tokens_, &nfa_);
	ASSERT_EQ(rc, ZDPI_OK);

	/* Single literal: 2 states (start + accept) */
	EXPECT_EQ(nfa_.num_states, 2u);
	EXPECT_TRUE(nfa_.states[nfa_.accept].accept);
}

TEST_F(NfaTest, Concatenation)
{
	int rc = regex_parse("ab", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);

	rc = nfa_build(&tokens_, &nfa_);
	ASSERT_EQ(rc, ZDPI_OK);

	/* 2 literals concatenated: 4 states + epsilon between */
	EXPECT_GE(nfa_.num_states, 4u);
	EXPECT_TRUE(nfa_.states[nfa_.accept].accept);
}

TEST_F(NfaTest, Alternation)
{
	int rc = regex_parse("a|b", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);

	rc = nfa_build(&tokens_, &nfa_);
	ASSERT_EQ(rc, ZDPI_OK);

	/* 2 branches + split/merge states */
	EXPECT_GE(nfa_.num_states, 6u);
	EXPECT_TRUE(nfa_.states[nfa_.accept].accept);
}

TEST_F(NfaTest, KleeneStar)
{
	int rc = regex_parse("a*", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);

	rc = nfa_build(&tokens_, &nfa_);
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_TRUE(nfa_.states[nfa_.accept].accept);
}

TEST_F(NfaTest, Plus)
{
	int rc = regex_parse("a+", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);

	rc = nfa_build(&tokens_, &nfa_);
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_TRUE(nfa_.states[nfa_.accept].accept);
}

TEST_F(NfaTest, ComplexPattern)
{
	int rc = regex_parse("(a|b)*c", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);

	rc = nfa_build(&tokens_, &nfa_);
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_GT(nfa_.num_states, 4u);
	EXPECT_TRUE(nfa_.states[nfa_.accept].accept);
}

TEST_F(NfaTest, EpsilonClosure)
{
	int rc = regex_parse("a", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);

	rc = nfa_build(&tokens_, &nfa_);
	ASSERT_EQ(rc, ZDPI_OK);

	uint8_t states[(NFA_DEFAULT_CAPACITY + 7) / 8] = { 0 };
	states[nfa_.start / 8] |= (1 << (nfa_.start % 8));
	nfa_epsilon_closure(&nfa_, states);

	/* Start should be in its own closure */
	EXPECT_TRUE(states[nfa_.start / 8] & (1 << (nfa_.start % 8)));
}

TEST_F(NfaTest, UnionTwoRules)
{
	struct re_token_stream streams[2];
	uint32_t rule_ids[2] = { 1, 2 };

	int rc = regex_parse("abc", &streams[0]);
	ASSERT_EQ(rc, ZDPI_OK);
	rc = regex_parse("xyz", &streams[1]);
	ASSERT_EQ(rc, ZDPI_OK);

	rc = nfa_build_union(streams, 2, rule_ids, &nfa_);
	ASSERT_EQ(rc, ZDPI_OK);

	EXPECT_GT(nfa_.num_states, 8u);
}

} // namespace nfa_tests
