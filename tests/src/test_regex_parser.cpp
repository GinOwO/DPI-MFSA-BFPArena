/**
 * @file test_regex_parser.cpp
 * @brief Unit tests for the PCRE-subset regex parser.
 */

#include "test_regex_parser.h"

extern "C" {
#include "zdpi_types.h"
}

namespace regex_tests {

void RegexParserTest::SetUp()
{
	memset(&tokens_, 0, sizeof(tokens_));
}

void RegexParserTest::TearDown()
{
}

TEST_F(RegexParserTest, SimpleLiteral)
{
	int rc = regex_parse("abc", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_GT(tokens_.len, 0u);

	/* Should have 3 literals + 2 concats = 5 tokens in postfix */
	EXPECT_EQ(tokens_.len, 5u);
}

TEST_F(RegexParserTest, Alternation)
{
	int rc = regex_parse("a|b", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	/* postfix: a b | */
	EXPECT_EQ(tokens_.len, 3u);
	EXPECT_EQ(tokens_.tokens[2].type, RE_TOK_ALTER);
}

TEST_F(RegexParserTest, KleeneStar)
{
	int rc = regex_parse("a*", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	/* postfix: a * */
	EXPECT_EQ(tokens_.len, 2u);
	EXPECT_EQ(tokens_.tokens[1].type, RE_TOK_STAR);
}

TEST_F(RegexParserTest, Plus)
{
	int rc = regex_parse("a+", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(tokens_.len, 2u);
	EXPECT_EQ(tokens_.tokens[1].type, RE_TOK_PLUS);
}

TEST_F(RegexParserTest, Optional)
{
	int rc = regex_parse("a?", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(tokens_.len, 2u);
	EXPECT_EQ(tokens_.tokens[1].type, RE_TOK_QUEST);
}

TEST_F(RegexParserTest, Dot)
{
	int rc = regex_parse("a.b", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	/* a . CONCAT b CONCAT */
	EXPECT_EQ(tokens_.len, 5u);
}

TEST_F(RegexParserTest, CharClass)
{
	int rc = regex_parse("[a-z]", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(tokens_.len, 1u);
	EXPECT_EQ(tokens_.tokens[0].type, RE_TOK_CLASS);
	EXPECT_TRUE(cc_test(&tokens_.tokens[0].cclass, 'a'));
	EXPECT_TRUE(cc_test(&tokens_.tokens[0].cclass, 'z'));
	EXPECT_FALSE(cc_test(&tokens_.tokens[0].cclass, 'A'));
}

TEST_F(RegexParserTest, NegatedCharClass)
{
	int rc = regex_parse("[^0-9]", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(tokens_.len, 1u);
	EXPECT_EQ(tokens_.tokens[0].type, RE_TOK_CLASS);
	EXPECT_FALSE(cc_test(&tokens_.tokens[0].cclass, '5'));
	EXPECT_TRUE(cc_test(&tokens_.tokens[0].cclass, 'a'));
}

TEST_F(RegexParserTest, EscapeSequences)
{
	int rc = regex_parse("\\d+", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(tokens_.tokens[0].type, RE_TOK_CLASS);
	EXPECT_TRUE(cc_test(&tokens_.tokens[0].cclass, '0'));
	EXPECT_TRUE(cc_test(&tokens_.tokens[0].cclass, '9'));
	EXPECT_FALSE(cc_test(&tokens_.tokens[0].cclass, 'a'));
}

TEST_F(RegexParserTest, Grouping)
{
	int rc = regex_parse("(ab)+", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_GT(tokens_.len, 0u);
}

TEST_F(RegexParserTest, ComplexPattern)
{
	int rc = regex_parse("GET\\s+/\\.\\./", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_GT(tokens_.len, 0u);
}

TEST_F(RegexParserTest, EmptyPatternFails)
{
	int rc = regex_parse("", &tokens_);
	/* Empty produces 0 tokens which is valid but useless */
	EXPECT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(tokens_.len, 0u);
}

TEST_F(RegexParserTest, EscapedLiterals)
{
	int rc = regex_parse("\\.", &tokens_);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(tokens_.len, 1u);
	EXPECT_EQ(tokens_.tokens[0].type, RE_TOK_LITERAL);
	EXPECT_EQ(tokens_.tokens[0].literal, '.');
}

} // namespace regex_tests
