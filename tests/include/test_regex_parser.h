#ifndef TEST_REGEX_PARSER_H
#define TEST_REGEX_PARSER_H

#include <gtest/gtest.h>

extern "C" {
#include "regex_parser.h"
}

namespace regex_tests {
class RegexParserTest : public ::testing::Test {
public:
	void SetUp() override;
	void TearDown() override;

	struct re_token_stream tokens_;
};
} // namespace regex_tests

#endif /* TEST_REGEX_PARSER_H */
