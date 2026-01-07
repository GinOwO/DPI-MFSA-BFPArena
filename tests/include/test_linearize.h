#ifndef TEST_LINEARIZE_H
#define TEST_LINEARIZE_H

#include <gtest/gtest.h>

extern "C" {
#include "linearize.h"
#include "ec_compress.h"
#include "dfa.h"
#include "nfa.h"
#include "regex_parser.h"
}

namespace linearize_tests {
class LinearizeTest : public ::testing::Test {
public:
	void SetUp() override;
	void TearDown() override;

	struct re_token_stream tokens_;
	struct nfa nfa_;
	struct dfa dfa_;
	struct ec_map ecm_;
	struct ec_table ect_;
	struct arena_blob blob_;
};
} // namespace linearize_tests

#endif /* TEST_LINEARIZE_H */
