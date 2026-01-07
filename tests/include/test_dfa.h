#ifndef TEST_DFA_H
#define TEST_DFA_H

#include <gtest/gtest.h>

extern "C" {
#include "dfa.h"
#include "nfa.h"
#include "regex_parser.h"
}

namespace dfa_tests {
class DfaTest : public ::testing::Test {
public:
	void SetUp() override;
	void TearDown() override;

	struct re_token_stream tokens_;
	struct nfa nfa_;
	struct dfa dfa_;
};
} // namespace dfa_tests

#endif /* TEST_DFA_H */
