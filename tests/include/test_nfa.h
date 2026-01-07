#ifndef TEST_NFA_H
#define TEST_NFA_H

#include <gtest/gtest.h>

extern "C" {
#include "nfa.h"
#include "regex_parser.h"
}

namespace nfa_tests {
class NfaTest : public ::testing::Test {
public:
	void SetUp() override;
	void TearDown() override;

	struct re_token_stream tokens_;
	struct nfa nfa_;
};
} // namespace nfa_tests

#endif /* TEST_NFA_H */
