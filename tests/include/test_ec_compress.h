#ifndef TEST_EC_COMPRESS_H
#define TEST_EC_COMPRESS_H

#include <gtest/gtest.h>

extern "C" {
#include "ec_compress.h"
#include "dfa.h"
#include "nfa.h"
#include "regex_parser.h"
}

namespace ec_tests {
class EcCompressTest : public ::testing::Test {
public:
	void SetUp() override;
	void TearDown() override;

	struct re_token_stream tokens_;
	struct nfa nfa_;
	struct dfa dfa_;
	struct ec_map ecm_;
	struct ec_table ect_;
};
} // namespace ec_tests

#endif /* TEST_EC_COMPRESS_H */
