#ifndef TEST_MFSA_H
#define TEST_MFSA_H

#include <gtest/gtest.h>

extern "C" {
#include "mfsa.h"
#include "dfa.h"
#include "nfa.h"
#include "regex_parser.h"
#include "ec_compress.h"
#include "linearize.h"
}

namespace mfsa_tests {
class MfsaTest : public ::testing::Test {
public:
	void SetUp() override;
	void TearDown() override;

	struct mfsa mfsa_;
	bool mfsa_valid_;
};
} // namespace mfsa_tests

#endif /* TEST_MFSA_H */
