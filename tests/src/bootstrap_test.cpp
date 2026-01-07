/**
 * @file bootstrap_test.cpp
 * @brief GTest framework smoke test.
 */

#include <gtest/gtest.h>

TEST(BootstrapTest, GTestWorks)
{
	EXPECT_EQ(1 + 1, 2);
}

TEST(BootstrapTest, TrueIsTrue)
{
	EXPECT_TRUE(true);
}
