/**
 * \file test_vccrypt_version.cpp
 *
 * Unit tests for vccrypt_version.
 *
 * \copyright 2021 Velo-Payments, Inc.  All rights reserved.
 */

#include <config.h>
#include <vccrypt/version.h>

/* DISABLED GTEST */
#if 0

TEST(vccrypt_version_test, verify_version_information_set)
{
    const char* version = vccrypt_version();

    ASSERT_NE(nullptr, version);
    EXPECT_STREQ(VCCRYPT_VERSION, version);
}
#endif
