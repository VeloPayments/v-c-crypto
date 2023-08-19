/**
 * \file test_vccrypt_version.cpp
 *
 * Unit tests for vccrypt_version.
 *
 * \copyright 2021-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <config.h>
#include <minunit/minunit.h>
#include <string.h>
#include <vccrypt/version.h>

TEST_SUITE(vccrypt_version_test);

TEST(verify_version_information_set)
{
    const char* version = vccrypt_version();

    TEST_ASSERT(nullptr != version);
    TEST_EXPECT(!strcmp(VCCRYPT_VERSION, version));
}
