/**
 * \file test/mock/suite/test_vccrypt_mock_suite_options_init.cpp
 *
 * Unit tests for the Velo mock crypto suite options init function.
 *
 * \copyright 2020-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <vccrypt/mock_suite.h>
#include <vpr/allocator/malloc_allocator.h>

TEST_SUITE(vccrypt_mock_suite_options_init);

/**
 * Initialization of the mock crypto suite should succeed.
 */
TEST(init)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
