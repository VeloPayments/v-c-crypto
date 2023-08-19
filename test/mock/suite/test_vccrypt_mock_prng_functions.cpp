/**
 * \file test/mock/suite/test_vccrypt_mock_prng_functions.cpp
 *
 * Unit tests for the Velo mock prng functions.
 *
 * \copyright 2020-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <vccrypt/mock_suite.h>
#include <vpr/allocator/malloc_allocator.h>

TEST_SUITE(vccrypt_mock_prng_functions);

/**
 * By default, the prng init function returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(init_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_prng_context_t prng;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* attempting to initiate a mock hash algorithm should fail. */
    TEST_EXPECT(
        VCCRYPT_ERROR_MOCK_NOT_ADDED == vccrypt_suite_prng_init(&suite, &prng));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * The prng init function can be mocked.
 */
TEST(init_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_prng_context_t prng;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_prng_init(
                    &suite,
                    [&](vccrypt_prng_options_t*, vccrypt_prng_context_t*)
                            -> int {
                        return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* attempting to initiate a mock prng algorithm should work. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS == vccrypt_suite_prng_init(&suite, &prng));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * The prng dispose function can be mocked.
 */
TEST(dispose_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_prng_context_t prng;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_prng_init(
                    &suite,
                    [&](vccrypt_prng_options_t*, vccrypt_prng_context_t*)
                            -> int {
                        return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* add a mock for the dispose method. */
    vccrypt_prng_options_t* got_options = nullptr;
    vccrypt_prng_context_t* got_context = nullptr;
    bool dispose_called = false;
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_prng_dispose(
                    &suite,
                    [&](
                        vccrypt_prng_options_t* options,
                        vccrypt_prng_context_t* context) -> void {
                            got_options = options;
                            got_context = context;
                            dispose_called = true;
                    }));

    /* PRECONDITIONS: got* are unset. */
    TEST_EXPECT(nullptr == got_options);
    TEST_EXPECT(nullptr == got_context);
    TEST_EXPECT(!dispose_called);

    /* attempting to initiate a mock prng algorithm should work. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS == vccrypt_suite_prng_init(&suite, &prng));

    /* dispose a mock prng algorithm. */
    dispose((disposable_t*)&prng);

    /* POSTCONDITIONS: got* are set. */
    TEST_EXPECT(&suite.prng_opts == got_options);
    TEST_EXPECT(&prng == got_context);
    TEST_EXPECT(dispose_called);

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the read mock returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(read_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_prng_context_t prng;
    uint8_t EXPECTED_BUFFER[4];
    size_t EXPECTED_SIZE = sizeof(EXPECTED_BUFFER);

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_prng_init(
                    &suite,
                    [&](vccrypt_prng_options_t*, vccrypt_prng_context_t*)
                            -> int {
                        return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* attempting to initiate a mock prng algorithm should work. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS == vccrypt_suite_prng_init(&suite, &prng));

    /* Calling the read method should result in an error. */
    TEST_EXPECT(
        VCCRYPT_ERROR_MOCK_NOT_ADDED
            == vccrypt_prng_read_c(
                    &prng, EXPECTED_BUFFER, EXPECTED_SIZE));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It is possible to mock the read method.
 */
TEST(read_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_prng_context_t prng;
    uint8_t EXPECTED_BUFFER[4];
    size_t EXPECTED_SIZE = sizeof(EXPECTED_BUFFER);

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_prng_init(
                    &suite,
                    [&](vccrypt_prng_options_t*, vccrypt_prng_context_t*)
                            -> int {
                        return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* add a mock for the read method. */
    vccrypt_prng_context_t* got_context = nullptr;
    uint8_t* got_buffer = nullptr;
    size_t got_size = 0;
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_prng_read(
                    &suite,
                    [&](
                        vccrypt_prng_context_t* context, uint8_t* buffer,
                        size_t size) -> int {
                            got_context = context;
                            got_buffer = buffer;
                            got_size = size;
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* attempting to initiate a mock prng algorithm should work. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS == vccrypt_suite_prng_init(&suite, &prng));

    /* PRECONDITIONS: the got* values are unset. */
    TEST_EXPECT(nullptr == got_context);
    TEST_EXPECT(nullptr == got_buffer);
    TEST_EXPECT(0 == got_size);

    /* Calling the read method should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_prng_read_c(&prng, EXPECTED_BUFFER, EXPECTED_SIZE));

    /* POSTCONDITIONS: the got* values are set. */
    TEST_EXPECT(&prng == got_context);
    TEST_EXPECT(EXPECTED_BUFFER == got_buffer);
    TEST_EXPECT(EXPECTED_SIZE == got_size);

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
