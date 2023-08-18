/**
 * \file test/mock/suite/test_vccrypt_mock_prng_functions.cpp
 *
 * Unit tests for the Velo mock prng functions.
 *
 * \copyright 2020 Velo-Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>
#include <vpr/allocator/malloc_allocator.h>

/* DISABLED GTEST */
#if 0

/**
 * By default, the prng init function returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_prng_functions, init_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_prng_context_t prng;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* attempting to initiate a mock hash algorithm should fail. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_suite_prng_init(&suite, &prng));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * The prng init function can be mocked.
 */
TEST(vccrypt_mock_prng_functions, init_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_prng_context_t prng;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_prng_init(
            &suite,
            [&](vccrypt_prng_options_t*, vccrypt_prng_context_t*) -> int {
                return VCCRYPT_STATUS_SUCCESS;
            }));

    /* attempting to initiate a mock prng algorithm should work. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_prng_init(&suite, &prng));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * The prng dispose function can be mocked.
 */
TEST(vccrypt_mock_prng_functions, dispose_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_prng_context_t prng;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_prng_init(
            &suite,
            [&](vccrypt_prng_options_t*, vccrypt_prng_context_t*) -> int {
                return VCCRYPT_STATUS_SUCCESS;
            }));

    /* add a mock for the dispose method. */
    vccrypt_prng_options_t* got_options = nullptr;
    vccrypt_prng_context_t* got_context = nullptr;
    bool dispose_called = false;
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_prng_dispose(
            &suite,
            [&](
                vccrypt_prng_options_t* options,
                vccrypt_prng_context_t* context) -> void {
                    got_options = options;
                    got_context = context;
                    dispose_called = true;
            }));

    /* PRECONDITIONS: got* are unset. */
    EXPECT_EQ(nullptr, got_options);
    EXPECT_EQ(nullptr, got_context);
    EXPECT_FALSE(dispose_called);

    /* attempting to initiate a mock prng algorithm should work. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_prng_init(&suite, &prng));

    /* dispose a mock prng algorithm. */
    dispose((disposable_t*)&prng);

    /* POSTCONDITIONS: got* are set. */
    EXPECT_EQ(&suite.prng_opts, got_options);
    EXPECT_EQ(&prng, got_context);
    EXPECT_TRUE(dispose_called);

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the read mock returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_prng_functions, read_default)
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
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_prng_init(
            &suite,
            [&](vccrypt_prng_options_t*, vccrypt_prng_context_t*) -> int {
                return VCCRYPT_STATUS_SUCCESS;
            }));

    /* attempting to initiate a mock prng algorithm should work. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_prng_init(&suite, &prng));

    /* Calling the read method should result in an error. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_prng_read_c(
            &prng, EXPECTED_BUFFER, EXPECTED_SIZE));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It is possible to mock the read method.
 */
TEST(vccrypt_mock_prng_functions, read_mocked)
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
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_prng_init(
            &suite,
            [&](vccrypt_prng_options_t*, vccrypt_prng_context_t*) -> int {
                return VCCRYPT_STATUS_SUCCESS;
            }));

    /* add a mock for the read method. */
    vccrypt_prng_context_t* got_context = nullptr;
    uint8_t* got_buffer = nullptr;
    size_t got_size = 0;
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_prng_read(
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
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_prng_init(&suite, &prng));

    /* PRECONDITIONS: the got* values are unset. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_buffer);
    EXPECT_EQ(0, got_size);

    /* Calling the read method should succeed. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_prng_read_c(
            &prng, EXPECTED_BUFFER, EXPECTED_SIZE));

    /* POSTCONDITIONS: the got* values are set. */
    EXPECT_EQ(&prng, got_context);
    EXPECT_EQ(EXPECTED_BUFFER, got_buffer);
    EXPECT_EQ(EXPECTED_SIZE, got_size);

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
#endif
