/**
 * \file test/mock/suite/test_vccrypt_mock_hash_options.cpp
 *
 * Unit tests for the Velo mock hash functions.
 *
 * \copyright 2020 Velo-Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vccrypt/mock_suite.h>
#include <vpr/allocator/malloc_allocator.h>

/**
 * By default, the hash init function returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_hash_functions, init_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_hash_context_t hash;

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
        vccrypt_suite_hash_init(&suite, &hash));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the hash init method.
 */
TEST(vccrypt_mock_hash_functions, init_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_hash_context_t hash;

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
        vccrypt_mock_suite_add_mock_hash_init(
            &suite,
            [&](vccrypt_hash_options_t*, vccrypt_hash_context_t*) -> int {
                return VCCRYPT_STATUS_SUCCESS;
            }));

    /* We should now be able to init a mock hash context. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_hash_init(&suite, &hash));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the hash dispose method.
 */
TEST(vccrypt_mock_hash_functions, dispose_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_hash_context_t hash;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_hash_init(
            &suite,
            [&](vccrypt_hash_options_t*, vccrypt_hash_context_t*) -> int {
                return VCCRYPT_STATUS_SUCCESS;
            }));

    /* add a mock for the dispose method. */
    bool dispose_called = false;
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_hash_dispose(
            &suite,
            [&](vccrypt_hash_options_t*, vccrypt_hash_context_t*) {
                dispose_called = true;
            }));

    /* precondition: dispose_called is false. */
    EXPECT_FALSE(dispose_called);

    /* We should be able to init a mock hash context. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_hash_init(&suite, &hash));

    /* Dispose this instance. */
    dispose((disposable_t*)&hash);

    /* postcondition: dispose_called should now be set to true. */
    EXPECT_TRUE(dispose_called);

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the hash digest method returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_hash_functions, digest_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_hash_context_t hash;
    uint8_t EXPECTED_DATA[3] = { 0, 1, 2 };
    size_t EXPECTED_DATA_SIZE = sizeof(EXPECTED_DATA);

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_hash_init(
            &suite,
            [&](vccrypt_hash_options_t*, vccrypt_hash_context_t*) -> int {
                return VCCRYPT_STATUS_SUCCESS;
            }));

    /* We should be able to init a mock hash context. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_hash_init(&suite, &hash));

    /* Calling the digest method should return an error. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_hash_digest(&hash, EXPECTED_DATA, EXPECTED_DATA_SIZE));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * The digest method can be mocked.
 */
TEST(vccrypt_mock_hash_functions, digest_mock)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_hash_context_t hash;
    uint8_t EXPECTED_DATA[3] = { 0, 1, 2 };
    size_t EXPECTED_DATA_SIZE = sizeof(EXPECTED_DATA);

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_hash_init(
            &suite,
            [&](vccrypt_hash_options_t*, vccrypt_hash_context_t*) -> int {
                return VCCRYPT_STATUS_SUCCESS;
            }));

    /* mock the digest method. */
    vccrypt_hash_context_t* got_context = nullptr;
    const uint8_t* got_data = nullptr;
    size_t got_size = 0;
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_hash_digest(
            &suite,
            [&](
                vccrypt_hash_context_t* context, const uint8_t* data,
                size_t size) -> int {

                    got_context = context;
                    got_data = data;
                    got_size = size;

                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* We should be able to init a mock hash context. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_hash_init(&suite, &hash));

    /* precondition: the got* values are blank. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_data);
    EXPECT_EQ(0, got_size);

    /* Calling the digest method should call our mock. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_hash_digest(&hash, EXPECTED_DATA, EXPECTED_DATA_SIZE));

    /* postcondition: the got* values are set. */
    EXPECT_EQ(&hash, got_context);
    EXPECT_EQ(EXPECTED_DATA, got_data);
    EXPECT_EQ(EXPECTED_DATA_SIZE, got_size);

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the hash finalize method returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_hash_functions, finalize_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_hash_context_t hash;
    vccrypt_buffer_t digest;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_hash_init(
            &suite,
            [&](vccrypt_hash_options_t*, vccrypt_hash_context_t*) -> int {
                return VCCRYPT_STATUS_SUCCESS;
            }));

    /* We should be able to init a mock hash context. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_hash_init(&suite, &hash));

    /* create a buffer for holding the hash. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_hash(&suite, &digest));

    /* Calling the finalize method should return an error. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_hash_finalize(&hash, &digest));

    /* cleanup. */
    dispose((disposable_t*)&digest);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * The finalize method can be mocked.
 */
TEST(vccrypt_mock_hash_functions, finalize_mock)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_hash_context_t hash;
    vccrypt_buffer_t digest;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_hash_init(
            &suite,
            [&](vccrypt_hash_options_t*, vccrypt_hash_context_t*) -> int {
                return VCCRYPT_STATUS_SUCCESS;
            }));

    /* mock the finalize method. */
    vccrypt_hash_context_t* got_context = nullptr;
    vccrypt_buffer_t* got_digest = nullptr;
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_hash_finalize(
            &suite,
            [&](
                vccrypt_hash_context_t* context, vccrypt_buffer_t* digest)
                    -> int {

                got_context = context;
                got_digest = digest;

                return VCCRYPT_STATUS_SUCCESS;
            }));

    /* We should be able to init a mock hash context. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_hash_init(&suite, &hash));

    /* create a buffer for holding the hash. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_hash(&suite, &digest));

    /* precondition: the got* values are blank. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_digest);

    /* Calling the digest method should call our mock. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_hash_finalize(&hash, &digest));

    /* postcondition: the got* values are set. */
    EXPECT_EQ(&hash, got_context);
    EXPECT_EQ(&digest, got_digest);

    /* cleanup. */
    dispose((disposable_t*)&digest);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
