/**
 * \file test/mock/suite/test_vccrypt_mock_mac_functions.cpp
 *
 * Unit tests for the Velo mock mac functions.
 *
 * \copyright 2020-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <vccrypt/mock_suite.h>
#include <vpr/allocator/malloc_allocator.h>

TEST_SUITE(vccrypt_mock_mac_functions);

/**
 * By default, the mac init function returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(init_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_mac_context_t mac;
    vccrypt_buffer_t key;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* create a buffer for the mac key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_mac_private_key(
                    &suite, &key, false));

    /* attempting to initiate a mock mac algorithm should fail. */
    TEST_EXPECT(
        VCCRYPT_ERROR_MOCK_NOT_ADDED
            == vccrypt_suite_mac_init(&suite, &mac, &key));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the mac init method.
 */
TEST(init_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_mac_context_t mac;
    vccrypt_buffer_t key;

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
            == vccrypt_mock_suite_add_mock_mac_init(
                    &suite,
                    [&](
                        vccrypt_mac_options_t*, vccrypt_mac_context_t*,
                        const vccrypt_buffer_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* create a buffer for the mac key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_mac_private_key(
                    &suite, &key, false));

    /* We should now be able to init a mock mac context. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS == vccrypt_suite_mac_init(&suite, &mac, &key));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the mac dispose method.
 */
TEST(dispose_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_mac_context_t mac;
    vccrypt_buffer_t key;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_mac_init(
                    &suite,
                    [&](
                        vccrypt_mac_options_t*, vccrypt_mac_context_t*,
                        const vccrypt_buffer_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* add a mock for the dispose method. */
    vccrypt_mac_options_t* got_options = nullptr;
    vccrypt_mac_context_t* got_context = nullptr;
    bool dispose_called = false;
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_mac_dispose(
                    &suite,
                    [&](
                        vccrypt_mac_options_t* options,
                        vccrypt_mac_context_t* context) {
                            got_options = options;
                            got_context = context;
                            dispose_called = true;
                    }));

    /* create a buffer for the mac key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_mac_private_key(
                    &suite, &key, false));

    /* precondition: dispose_called is false. */
    TEST_EXPECT(nullptr == got_options);
    TEST_EXPECT(nullptr == got_context);
    TEST_EXPECT(!dispose_called);

    /* We should be able to init a mock mac context. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS == vccrypt_suite_mac_init(&suite, &mac, &key));

    /* Dispose this instance. */
    dispose((disposable_t*)&mac);

    /* postcondition: dispose_called should now be set to true. */
    TEST_EXPECT(&suite.mac_opts == got_options);
    TEST_EXPECT(&mac == got_context);
    TEST_EXPECT(dispose_called);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the mac digest method returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(digest_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_mac_context_t mac;
    vccrypt_buffer_t key;
    uint8_t EXPECTED_DATA[3] = { 0, 1, 2 };
    size_t EXPECTED_DATA_SIZE = sizeof(EXPECTED_DATA);

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_mac_init(
                    &suite,
                    [&](
                        vccrypt_mac_options_t*, vccrypt_mac_context_t*,
                        const vccrypt_buffer_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* create a buffer for the mac key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_mac_private_key(
                    &suite, &key, false));

    /* We should be able to init a mock mac context. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS == vccrypt_suite_mac_init(&suite, &mac, &key));

    /* Calling the digest method should return an error. */
    TEST_EXPECT(
        VCCRYPT_ERROR_MOCK_NOT_ADDED
            == vccrypt_mac_digest(&mac, EXPECTED_DATA, EXPECTED_DATA_SIZE));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the mac digest method.
 */
TEST(digest_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_mac_context_t mac;
    vccrypt_buffer_t key;
    uint8_t EXPECTED_DATA[3] = { 0, 1, 2 };
    size_t EXPECTED_DATA_SIZE = sizeof(EXPECTED_DATA);

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_mac_init(
                    &suite,
                    [&](
                        vccrypt_mac_options_t*, vccrypt_mac_context_t*,
                        const vccrypt_buffer_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* mock the digest method. */
    vccrypt_mac_context_t* got_context = nullptr;
    const uint8_t* got_data = nullptr;
    size_t got_size = 0;
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_mac_digest(
                    &suite,
                    [&](
                        vccrypt_mac_context_t* context, const uint8_t* data,
                        size_t size) -> int {

                            got_context = context;
                            got_data = data;
                            got_size = size;

                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* create a buffer for the mac key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_mac_private_key(
                    &suite, &key, false));

    /* We should be able to init a mock mac context. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS == vccrypt_suite_mac_init(&suite, &mac, &key));

    /* PRECONDITIONS: the got* values are unset. */
    TEST_EXPECT(nullptr == got_context);
    TEST_EXPECT(nullptr == got_data);
    TEST_EXPECT(0 == got_size);

    /* Calling the digest method should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mac_digest(&mac, EXPECTED_DATA, EXPECTED_DATA_SIZE));

    /* POSTCONDITIONS: the got* values are set. */
    TEST_EXPECT(&mac == got_context);
    TEST_EXPECT(EXPECTED_DATA == got_data);
    TEST_EXPECT(EXPECTED_DATA_SIZE == got_size);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the mac finalize method returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(finalize_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_mac_context_t mac;
    vccrypt_buffer_t key;
    vccrypt_buffer_t mac_buffer;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_mac_init(
                    &suite,
                    [&](
                        vccrypt_mac_options_t*, vccrypt_mac_context_t*,
                        const vccrypt_buffer_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* create a buffer for the mac key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_mac_private_key(
                    &suite, &key, false));

    /* create a buffer for the mac buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_mac_authentication_code(
                    &suite, &mac_buffer, false));

    /* We should be able to init a mock mac context. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS == vccrypt_suite_mac_init(&suite, &mac, &key));

    /* Calling the finalize method should return an error. */
    TEST_EXPECT(
        VCCRYPT_ERROR_MOCK_NOT_ADDED
            == vccrypt_mac_finalize(&mac, &mac_buffer));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&mac_buffer);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the finalize method.
 */
TEST(finalize_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_mac_context_t mac;
    vccrypt_buffer_t key;
    vccrypt_buffer_t mac_buffer;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* add a mock for the init method. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_mac_init(
                    &suite,
                    [&](
                        vccrypt_mac_options_t*, vccrypt_mac_context_t*,
                        const vccrypt_buffer_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* mock the finalize method. */
    vccrypt_mac_context_t* got_context = nullptr;
    vccrypt_buffer_t* got_digest = nullptr;
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_mac_finalize(
                    &suite,
                    [&](
                        vccrypt_mac_context_t* context,
                        vccrypt_buffer_t* digest)
                            -> int {

                        got_context = context;
                        got_digest = digest;

                        return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* create a buffer for the mac key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_mac_private_key(
                    &suite, &key, false));

    /* create a buffer for the mac buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_mac_authentication_code(
                    &suite, &mac_buffer, false));

    /* We should be able to init a mock mac context. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS == vccrypt_suite_mac_init(&suite, &mac, &key));

    /* PRECONDITIONS: the got* values are unset. */
    TEST_EXPECT(nullptr == got_context);
    TEST_EXPECT(nullptr == got_digest);

    /* Calling the finalize method should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS == vccrypt_mac_finalize(&mac, &mac_buffer));

    /* POSTCONDITIONS: the got* values are set. */
    TEST_EXPECT(&mac == got_context);
    TEST_EXPECT(&mac_buffer == got_digest);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&mac_buffer);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
