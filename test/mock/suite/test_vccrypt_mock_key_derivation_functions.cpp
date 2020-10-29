/**
 * \file test/mock/suite/test_vccrypt_mock_key_derivation_functions.cpp
 *
 * Unit tests for the Velo mock key derivation functions.
 *
 * \copyright 2020 Velo-Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vccrypt/mock_suite.h>
#include <vpr/allocator/malloc_allocator.h>

/**
 * By default, the key derivation init function returns
 * VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_key_derivation_functions, init_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_derivation_context_t key;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* attempting to initialize mock key derivation should fail. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_suite_key_derivation_init(&key, &suite));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the key derivation init method.
 */
TEST(vccrypt_mock_key_derivation_functions, init_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_derivation_context_t key;

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
        vccrypt_mock_suite_add_mock_key_derivation_init(
            &suite,
            [&](
                vccrypt_key_derivation_context_t*,
                vccrypt_key_derivation_options_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* The init should now succeed. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_key_derivation_init(&key, &suite));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the key derivation dispose method.
 */
TEST(vccrypt_mock_key_derivation_functions, dispose_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_derivation_context_t key;

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
        vccrypt_mock_suite_add_mock_key_derivation_init(
            &suite,
            [&](
                vccrypt_key_derivation_context_t*,
                vccrypt_key_derivation_options_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* add a mock for the dispose method. */
    vccrypt_key_derivation_context_t* got_context = nullptr;
    vccrypt_key_derivation_options_t* got_options = nullptr;
    bool dispose_called = false;
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_key_derivation_dispose(
            &suite,
            [&](
                vccrypt_key_derivation_context_t* context,
                vccrypt_key_derivation_options_t* options) {
                    got_context = context;
                    got_options = options;
                    dispose_called = true;
            }));

    /* Initialize this instance via the mock. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_key_derivation_init(&key, &suite));

    /* PRECONDITIONS: parameters are unset. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_options);
    EXPECT_FALSE(dispose_called);

    /* Dispose this instance. */
    dispose((disposable_t*)&key);

    /* POSTCONDITIONS: parameters are set. */
    EXPECT_EQ(&key, got_context);
    EXPECT_EQ(&suite.key_derivation_opts, got_options);
    EXPECT_TRUE(dispose_called);

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the derive key function returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_key_derivation_functions, derive_key_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_derivation_context_t key;
    vccrypt_buffer_t pass;
    vccrypt_buffer_t salt;
    vccrypt_buffer_t derived_key;
    unsigned int rounds = 5000;

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
        vccrypt_mock_suite_add_mock_key_derivation_init(
            &suite,
            [&](
                vccrypt_key_derivation_context_t*,
                vccrypt_key_derivation_options_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* Initialize this instance via the mock. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_key_derivation_init(&key, &suite));

    /* Create a buffer for the password. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&pass, &alloc_opts, 10));

    /* Create a buffer for the salt. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&salt, &alloc_opts, 10));

    /* Create a buffer for the derived key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&derived_key, &alloc_opts, 10));

    /* The derive_key method fails. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_key_derivation_derive_key(
            &derived_key, &key, &pass, &salt, rounds));

    /* cleanup. */
    dispose((disposable_t*)&pass);
    dispose((disposable_t*)&salt);
    dispose((disposable_t*)&derived_key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the derive key function.
 */
TEST(vccrypt_mock_key_derivation_functions, derive_key_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_derivation_context_t key;
    vccrypt_buffer_t pass;
    vccrypt_buffer_t salt;
    vccrypt_buffer_t derived_key;
    unsigned int rounds = 5000;

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
        vccrypt_mock_suite_add_mock_key_derivation_init(
            &suite,
            [&](
                vccrypt_key_derivation_context_t*,
                vccrypt_key_derivation_options_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* add a mock for the derive key function. */
    vccrypt_buffer_t* got_derived_key = nullptr;
    vccrypt_key_derivation_context_t* got_context = nullptr;
    const vccrypt_buffer_t* got_pass = nullptr;
    const vccrypt_buffer_t* got_salt = nullptr;
    unsigned int got_rounds = 0;
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_key_derivation_derive_key(
            &suite,
            [&](
                vccrypt_buffer_t* param_derived_key,
                vccrypt_key_derivation_context_t* param_context,
                const vccrypt_buffer_t* param_pass,
                const vccrypt_buffer_t* param_salt,
                unsigned int param_rounds) -> int {
                    got_derived_key = param_derived_key;
                    got_context = param_context;
                    got_pass = param_pass;
                    got_salt = param_salt;
                    got_rounds = param_rounds;
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* Initialize this instance via the mock. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_key_derivation_init(&key, &suite));

    /* Create a buffer for the password. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&pass, &alloc_opts, 10));

    /* Create a buffer for the salt. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&salt, &alloc_opts, 10));

    /* Create a buffer for the derived key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&derived_key, &alloc_opts, 10));

    /* PRECONDITIONS: parameters are unset. */
    EXPECT_EQ(nullptr, got_derived_key);
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_pass);
    EXPECT_EQ(nullptr, got_salt);
    EXPECT_EQ(0, got_rounds);

    /* The mocked derive_key method succeeds. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_key_derivation_derive_key(
            &derived_key, &key, &pass, &salt, rounds));

    /* POSTCONDITIONS: parameters are set. */
    EXPECT_EQ(&derived_key, got_derived_key);
    EXPECT_EQ(&key, got_context);
    EXPECT_EQ(&pass, got_pass);
    EXPECT_EQ(&salt, got_salt);
    EXPECT_EQ(rounds, got_rounds);

    /* cleanup. */
    dispose((disposable_t*)&pass);
    dispose((disposable_t*)&salt);
    dispose((disposable_t*)&derived_key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
