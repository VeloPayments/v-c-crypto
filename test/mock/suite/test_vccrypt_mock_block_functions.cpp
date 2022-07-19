/**
 * \file test/mock/suite/test_vccrypt_mock_block_functions.cpp
 *
 * Unit tests for the Velo mock block functions.
 *
 * \copyright 2020 Velo-Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vccrypt/mock_suite.h>
#include <vpr/allocator/malloc_allocator.h>

/**
 * By default, the block init function returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_block_functions, init_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_block_context_t block;
    vccrypt_buffer_t key;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* create a buffer for the block key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* attempting to initiate a mock block algorithm should fail. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_suite_block_init(&suite, &block, &key, true));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the init function.
 */
TEST(vccrypt_mock_block_functions, init_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_block_context_t block;
    vccrypt_buffer_t key;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init function. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_block_init(
            &suite,
            [&](
                vccrypt_block_options_t*, vccrypt_block_context_t*,
                const vccrypt_buffer_t*, bool) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the block key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* The init method should succeed. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_block_init(&suite, &block, &key, true));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the dispose function.
 */
TEST(vccrypt_mock_block_functions, dispose_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_block_context_t block;
    vccrypt_buffer_t key;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init function. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_block_init(
            &suite,
            [&](
                vccrypt_block_options_t*, vccrypt_block_context_t*,
                const vccrypt_buffer_t*, bool) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* mock the dispose function. */
    vccrypt_block_options_t* got_options = nullptr;
    vccrypt_block_context_t* got_context = nullptr;
    bool dispose_called = false;
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_block_dispose(
            &suite,
            [&](
                vccrypt_block_options_t* param_options,
                vccrypt_block_context_t* param_context) {
                    got_options = param_options;
                    got_context = param_context;
                    dispose_called = true;
            }));

    /* create a buffer for the block key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* The init method should succeed. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_block_init(&suite, &block, &key, true));

    /* PRECONDITIONS: params are unset. */
    EXPECT_EQ(nullptr, got_options);
    EXPECT_EQ(nullptr, got_context);
    EXPECT_FALSE(dispose_called);

    /* call dispose. */
    dispose((disposable_t*)&block);

    /* POSTCONDITIONS: params are set. */
    EXPECT_EQ(&suite.block_cipher_opts, got_options);
    EXPECT_EQ(&block, got_context);
    EXPECT_TRUE(dispose_called);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the block encrypt function returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_block_functions, block_encrypt_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_block_context_t block;
    vccrypt_buffer_t key;
    const uint8_t iv[16] = { 0 };
    const uint8_t input[16] = { 0 };
    uint8_t output[16] = { 0 };

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init function. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_block_init(
            &suite,
            [&](
                vccrypt_block_options_t*, vccrypt_block_context_t*,
                const vccrypt_buffer_t*, bool) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the block key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* The init method should succeed. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_block_init(&suite, &block, &key, true));

    /* Calling the block encrypt function should fail. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_block_encrypt(&block, iv, input, output));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the block encrypt function.
 */
TEST(vccrypt_mock_block_functions, block_encrypt_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_block_context_t block;
    vccrypt_buffer_t key;
    const uint8_t iv[16] = { 0 };
    const uint8_t input[16] = { 0 };
    uint8_t output[16] = { 0 };

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init function. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_block_init(
            &suite,
            [&](
                vccrypt_block_options_t*, vccrypt_block_context_t*,
                const vccrypt_buffer_t*, bool) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* mock the block encrypt function. */
    vccrypt_block_context_t* got_context = nullptr;
    const void* got_iv = nullptr;
    const void* got_input = nullptr;
    void* got_output = nullptr;
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_block_encrypt(
            &suite,
            [&](
                vccrypt_block_context_t* param_context, const void* param_iv,
                const void* param_input, void* param_output) -> int {
                    got_context = param_context;
                    got_iv = param_iv;
                    got_input = param_input;
                    got_output = param_output;
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the block key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* The init method should succeed. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_block_init(&suite, &block, &key, true));

    /* PRECONDITIONS: params are unset. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_iv);
    EXPECT_EQ(nullptr, got_input);
    EXPECT_EQ(nullptr, got_output);

    /* Calling the block encrypt function should succeed. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_block_encrypt(&block, iv, input, output));

    /* POSTCONDITIONS: params are set. */
    EXPECT_EQ(&block, got_context);
    EXPECT_EQ(iv, got_iv);
    EXPECT_EQ(input, got_input);
    EXPECT_EQ(output, got_output);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the block decrypt function returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_block_functions, block_decrypt_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_block_context_t block;
    vccrypt_buffer_t key;
    const uint8_t iv[16] = { 0 };
    const uint8_t input[16] = { 0 };
    uint8_t output[16] = { 0 };

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init function. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_block_init(
            &suite,
            [&](
                vccrypt_block_options_t*, vccrypt_block_context_t*,
                const vccrypt_buffer_t*, bool) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the block key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* The init method should succeed. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_block_init(&suite, &block, &key, true));

    /* Calling the block decrypt function should fail. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_block_decrypt(&block, iv, input, output));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the block decrypt function.
 */
TEST(vccrypt_mock_block_functions, block_decrypt_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_block_context_t block;
    vccrypt_buffer_t key;
    const uint8_t iv[16] = { 0 };
    const uint8_t input[16] = { 0 };
    uint8_t output[16] = { 0 };

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init function. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_block_init(
            &suite,
            [&](
                vccrypt_block_options_t*, vccrypt_block_context_t*,
                const vccrypt_buffer_t*, bool) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* mock the block decrypt function. */
    vccrypt_block_context_t* got_context = nullptr;
    const void* got_iv = nullptr;
    const void* got_input = nullptr;
    void* got_output = nullptr;
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_block_decrypt(
            &suite,
            [&](
                vccrypt_block_context_t* param_context, const void* param_iv,
                const void* param_input, void* param_output) -> int {
                    got_context = param_context;
                    got_iv = param_iv;
                    got_input = param_input;
                    got_output = param_output;
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the block key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* The init method should succeed. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_block_init(&suite, &block, &key, true));

    /* PRECONDITIONS: params are unset. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_iv);
    EXPECT_EQ(nullptr, got_input);
    EXPECT_EQ(nullptr, got_output);

    /* Calling the block decrypt function should succeed. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_block_decrypt(&block, iv, input, output));

    /* POSTCONDITIONS: params are set. */
    EXPECT_EQ(&block, got_context);
    EXPECT_EQ(iv, got_iv);
    EXPECT_EQ(input, got_input);
    EXPECT_EQ(output, got_output);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
