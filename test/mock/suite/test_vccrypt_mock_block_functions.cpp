/**
 * \file test/mock/suite/test_vccrypt_mock_block_functions.cpp
 *
 * Unit tests for the Velo mock block functions.
 *
 * \copyright 2020-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <vccrypt/mock_suite.h>
#include <vpr/allocator/malloc_allocator.h>

TEST_SUITE(vccrypt_mock_block_functions);

/**
 * By default, the block init function returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(init_default)
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
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* create a buffer for the block key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(
                    &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* attempting to initiate a mock block algorithm should fail. */
    TEST_EXPECT(
        VCCRYPT_ERROR_MOCK_NOT_ADDED
            == vccrypt_suite_block_init(&suite, &block, &key, true));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the init function.
 */
TEST(init_mocked)
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
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init function. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_block_init(
                    &suite,
                    [&](
                        vccrypt_block_options_t*, vccrypt_block_context_t*,
                        const vccrypt_buffer_t*, bool) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* create a buffer for the block key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(
                    &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* The init method should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_block_init(&suite, &block, &key, true));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the dispose function.
 */
TEST(dispose_mocked)
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
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init function. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_block_init(
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
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_block_dispose(
                    &suite,
                    [&](
                        vccrypt_block_options_t* param_options,
                        vccrypt_block_context_t* param_context) {
                            got_options = param_options;
                            got_context = param_context;
                            dispose_called = true;
                    }));

    /* create a buffer for the block key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(
                    &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* The init method should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_block_init(&suite, &block, &key, true));

    /* PRECONDITIONS: params are unset. */
    TEST_EXPECT(nullptr == got_options);
    TEST_EXPECT(nullptr == got_context);
    TEST_EXPECT(!dispose_called);

    /* call dispose. */
    dispose((disposable_t*)&block);

    /* POSTCONDITIONS: params are set. */
    TEST_EXPECT(&suite.block_cipher_opts == got_options);
    TEST_EXPECT(&block == got_context);
    TEST_EXPECT(dispose_called);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the block encrypt function returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(block_encrypt_default)
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
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init function. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_block_init(
                    &suite,
                    [&](
                        vccrypt_block_options_t*, vccrypt_block_context_t*,
                        const vccrypt_buffer_t*, bool) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* create a buffer for the block key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(
                    &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* The init method should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_block_init(&suite, &block, &key, true));

    /* Calling the block encrypt function should fail. */
    TEST_EXPECT(
        VCCRYPT_ERROR_MOCK_NOT_ADDED
            == vccrypt_block_encrypt(&block, iv, input, output));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the block encrypt function.
 */
TEST(block_encrypt_mocked)
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
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init function. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_block_init(
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
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_block_encrypt(
                    &suite,
                    [&](
                        vccrypt_block_context_t* param_context,
                        const void* param_iv, const void* param_input,
                        void* param_output) -> int {
                            got_context = param_context;
                            got_iv = param_iv;
                            got_input = param_input;
                            got_output = param_output;
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* create a buffer for the block key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(
                    &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* The init method should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_block_init(&suite, &block, &key, true));

    /* PRECONDITIONS: params are unset. */
    TEST_EXPECT(nullptr == got_context);
    TEST_EXPECT(nullptr == got_iv);
    TEST_EXPECT(nullptr == got_input);
    TEST_EXPECT(nullptr == got_output);

    /* Calling the block encrypt function should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_block_encrypt(&block, iv, input, output));

    /* POSTCONDITIONS: params are set. */
    TEST_EXPECT(&block == got_context);
    TEST_EXPECT(iv == got_iv);
    TEST_EXPECT(input == got_input);
    TEST_EXPECT(output == got_output);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the block decrypt function returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(block_decrypt_default)
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
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init function. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_block_init(
                    &suite,
                    [&](
                        vccrypt_block_options_t*, vccrypt_block_context_t*,
                        const vccrypt_buffer_t*, bool) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* create a buffer for the block key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(
                    &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* The init method should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_block_init(&suite, &block, &key, true));

    /* Calling the block decrypt function should fail. */
    TEST_EXPECT(
        VCCRYPT_ERROR_MOCK_NOT_ADDED
            == vccrypt_block_decrypt(&block, iv, input, output));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the block decrypt function.
 */
TEST(block_decrypt_mocked)
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
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init function. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_block_init(
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
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_block_decrypt(
                    &suite,
                    [&](
                        vccrypt_block_context_t* param_context,
                        const void* param_iv, const void* param_input,
                        void* param_output) -> int {
                            got_context = param_context;
                            got_iv = param_iv;
                            got_input = param_input;
                            got_output = param_output;
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* create a buffer for the block key. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(
                    &key, &alloc_opts, suite.block_cipher_opts.key_size));

    /* The init method should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_block_init(&suite, &block, &key, true));

    /* PRECONDITIONS: params are unset. */
    TEST_EXPECT(nullptr == got_context);
    TEST_EXPECT(nullptr == got_iv);
    TEST_EXPECT(nullptr == got_input);
    TEST_EXPECT(nullptr == got_output);

    /* Calling the block decrypt function should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_block_decrypt(&block, iv, input, output));

    /* POSTCONDITIONS: params are set. */
    TEST_EXPECT(&block == got_context);
    TEST_EXPECT(iv == got_iv);
    TEST_EXPECT(input == got_input);
    TEST_EXPECT(output == got_output);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
