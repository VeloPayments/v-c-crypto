/**
 * \file test/mock/suite/test_vccrypt_mock_stream_functions.cpp
 *
 * Unit tests for the Velo mock stream functions.
 *
 * \copyright 2020 Velo-Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vccrypt/mock_suite.h>
#include <vpr/allocator/malloc_allocator.h>

/**
 * By default, the stream init function returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_stream_functions, init_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* attempting to initiate a mock block algorithm should fail. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the init method.
 */
TEST(vccrypt_mock_stream_functions, init_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the dispose method.
 */
TEST(vccrypt_mock_stream_functions, dispose_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* mock the dispose method. */
    vccrypt_stream_options_t* got_options = nullptr;
    vccrypt_stream_context_t* got_context = nullptr;
    bool dispose_called = false;
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_dispose(
            &suite,
            [&](
                vccrypt_stream_options_t* param_options,
                vccrypt_stream_context_t* param_context) {
                    got_options = param_options;
                    got_context = param_context;
                    dispose_called = true;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* PRECONDITIONS: params are unset. */
    EXPECT_EQ(nullptr, got_options);
    EXPECT_EQ(nullptr, got_context);
    EXPECT_FALSE(dispose_called);

    /* call dispose to call our dispose mock. */
    dispose((disposable_t*)&stream);

    /* POSTCONDITIONS: params are set. */
    EXPECT_EQ(&suite.stream_cipher_opts, got_options);
    EXPECT_EQ(&stream, got_context);
    EXPECT_TRUE(dispose_called);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, start encryption returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_stream_functions, start_encryption_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;
    const uint8_t iv[16] = { 0 };
    size_t iv_size = 16;
    uint8_t output[16];
    size_t offset = 0;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* start encryption fails. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_stream_start_encryption(&stream, iv, iv_size, output, &offset));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the start encryption function.
 */
TEST(vccrypt_mock_stream_functions, start_encryption_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;
    const uint8_t iv[16] = { 0 };
    size_t iv_size = 16;
    uint8_t output[16];
    size_t offset = 0;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* mock the start encryption method. */
    vccrypt_stream_context_t* got_context = nullptr;
    const void* got_iv = nullptr;
    size_t got_iv_size = 0;
    void* got_output = nullptr;
    size_t* got_offset = nullptr;
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_start_encryption(
            &suite,
            [&](
                vccrypt_stream_context_t* param_context, const void* param_iv,
                size_t param_iv_size, void* param_output,
                size_t* param_offset) -> int {
                    got_context = param_context;
                    got_iv = param_iv;
                    got_iv_size = param_iv_size;
                    got_output = param_output;
                    got_offset = param_offset;
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* PRECONDITIONS: params are unset. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_iv);
    EXPECT_EQ(0, got_iv_size);
    EXPECT_EQ(nullptr, got_output);
    EXPECT_EQ(nullptr, got_offset);

    /* start encryption calls our mock. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_stream_start_encryption(&stream, iv, iv_size, output, &offset));

    /* POSTCONDITIONS: params are unset. */
    EXPECT_EQ(&stream, got_context);
    EXPECT_EQ(iv, got_iv);
    EXPECT_EQ(iv_size, got_iv_size);
    EXPECT_EQ(output, got_output);
    EXPECT_EQ(&offset, got_offset);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, continue encryption returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_stream_functions, continue_encryption_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;
    const uint8_t iv[16] = { 0 };
    size_t iv_size = 16;
    size_t offset = 999;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* continue encryption fails. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_stream_continue_encryption(
            &stream, iv, iv_size, offset));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the continue encryption function.
 */
TEST(vccrypt_mock_stream_functions, continue_encryption_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;
    const uint8_t iv[16] = { 0 };
    size_t iv_size = 16;
    size_t offset = 999;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* mock the start encryption method. */
    vccrypt_stream_context_t* got_context = nullptr;
    const void* got_iv = nullptr;
    size_t got_iv_size = 0;
    size_t got_offset = 0;
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_continue_encryption(
            &suite,
            [&](
                vccrypt_stream_context_t* param_context, const void* param_iv,
                size_t param_iv_size, size_t param_offset) -> int {
                    got_context = param_context;
                    got_iv = param_iv;
                    got_iv_size = param_iv_size;
                    got_offset = param_offset;
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* PRECONDITIONS: params are unset. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_iv);
    EXPECT_EQ(0, got_iv_size);
    EXPECT_EQ(0, got_offset);

    /* continue encryption calls our mock. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_stream_continue_encryption(&stream, iv, iv_size, offset));

    /* POSTCONDITIONS: params are unset. */
    EXPECT_EQ(&stream, got_context);
    EXPECT_EQ(iv, got_iv);
    EXPECT_EQ(iv_size, got_iv_size);
    EXPECT_EQ(offset, got_offset);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, start decryption returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_stream_functions, start_decryption_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;
    uint8_t input[16];
    size_t offset = 0;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* start encryption fails. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_stream_start_decryption(&stream, input, &offset));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the start decryption function.
 */
TEST(vccrypt_mock_stream_functions, start_decryption_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;
    uint8_t input[16];
    size_t offset = 0;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* mock the start encryption method. */
    vccrypt_stream_context_t* got_context = nullptr;
    const void* got_input = nullptr;
    size_t* got_offset = nullptr;
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_start_decryption(
            &suite,
            [&](
                vccrypt_stream_context_t* param_context,
                const void* param_input, size_t* param_offset) -> int {
                    got_context = param_context;
                    got_input = param_input;
                    got_offset = param_offset;
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* PRECONDITIONS: params are unset. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_input);
    EXPECT_EQ(nullptr, got_offset);

    /* start decryption calls our mock. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_stream_start_decryption(&stream, input, &offset));

    /* POSTCONDITIONS: params are unset. */
    EXPECT_EQ(&stream, got_context);
    EXPECT_EQ(input, got_input);
    EXPECT_EQ(&offset, got_offset);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, continue decryption returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_stream_functions, continue_decryption_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;
    const uint8_t iv[16] = { 0 };
    size_t iv_size = 16;
    size_t offset = 999;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* continue decryption fails. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_stream_continue_decryption(
            &stream, iv, iv_size, offset));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the continue decryption function.
 */
TEST(vccrypt_mock_stream_functions, continue_decryption_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;
    const uint8_t iv[16] = { 0 };
    size_t iv_size = 16;
    size_t offset = 999;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* mock the continue decryption method. */
    vccrypt_stream_context_t* got_context = nullptr;
    const void* got_iv = nullptr;
    size_t got_iv_size = 0;
    size_t got_offset = 0;
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_continue_decryption(
            &suite,
            [&](
                vccrypt_stream_context_t* param_context, const void* param_iv,
                size_t param_iv_size, size_t param_offset) -> int {
                    got_context = param_context;
                    got_iv = param_iv;
                    got_iv_size = param_iv_size;
                    got_offset = param_offset;
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* PRECONDITIONS: params are unset. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_iv);
    EXPECT_EQ(0, got_iv_size);
    EXPECT_EQ(0, got_offset);

    /* continue decryption calls our mock. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_stream_continue_decryption(&stream, iv, iv_size, offset));

    /* POSTCONDITIONS: params are unset. */
    EXPECT_EQ(&stream, got_context);
    EXPECT_EQ(iv, got_iv);
    EXPECT_EQ(iv_size, got_iv_size);
    EXPECT_EQ(offset, got_offset);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, encrypt returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_stream_functions, encrypt_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;
    uint8_t input[16] = { 0 };
    size_t size = 16;
    uint8_t output[16];
    size_t offset = 0;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* encrypt fails. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_stream_encrypt(&stream, input, size, output, &offset));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the encrypt function.
 */
TEST(vccrypt_mock_stream_functions, encrypt_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;
    const uint8_t input[16] = { 0 };
    size_t size = 16;
    uint8_t output[16];
    size_t offset = 0;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* mock the encrypt method. */
    vccrypt_stream_context_t* got_context = nullptr;
    const void* got_input = nullptr;
    size_t got_size = 0;
    void* got_output = nullptr;
    size_t* got_offset = nullptr;
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_encrypt(
            &suite,
            [&](
                vccrypt_stream_context_t* param_context,
                const void* param_input, size_t param_size, void* param_output,
                size_t* param_offset) -> int {
                    got_context = param_context;
                    got_input = param_input;
                    got_size = param_size;
                    got_output = param_output;
                    got_offset = param_offset;
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* PRECONDITIONS: params are unset. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_input);
    EXPECT_EQ(0, got_size);
    EXPECT_EQ(nullptr, got_output);
    EXPECT_EQ(nullptr, got_offset);

    /* encrypt calls our mock. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_stream_encrypt(&stream, input, size, output, &offset));

    /* POSTCONDITIONS: params are unset. */
    EXPECT_EQ(&stream, got_context);
    EXPECT_EQ(input, got_input);
    EXPECT_EQ(size, got_size);
    EXPECT_EQ(output, got_output);
    EXPECT_EQ(&offset, got_offset);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, decrypt returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_stream_functions, decrypt_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;
    uint8_t input[16] = { 0 };
    size_t size = 16;
    uint8_t output[16];
    size_t offset = 0;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* decrypt fails. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_stream_decrypt(&stream, input, size, output, &offset));

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the decrypt function.
 */
TEST(vccrypt_mock_stream_functions, decrypt_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_stream_context_t stream;
    vccrypt_buffer_t key;
    const uint8_t input[16] = { 0 };
    size_t size = 16;
    uint8_t output[16];
    size_t offset = 0;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* mock the init method. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_init(
            &suite,
            [&](
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                vccrypt_buffer_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* mock the decrypt method. */
    vccrypt_stream_context_t* got_context = nullptr;
    const void* got_input = nullptr;
    size_t got_size = 0;
    void* got_output = nullptr;
    size_t* got_offset = nullptr;
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_stream_decrypt(
            &suite,
            [&](
                vccrypt_stream_context_t* param_context,
                const void* param_input, size_t param_size, void* param_output,
                size_t* param_offset) -> int {
                    got_context = param_context;
                    got_input = param_input;
                    got_size = param_size;
                    got_output = param_output;
                    got_offset = param_offset;
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create a buffer for the stream key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* We should be able to call init successfully. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &key));

    /* PRECONDITIONS: params are unset. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_input);
    EXPECT_EQ(0, got_size);
    EXPECT_EQ(nullptr, got_output);
    EXPECT_EQ(nullptr, got_offset);

    /* decrypt calls our mock. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_stream_decrypt(&stream, input, size, output, &offset));

    /* POSTCONDITIONS: params are unset. */
    EXPECT_EQ(&stream, got_context);
    EXPECT_EQ(input, got_input);
    EXPECT_EQ(size, got_size);
    EXPECT_EQ(output, got_output);
    EXPECT_EQ(&offset, got_offset);

    /* cleanup. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
