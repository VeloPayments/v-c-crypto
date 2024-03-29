/**
 * \file test/mock/suite/test_vccrypt_mock_digital_signature_functions.cpp
 *
 * Unit tests for the Velo mock digital signature functions.
 *
 * \copyright 2020-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <vccrypt/mock_suite.h>
#include <vpr/allocator/malloc_allocator.h>

TEST_SUITE(vccrypt_mock_digital_signature_functions);

/**
 * By default, the digital signature init function returns
 * VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(init_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_digital_signature_context_t sign;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* attempting to initiate a mock digital signature algorithm should fail. */
    TEST_EXPECT(
        VCCRYPT_ERROR_MOCK_NOT_ADDED
            == vccrypt_suite_digital_signature_init(&suite, &sign));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the digital_signature_init method.
 */
TEST(init_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_digital_signature_context_t sign;

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
            == vccrypt_mock_suite_add_mock_digital_signature_init(
                    &suite,
                    [&](
                        vccrypt_digital_signature_options_t*,
                        vccrypt_digital_signature_context_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* digital signature init should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_digital_signature_init(&suite, &sign));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock the digital_signature_dispose method.
 */
TEST(dispose_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_digital_signature_context_t sign;

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
            == vccrypt_mock_suite_add_mock_digital_signature_init(
                    &suite,
                    [&](
                        vccrypt_digital_signature_options_t*,
                        vccrypt_digital_signature_context_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* add a mock for the dispose method. */
    vccrypt_digital_signature_options_t* got_options = nullptr;
    vccrypt_digital_signature_context_t* got_context = nullptr;
    bool dispose_called = false;
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_digital_signature_dispose(
                    &suite,
                    [&](
                        vccrypt_digital_signature_options_t* options,
                        vccrypt_digital_signature_context_t* context) {
                            got_options = options;
                            got_context = context;
                            dispose_called = true;
                    }));

    /* digital signature init should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_digital_signature_init(&suite, &sign));

    /* PRECONDITIONS: got* values unset. */
    TEST_EXPECT(nullptr == got_options);
    TEST_EXPECT(nullptr == got_context);
    TEST_EXPECT(!dispose_called);

    /* call dispose. */
    dispose((disposable_t*)&sign);

    /* POSTCONDITIONS: got* values set. */
    TEST_EXPECT(&suite.sign_opts == got_options);
    TEST_EXPECT(&sign == got_context);
    TEST_EXPECT(dispose_called);

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the digital signature sign function returns
 * VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(sign_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_digital_signature_context_t sign;
    vccrypt_buffer_t sign_buffer;
    vccrypt_buffer_t priv;
    const uint8_t EXPECTED_MESSAGE[3] = { 7, 8, 9 };
    size_t EXPECTED_MESSAGE_SIZE = sizeof(EXPECTED_MESSAGE);

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
            == vccrypt_mock_suite_add_mock_digital_signature_init(
                    &suite,
                    [&](
                        vccrypt_digital_signature_options_t*,
                        vccrypt_digital_signature_context_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* digital signature init should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_digital_signature_init(&suite, &sign));

    /* create sign buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_signature(&suite, &sign_buffer));

    /* create priv buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_signature_private_key(
                    &suite, &priv));

    /* sign should fail. */
    TEST_EXPECT(
        VCCRYPT_ERROR_MOCK_NOT_ADDED
            == vccrypt_digital_signature_sign(
                    &sign, &sign_buffer, &priv, EXPECTED_MESSAGE,
                    EXPECTED_MESSAGE_SIZE));

    /* cleanup. */
    dispose((disposable_t*)&sign_buffer);
    dispose((disposable_t*)&priv);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We should be able to mock the sign method.
 */
TEST(sign_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_digital_signature_context_t sign;
    vccrypt_buffer_t sign_buffer;
    vccrypt_buffer_t priv;
    const uint8_t EXPECTED_MESSAGE[3] = { 7, 8, 9 };
    size_t EXPECTED_MESSAGE_SIZE = sizeof(EXPECTED_MESSAGE);

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
            == vccrypt_mock_suite_add_mock_digital_signature_init(
                    &suite,
                    [&](
                        vccrypt_digital_signature_options_t*,
                        vccrypt_digital_signature_context_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* add a mock for the sign method. */
    vccrypt_digital_signature_context_t* got_context = nullptr;
    vccrypt_buffer_t* got_sign_buffer = nullptr;
    const vccrypt_buffer_t* got_priv = nullptr;
    const uint8_t* got_message = nullptr;
    size_t got_message_size = 0;
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_digital_signature_sign(
                    &suite,
                    [&](
                        vccrypt_digital_signature_context_t* context,
                        vccrypt_buffer_t* sign_buffer_param,
                        const vccrypt_buffer_t* priv_param,
                        const uint8_t* message,
                        size_t message_size) -> int {
                            got_context = context;
                            got_sign_buffer = sign_buffer_param;
                            got_priv = priv_param;
                            got_message = message;
                            got_message_size = message_size;

                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* digital signature init should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_digital_signature_init(&suite, &sign));

    /* create sign buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_signature(&suite, &sign_buffer));

    /* create priv buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_signature_private_key(
                    &suite, &priv));

    /* PRECONDITIONS: got* values should be unset. */
    TEST_EXPECT(nullptr == got_context);
    TEST_EXPECT(nullptr == got_sign_buffer);
    TEST_EXPECT(nullptr == got_priv);
    TEST_EXPECT(nullptr == got_message);
    TEST_EXPECT(0 == got_message_size);

    /* sign should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_digital_signature_sign(
                    &sign, &sign_buffer, &priv, EXPECTED_MESSAGE,
                    EXPECTED_MESSAGE_SIZE));

    /* POSTCONDITIONS: got* values should be set. */
    TEST_EXPECT(&sign == got_context);
    TEST_EXPECT(&sign_buffer == got_sign_buffer);
    TEST_EXPECT(&priv == got_priv);
    TEST_EXPECT(EXPECTED_MESSAGE == got_message);
    TEST_EXPECT(EXPECTED_MESSAGE_SIZE == got_message_size);

    /* cleanup. */
    dispose((disposable_t*)&sign_buffer);
    dispose((disposable_t*)&priv);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the digital signature verify function returns
 * VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(verify_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_digital_signature_context_t sign;
    vccrypt_buffer_t sign_buffer;
    vccrypt_buffer_t pub;
    const uint8_t EXPECTED_MESSAGE[3] = { 7, 8, 9 };
    size_t EXPECTED_MESSAGE_SIZE = sizeof(EXPECTED_MESSAGE);

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
            == vccrypt_mock_suite_add_mock_digital_signature_init(
                    &suite,
                    [&](
                        vccrypt_digital_signature_options_t*,
                        vccrypt_digital_signature_context_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* digital signature init should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_digital_signature_init(&suite, &sign));

    /* create sign buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_signature(&suite, &sign_buffer));

    /* create pub buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_signature_public_key(
                    &suite, &pub));

    /* verify should fail. */
    TEST_EXPECT(
        VCCRYPT_ERROR_MOCK_NOT_ADDED
            == vccrypt_digital_signature_verify(
                    &sign, &sign_buffer, &pub, EXPECTED_MESSAGE,
                    EXPECTED_MESSAGE_SIZE));

    /* cleanup. */
    dispose((disposable_t*)&sign_buffer);
    dispose((disposable_t*)&pub);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We should be able to mock the verify method.
 */
TEST(verify_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_digital_signature_context_t sign;
    vccrypt_buffer_t sign_buffer;
    vccrypt_buffer_t pub;
    const uint8_t EXPECTED_MESSAGE[3] = { 7, 8, 9 };
    size_t EXPECTED_MESSAGE_SIZE = sizeof(EXPECTED_MESSAGE);

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
            == vccrypt_mock_suite_add_mock_digital_signature_init(
                    &suite,
                    [&](
                        vccrypt_digital_signature_options_t*,
                        vccrypt_digital_signature_context_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* add a mock for the verify method. */
    vccrypt_digital_signature_context_t* got_context = nullptr;
    const vccrypt_buffer_t* got_signature = nullptr;
    const vccrypt_buffer_t* got_pub = nullptr;
    const uint8_t* got_message = nullptr;
    size_t got_message_size = 0;
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_digital_signature_verify(
                    &suite,
                    [&](
                        vccrypt_digital_signature_context_t* context,
                        const vccrypt_buffer_t* signature,
                        const vccrypt_buffer_t* pub_param, const uint8_t* message,
                        size_t message_size) -> int {
                            got_context = context;
                            got_signature = signature;
                            got_pub = pub_param;
                            got_message = message;
                            got_message_size = message_size;
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* digital signature init should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_digital_signature_init(&suite, &sign));

    /* create sign buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_signature(&suite, &sign_buffer));

    /* create pub buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_signature_public_key(
                    &suite, &pub));

    /* PRECONDITIONS: got* values are unset. */
    TEST_EXPECT(nullptr == got_context);
    TEST_EXPECT(nullptr == got_signature);
    TEST_EXPECT(nullptr == got_pub);
    TEST_EXPECT(nullptr == got_message);
    TEST_EXPECT(0 == got_message_size);

    /* verify should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_digital_signature_verify(
                    &sign, &sign_buffer, &pub, EXPECTED_MESSAGE,
                    EXPECTED_MESSAGE_SIZE));

    /* POSTCONDITIONS: got* values are set. */
    TEST_EXPECT(&sign == got_context);
    TEST_EXPECT(&sign_buffer == got_signature);
    TEST_EXPECT(&pub == got_pub);
    TEST_EXPECT(EXPECTED_MESSAGE == got_message);
    TEST_EXPECT(EXPECTED_MESSAGE_SIZE == got_message_size);

    /* cleanup. */
    dispose((disposable_t*)&sign_buffer);
    dispose((disposable_t*)&pub);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the digital signature keypair_create function returns
 * VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(keypair_create_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_digital_signature_context_t sign;
    vccrypt_buffer_t pub;
    vccrypt_buffer_t priv;

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
            == vccrypt_mock_suite_add_mock_digital_signature_init(
                    &suite,
                    [&](
                        vccrypt_digital_signature_options_t*,
                        vccrypt_digital_signature_context_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* digital signature init should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_digital_signature_init(&suite, &sign));

    /* create priv buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_signature_private_key(
                    &suite, &priv));

    /* create pub buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_signature_public_key(
                    &suite, &pub));

    /* keypair_create should fail. */
    TEST_EXPECT(
        VCCRYPT_ERROR_MOCK_NOT_ADDED
            == vccrypt_digital_signature_keypair_create(&sign, &priv, &pub));

    /* cleanup. */
    dispose((disposable_t*)&priv);
    dispose((disposable_t*)&pub);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can mock keypair_create.
 */
TEST(keypair_create_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_digital_signature_context_t sign;
    vccrypt_buffer_t pub;
    vccrypt_buffer_t priv;

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
            == vccrypt_mock_suite_add_mock_digital_signature_init(
                    &suite,
                    [&](
                        vccrypt_digital_signature_options_t*,
                        vccrypt_digital_signature_context_t*) -> int {
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* add a mock for the keypair_create method. */
    vccrypt_digital_signature_context_t* got_context = nullptr;
    vccrypt_buffer_t* got_priv = nullptr;
    vccrypt_buffer_t* got_pub = nullptr;
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_mock_suite_add_mock_digital_signature_keypair_create(
                    &suite,
                    [&](
                        vccrypt_digital_signature_context_t* context,
                        vccrypt_buffer_t* priv_param,
                        vccrypt_buffer_t* pub_param) -> int {
                            got_context = context;
                            got_priv = priv_param;
                            got_pub = pub_param;
                            return VCCRYPT_STATUS_SUCCESS;
                    }));

    /* digital signature init should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_digital_signature_init(&suite, &sign));

    /* create priv buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_signature_private_key(
                    &suite, &priv));

    /* create pub buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_signature_public_key(
                    &suite, &pub));

    /* PRECONDITIONS: got* values are unset. */
    TEST_EXPECT(nullptr == got_context);
    TEST_EXPECT(nullptr == got_priv);
    TEST_EXPECT(nullptr == got_pub);

    /* keypair_create should succeed. */
    TEST_EXPECT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_digital_signature_keypair_create(&sign, &priv, &pub));

    /* POSTCONDITIONS: got* values are set. */
    TEST_EXPECT(&sign == got_context);
    TEST_EXPECT(&priv == got_priv);
    TEST_EXPECT(&pub == got_pub);

    /* cleanup. */
    dispose((disposable_t*)&priv);
    dispose((disposable_t*)&pub);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
