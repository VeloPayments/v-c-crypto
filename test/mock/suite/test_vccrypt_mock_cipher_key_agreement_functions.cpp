/**
 * \file test/mock/suite/test_vccrypt_mock_cipher_key_agreement_functions.cpp
 *
 * Unit tests for the Velo mock cipher key agreement functions.
 *
 * \copyright 2020 Velo-Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vccrypt/mock_suite.h>
#include <vpr/allocator/malloc_allocator.h>

/**
 * By default, the cipher key agreement init function returns
 * VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_cipher_key_agreement_functions, init_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_agreement_context_t agreement;

    /* register the mock suite. */
    vccrypt_suite_register_mock();

    /* create the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initializing the mock suite should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_options_init(&suite, &alloc_opts));

    /* attempting to initialize mock cipher key agreement should fail. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_suite_cipher_key_agreement_init(&suite, &agreement));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the cipher key agreement init method.
 */
TEST(vccrypt_mock_cipher_key_agreement_functions, init_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_agreement_context_t agreement;

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
        vccrypt_mock_suite_add_mock_cipher_key_agreement_init(
            &suite,
            [&](
                vccrypt_key_agreement_options_t*,
                vccrypt_key_agreement_context_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* The init should now succeed. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_cipher_key_agreement_init(&suite, &agreement));

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the cipher key agreement dispose method.
 */
TEST(vccrypt_mock_cipher_key_agreement_functions, dispose_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_agreement_context_t agreement;

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
        vccrypt_mock_suite_add_mock_cipher_key_agreement_init(
            &suite,
            [&](
                vccrypt_key_agreement_options_t*,
                vccrypt_key_agreement_context_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* add a mock for the dispose method. */
    vccrypt_key_agreement_options_t* got_options = nullptr;
    vccrypt_key_agreement_context_t* got_context = nullptr;
    bool dispose_called = false;
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_cipher_key_agreement_dispose(
            &suite,
            [&](
                vccrypt_key_agreement_options_t* options,
                vccrypt_key_agreement_context_t* context) {
                    got_options = options;
                    got_context = context;
                    dispose_called = true;
            }));

    /* PRECONDITIONS: dispose_called is false. */
    EXPECT_EQ(nullptr, got_options);
    EXPECT_EQ(nullptr, got_context);
    EXPECT_FALSE(dispose_called);

    /* We should be able to init a mock cipher key agreement instance. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_cipher_key_agreement_init(&suite, &agreement));

    /* Dispose this instance. */
    dispose((disposable_t*)&agreement);

    /* POSTCONDITIONS: dispose_called should now be set to true. */
    EXPECT_EQ(&suite.key_cipher_opts, got_options);
    EXPECT_EQ(&agreement, got_context);
    EXPECT_TRUE(dispose_called);

    /* cleanup. */
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the long term secret create function returns
 * VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_cipher_key_agreement_functions, long_term_secret_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_agreement_context_t agreement;
    vccrypt_buffer_t priv, pub, shared;

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
        vccrypt_mock_suite_add_mock_cipher_key_agreement_init(
            &suite,
            [&](
                vccrypt_key_agreement_options_t*,
                vccrypt_key_agreement_context_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create pub key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
            &suite, &pub));

    /* create priv key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_private_key(
            &suite, &priv));

    /* create shared key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
            &suite, &shared));

    /* We should be able to init a mock cipher key agreement instance. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_cipher_key_agreement_init(&suite, &agreement));

    /* Calling the long-term shared secret create method fails. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_key_agreement_long_term_secret_create(
            &agreement, &priv, &pub, &shared));

    /* cleanup. */
    dispose((disposable_t*)&pub);
    dispose((disposable_t*)&priv);
    dispose((disposable_t*)&shared);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the long term shared secret create function.
 */
TEST(vccrypt_mock_cipher_key_agreement_functions, long_term_secret_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_agreement_context_t agreement;
    vccrypt_buffer_t priv, pub, shared;

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
        vccrypt_mock_suite_add_mock_cipher_key_agreement_init(
            &suite,
            [&](
                vccrypt_key_agreement_options_t*,
                vccrypt_key_agreement_context_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* add a mock for the long-term secret create method. */
    vccrypt_key_agreement_context_t* got_context = nullptr;
    const vccrypt_buffer_t* got_priv = nullptr;
    const vccrypt_buffer_t* got_pub = nullptr;
    vccrypt_buffer_t* got_shared = nullptr;
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_cipher_key_agreement_long_term_secret_create(
            &suite,
            [&](
                vccrypt_key_agreement_context_t* context,
                const vccrypt_buffer_t* priv_param,
                const vccrypt_buffer_t* pub_param,
                vccrypt_buffer_t* shared_param) {
                    got_context = context;
                    got_priv = priv_param;
                    got_pub = pub_param;
                    got_shared = shared_param;

                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create pub key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
            &suite, &pub));

    /* create priv key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_private_key(
            &suite, &priv));

    /* create shared key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
            &suite, &shared));

    /* PRECONDITIONS: parameters are unset. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_priv);
    EXPECT_EQ(nullptr, got_pub);
    EXPECT_EQ(nullptr, got_shared);

    /* We should be able to init a mock cipher key agreement instance. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_cipher_key_agreement_init(&suite, &agreement));

    /* We should be able to run the mock long term shared secret create mock. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_key_agreement_long_term_secret_create(
            &agreement, &priv, &pub, &shared));

    /* POSTCONDITIONS: parameters are set. */
    EXPECT_EQ(&agreement, got_context);
    EXPECT_EQ(&priv, got_priv);
    EXPECT_EQ(&pub, got_pub);
    EXPECT_EQ(&shared, got_shared);

    /* cleanup. */
    dispose((disposable_t*)&pub);
    dispose((disposable_t*)&priv);
    dispose((disposable_t*)&shared);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the short term secret create function returns
 * VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_cipher_key_agreement_functions, short_term_secret_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_agreement_context_t agreement;
    vccrypt_buffer_t priv, pub, shared, server_nonce, client_nonce;

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
        vccrypt_mock_suite_add_mock_cipher_key_agreement_init(
            &suite,
            [&](
                vccrypt_key_agreement_options_t*,
                vccrypt_key_agreement_context_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create pub key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
            &suite, &pub));

    /* create priv key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_private_key(
            &suite, &priv));

    /* create shared key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
            &suite, &shared));

    /* create server nonce buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &suite, &server_nonce));

    /* create client nonce buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &suite, &client_nonce));

    /* We should be able to init a mock cipher key agreement instance. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_cipher_key_agreement_init(&suite, &agreement));

    /* Calling the short-term shared secret create method fails. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_key_agreement_short_term_secret_create(
            &agreement, &priv, &pub, &server_nonce, &client_nonce, &shared));

    /* cleanup. */
    dispose((disposable_t*)&pub);
    dispose((disposable_t*)&priv);
    dispose((disposable_t*)&shared);
    dispose((disposable_t*)&server_nonce);
    dispose((disposable_t*)&client_nonce);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the short term shared secret create function.
 */
TEST(vccrypt_mock_cipher_key_agreement_functions, short_term_secret_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_agreement_context_t agreement;
    vccrypt_buffer_t priv, pub, shared, server_nonce, client_nonce;

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
        vccrypt_mock_suite_add_mock_cipher_key_agreement_init(
            &suite,
            [&](
                vccrypt_key_agreement_options_t*,
                vccrypt_key_agreement_context_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* add a mock for the short-term secret create method. */
    vccrypt_key_agreement_context_t* got_context = nullptr;
    const vccrypt_buffer_t* got_priv = nullptr;
    const vccrypt_buffer_t* got_pub = nullptr;
    const vccrypt_buffer_t* got_server_nonce = nullptr;
    const vccrypt_buffer_t* got_client_nonce = nullptr;
    vccrypt_buffer_t* got_shared = nullptr;
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_cipher_key_agreement_short_term_secret_create(
            &suite,
            [&](
                vccrypt_key_agreement_context_t* context,
                const vccrypt_buffer_t* priv_param,
                const vccrypt_buffer_t* pub_param,
                const vccrypt_buffer_t* server_nonce_param,
                const vccrypt_buffer_t* client_nonce_param,
                vccrypt_buffer_t* shared_param) {
                    got_context = context;
                    got_priv = priv_param;
                    got_pub = pub_param;
                    got_server_nonce = server_nonce_param;
                    got_client_nonce = client_nonce_param;
                    got_shared = shared_param;

                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create pub key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
            &suite, &pub));

    /* create priv key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_private_key(
            &suite, &priv));

    /* create shared key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
            &suite, &shared));

    /* create server nonce buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &suite, &server_nonce));

    /* create client nonce buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &suite, &client_nonce));

    /* We should be able to init a mock cipher key agreement instance. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_cipher_key_agreement_init(&suite, &agreement));

    /* PRECONDITIONS: parameters are unset. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_priv);
    EXPECT_EQ(nullptr, got_pub);
    EXPECT_EQ(nullptr, got_server_nonce);
    EXPECT_EQ(nullptr, got_client_nonce);
    EXPECT_EQ(nullptr, got_shared);

    /* Calling the short-term shared secret create method succeeds. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_key_agreement_short_term_secret_create(
            &agreement, &priv, &pub, &server_nonce, &client_nonce, &shared));

    /* POSTCONDITIONS: parameters are set. */
    EXPECT_EQ(&agreement, got_context);
    EXPECT_EQ(&priv, got_priv);
    EXPECT_EQ(&pub, got_pub);
    EXPECT_EQ(&server_nonce, got_server_nonce);
    EXPECT_EQ(&client_nonce, got_client_nonce);
    EXPECT_EQ(&shared, got_shared);

    /* cleanup. */
    dispose((disposable_t*)&pub);
    dispose((disposable_t*)&priv);
    dispose((disposable_t*)&shared);
    dispose((disposable_t*)&server_nonce);
    dispose((disposable_t*)&client_nonce);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * By default, the keypair create function returns VCCRYPT_ERROR_MOCK_NOT_ADDED.
 */
TEST(vccrypt_mock_cipher_key_agreement_functions, keypair_create_default)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_agreement_context_t agreement;
    vccrypt_buffer_t priv, pub;

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
        vccrypt_mock_suite_add_mock_cipher_key_agreement_init(
            &suite,
            [&](
                vccrypt_key_agreement_options_t*,
                vccrypt_key_agreement_context_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create pub key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
            &suite, &pub));

    /* create priv key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_private_key(
            &suite, &priv));

    /* We should be able to init a mock cipher key agreement instance. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_cipher_key_agreement_init(&suite, &agreement));

    /* Calling the keypair create method fails. */
    EXPECT_EQ(
        VCCRYPT_ERROR_MOCK_NOT_ADDED,
        vccrypt_key_agreement_keypair_create(
            &agreement, &priv, &pub));

    /* cleanup. */
    dispose((disposable_t*)&pub);
    dispose((disposable_t*)&priv);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * It's possible to mock the keypair create function.
 */
TEST(vccrypt_mock_cipher_key_agreement_functions, keypair_create_mocked)
{
    vccrypt_suite_options_t suite;
    allocator_options_t alloc_opts;
    vccrypt_key_agreement_context_t agreement;
    vccrypt_buffer_t priv, pub;

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
        vccrypt_mock_suite_add_mock_cipher_key_agreement_init(
            &suite,
            [&](
                vccrypt_key_agreement_options_t*,
                vccrypt_key_agreement_context_t*) -> int {
                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* add a mock for the keypair create method. */
    vccrypt_key_agreement_context_t* got_context = nullptr;
    const vccrypt_buffer_t* got_priv = nullptr;
    const vccrypt_buffer_t* got_pub = nullptr;
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mock_suite_add_mock_cipher_key_agreement_keypair_create(
            &suite,
            [&](
                vccrypt_key_agreement_context_t* context,
                const vccrypt_buffer_t* priv_param,
                const vccrypt_buffer_t* pub_param) {
                    got_context = context;
                    got_priv = priv_param;
                    got_pub = pub_param;

                    return VCCRYPT_STATUS_SUCCESS;
            }));

    /* create pub key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
            &suite, &pub));

    /* create priv key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_private_key(
            &suite, &priv));

    /* We should be able to init a mock cipher key agreement instance. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_cipher_key_agreement_init(&suite, &agreement));

    /* PRECONDITIONS: parameters are unset. */
    EXPECT_EQ(nullptr, got_context);
    EXPECT_EQ(nullptr, got_priv);
    EXPECT_EQ(nullptr, got_pub);

    /* Calling the keypair create method succeeds. */
    EXPECT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_key_agreement_keypair_create(
            &agreement, &priv, &pub));

    /* POSTCONDITIONS: parameters are set. */
    EXPECT_EQ(&agreement, got_context);
    EXPECT_EQ(&priv, got_priv);
    EXPECT_EQ(&pub, got_pub);

    /* cleanup. */
    dispose((disposable_t*)&pub);
    dispose((disposable_t*)&priv);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
