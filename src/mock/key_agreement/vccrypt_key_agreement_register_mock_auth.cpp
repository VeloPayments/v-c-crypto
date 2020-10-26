/**
 * \file vccrypt_key_agreement_register_mock_auth.c
 *
 * Register sha512 curve25519 and force a link dependency so that this algorithm
 * can be used at runtime.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/hash.h>
#include <vccrypt/key_agreement.h>
#include <vccrypt/mac.h>
#include <vccrypt/mock/key_agreement.h>
#include <vpr/abstract_factory.h>
#include <vpr/allocator.h>
#include <vpr/parameters.h>

/* forward decls */
static int vccrypt_mock_auth_init(void* options, void* context);
static void vccrypt_mock_auth_dispose(void* options, void* context);
static int vccrypt_mock_auth_options_init(
    void* options, allocator_options_t* alloc_opts);
static void vccrypt_mock_auth_options_dispose(void* disp);
static int vccrypt_mock_auth_long_term_secret_create(
    void* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, vccrypt_buffer_t* shared);
static int vccrypt_mock_auth_short_term_secret_create(
    void* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, const vccrypt_buffer_t* server_nonce,
    const vccrypt_buffer_t* client_nonce, vccrypt_buffer_t* shared);
static int vccrypt_mock_auth_keypair_create(
    void* context, vccrypt_buffer_t* priv, vccrypt_buffer_t* pub);

/* static data for this instance */
static abstract_factory_registration_t mock_auth_impl;
static vccrypt_key_agreement_options_t mock_auth_options;
static bool mock_auth_impl_registered = false;

/**
 * Register mock_auth for use by the crypto library.
 */
void vccrypt_key_agreement_register_mock_auth()
{
    MODEL_ASSERT(!mock_auth_impl_registered);

    /* only register once */
    if (mock_auth_impl_registered)
    {
        return;
    }

    /* set up the options for mock_auth */
    mock_auth_options.hdr.dispose =
        &vccrypt_mock_auth_options_dispose;
    mock_auth_options.alloc_opts = 0; /* allocator handled by init */
    mock_auth_options.prng_opts = 0; /* prng options handled by init */
    mock_auth_options.hash_algorithm =
        VCCRYPT_HASH_ALGORITHM_SHA_2_512;
    mock_auth_options.hmac_algorithm =
        VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC;
    mock_auth_options.shared_secret_size =
        VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_SECRET_SIZE;
    mock_auth_options.private_key_size =
        VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_PRIVATE_KEY_SIZE;
    mock_auth_options.public_key_size =
        VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_PUBLIC_KEY_SIZE;
    mock_auth_options.minimum_nonce_size =
        VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_NONCE_SIZE;
    mock_auth_options.vccrypt_key_agreement_alg_init =
        &vccrypt_mock_auth_init;
    mock_auth_options.vccrypt_key_agreement_alg_dispose =
        &vccrypt_mock_auth_dispose;
    mock_auth_options.vccrypt_key_agreement_alg_long_term_secret_create =
        &vccrypt_mock_auth_long_term_secret_create;
    mock_auth_options.vccrypt_key_agreement_alg_short_term_secret_create =
        &vccrypt_mock_auth_short_term_secret_create;
    mock_auth_options.vccrypt_key_agreement_alg_keypair_create =
        &vccrypt_mock_auth_keypair_create;
    mock_auth_options.vccrypt_key_agreement_alg_options_init =
        &vccrypt_mock_auth_options_init;

    /* set up this registration for the abstract factory */
    mock_auth_impl.interface = VCCRYPT_INTERFACE_KEY;
    mock_auth_impl.implementation =
        VCCRYPT_KEY_AGREEMENT_ALGORITHM_MOCK_AUTH;
    mock_auth_impl.implementation_features =
        VCCRYPT_KEY_AGREEMENT_ALGORITHM_MOCK_AUTH;
    mock_auth_impl.factory = 0;
    mock_auth_impl.context = &mock_auth_options;

    /* register this instance */
    abstract_factory_register(&mock_auth_impl);

    /* only register once */
    mock_auth_impl_registered = true;
}

/**
 * Algorithm-specific initialization for key agreement.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to the vccrypt_key_agreement_context_t
 *                  structure.
 *
 * \returns 0 on success and non-zero on error.
 */
static int vccrypt_mock_auth_init(void* options, void* context)
{
    vccrypt_key_agreement_options_t* key_opts =
        (vccrypt_key_agreement_options_t*)options;
    vccrypt_key_agreement_context_t* key_ctx =
        (vccrypt_key_agreement_context_t*)context;

    key_agreement_mock* mock =
        (key_agreement_mock*)key_opts->options_context;

    if (!mock->key_agreement_init_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->key_agreement_init_mock)(key_opts, key_ctx);
    }
}

/**
 * Algorithm-specific disposal for key agreement.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to the vccrypt_key_agreement_context_t
 *                  structure.
 */
static void vccrypt_mock_auth_dispose(
    void* options, void* context)
{
    vccrypt_key_agreement_options_t* key_opts =
        (vccrypt_key_agreement_options_t*)options;
    vccrypt_key_agreement_context_t* key_ctx =
        (vccrypt_key_agreement_context_t*)context;

    key_agreement_mock* mock =
        (key_agreement_mock*)key_opts->options_context;

    if (!!mock->key_agreement_dispose_mock)
    {
        (*mock->key_agreement_dispose_mock)(key_opts, key_ctx);
    }
}

/**
 * Generate the long-term secret, given a private key and a public key.
 *
 * \param context   Opaque pointer to the vccrypt_key_agreement_context_t
 *                  structure.
 * \param priv      The private key to use for this operation.
 * \param pub       The public key to use for this operation.
 * \param shared    The buffer to receive the long-term secret.
 *
 * \returns 0 on success and non-zero on error.
 */
static int vccrypt_mock_auth_long_term_secret_create(
    void* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, vccrypt_buffer_t* shared)
{
    vccrypt_key_agreement_context_t* key_ctx =
        (vccrypt_key_agreement_context_t*)context;
    vccrypt_key_agreement_options_t* key_opts = key_ctx->options;

    key_agreement_mock* mock =
        (key_agreement_mock*)key_opts->options_context;

    if (!mock->key_agreement_long_term_secret_create_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return
            (*mock->key_agreement_long_term_secret_create_mock)(
                key_ctx, priv, pub, shared);
    }
}

/**
 * \brief Generate the short-term secret, given a private key, a public
 * key, a server nonce, and a client nonce.
 *
 * \param context       Opaque pointer to the
 *                      vccrypt_key_agreement_context_t structure.
 * \param priv          The private key to use for this operation.
 * \param pub           The public key to use for this operation.
 * \param server_nonce  The server nonce to use for this operation.
 * \param client_nonce  The client nonce to use for this operation.
 * \param shared        The buffer to receive the long-term secret.
 *
 * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
 */
static int vccrypt_mock_auth_short_term_secret_create(
    void* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, const vccrypt_buffer_t* server_nonce,
    const vccrypt_buffer_t* client_nonce, vccrypt_buffer_t* shared)
{
    vccrypt_key_agreement_context_t* key_ctx =
        (vccrypt_key_agreement_context_t*)context;
    vccrypt_key_agreement_options_t* key_opts = key_ctx->options;

    key_agreement_mock* mock =
        (key_agreement_mock*)key_opts->options_context;

    if (!mock->key_agreement_short_term_secret_create_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return
            (*mock->key_agreement_short_term_secret_create_mock)(
                key_ctx, priv, pub, server_nonce, client_nonce, shared);
    }
}

/**
 * Generate a keypair.
 *
 * \param context   Opaque pointer to the vccrypt_key_agreement_context_t
 *                  structure.
 * \param priv      The buffer to receive the private key.
 * \param pub       The buffer to receive the public key.
 *
 * \returns 0 on success and non-zero on error.
 */
static int vccrypt_mock_auth_keypair_create(
    void* context, vccrypt_buffer_t* priv, vccrypt_buffer_t* pub)
{
    vccrypt_key_agreement_context_t* key_ctx =
        (vccrypt_key_agreement_context_t*)context;
    vccrypt_key_agreement_options_t* key_opts = key_ctx->options;

    key_agreement_mock* mock =
        (key_agreement_mock*)key_opts->options_context;

    if (!mock->key_agreement_keypair_create_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->key_agreement_keypair_create_mock)(key_ctx, priv, pub);
    }
}

/**
 * \brief Implementation specific options init method.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options structure for this method.
 *
 * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
 */
static int vccrypt_mock_auth_options_init(
    void* options, allocator_options_t* UNUSED(alloc_opts))
{
    vccrypt_key_agreement_options_t* key_opts =
        (vccrypt_key_agreement_options_t*)options;

    key_opts->options_context = new key_agreement_mock;

    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure.
 *
 * \param options   the options structure to dispose.
 */
static void vccrypt_mock_auth_options_dispose(void* disp)
{
    vccrypt_key_agreement_options_t* key_opts =
        (vccrypt_key_agreement_options_t*)disp;

    MODEL_ASSERT(key_opts != NULL);

    key_agreement_mock* mock = (key_agreement_mock*)key_opts->options_context;
    delete mock;

    memset(key_opts, 0, sizeof(vccrypt_key_agreement_options_t));
}
