/**
 * \file vccrypt_key_agreement_register_curve25519_sha512.c
 *
 * Register sha512 curve25519 and force a link dependency so that this algorithm
 * can be used at runtime.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/key_agreement.h>
#include <vccrypt/hash.h>
#include <vccrypt/mac.h>
#include <vpr/abstract_factory.h>
#include <vpr/allocator.h>
#include <vpr/parameters.h>

#include "../digital_signature/ref/curve25519.h"
#include "key_agreement_common.h"

/* forward decls */
static int vccrypt_curve25519_sha512_init(void* options, void* context);
static void vccrypt_curve25519_sha512_dispose(void* options, void* context);
static int vccrypt_curve25519_sha512_options_init(
    void* options, allocator_options_t* alloc_opts);
static void vccrypt_curve25519_sha512_options_dispose(void* disp);
static int vccrypt_curve25519_sha512_long_term_secret_create(
    void* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, vccrypt_buffer_t* shared);
static int vccrypt_curve25519_sha512_short_term_secret_create(
    void* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, const vccrypt_buffer_t* server_nonce,
    const vccrypt_buffer_t* client_nonce, vccrypt_buffer_t* shared);
static int vccrypt_curve25519_sha512_keypair_create(
    void* context, vccrypt_buffer_t* priv, vccrypt_buffer_t* pub);

/* static data for this instance */
static abstract_factory_registration_t curve25519_sha512_impl;
static vccrypt_key_agreement_options_t curve25519_sha512_options;
static bool curve25519_sha512_impl_registered = false;

/**
 * Register curve25519_sha512 for use by the crypto library.
 */
void vccrypt_key_agreement_register_curve25519_sha512()
{
    MODEL_ASSERT(!curve25519_sha512_impl_registered);

    /* only register once */
    if (curve25519_sha512_impl_registered)
    {
        return;
    }

    /* we need HMAC-SHA-512 for curve25519_sha512 */
    vccrypt_mac_register_SHA_2_512_HMAC();

    /* set up the options for curve25519_sha512 */
    curve25519_sha512_options.hdr.dispose =
        &vccrypt_curve25519_sha512_options_dispose;
    curve25519_sha512_options.alloc_opts = 0; /* allocator handled by init */
    curve25519_sha512_options.prng_opts = 0; /* prng options handled by init */
    curve25519_sha512_options.hash_algorithm =
        VCCRYPT_HASH_ALGORITHM_SHA_2_512;
    curve25519_sha512_options.hmac_algorithm =
        VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC;
    curve25519_sha512_options.shared_secret_size =
        VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_SECRET_SIZE;
    curve25519_sha512_options.private_key_size =
        VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_PRIVATE_KEY_SIZE;
    curve25519_sha512_options.public_key_size =
        VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_PUBLIC_KEY_SIZE;
    curve25519_sha512_options.minimum_nonce_size =
        VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_NONCE_SIZE;
    curve25519_sha512_options.vccrypt_key_agreement_alg_init =
        &vccrypt_curve25519_sha512_init;
    curve25519_sha512_options.vccrypt_key_agreement_alg_dispose =
        &vccrypt_curve25519_sha512_dispose;
    curve25519_sha512_options.vccrypt_key_agreement_alg_long_term_secret_create =
        &vccrypt_curve25519_sha512_long_term_secret_create;
    curve25519_sha512_options.vccrypt_key_agreement_alg_short_term_secret_create =
        &vccrypt_curve25519_sha512_short_term_secret_create;
    curve25519_sha512_options.vccrypt_key_agreement_alg_keypair_create =
        &vccrypt_curve25519_sha512_keypair_create;
    curve25519_sha512_options.vccrypt_key_agreement_alg_options_init =
        &vccrypt_curve25519_sha512_options_init;

    /* set up this registration for the abstract factory */
    curve25519_sha512_impl.interface = VCCRYPT_INTERFACE_KEY;
    curve25519_sha512_impl.implementation =
        VCCRYPT_KEY_AGREEMENT_ALGORITHM_CURVE25519_SHA512;
    curve25519_sha512_impl.implementation_features =
        VCCRYPT_KEY_AGREEMENT_ALGORITHM_CURVE25519_SHA512;
    curve25519_sha512_impl.factory = 0;
    curve25519_sha512_impl.context = &curve25519_sha512_options;

    /* register this instance */
    abstract_factory_register(&curve25519_sha512_impl);

    /* only register once */
    curve25519_sha512_impl_registered = true;
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
static int vccrypt_curve25519_sha512_init(void* UNUSED(options), void* context)
{
    vccrypt_key_agreement_context_t* ctx =
        (vccrypt_key_agreement_context_t*)context;
    MODEL_ASSERT(ctx != NULL);

    /* we don't need separate state for sha512 mode */
    ctx->key_agreement_state = NULL;

    /* success */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Algorithm-specific disposal for key agreement.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to the vccrypt_key_agreement_context_t
 *                  structure.
 */
static void vccrypt_curve25519_sha512_dispose(
    void* UNUSED(options), void* UNUSED(context))
{
    /* no special cleanup needed */
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
static int vccrypt_curve25519_sha512_long_term_secret_create(
    void* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, vccrypt_buffer_t* shared)
{
    int retval = VCCRYPT_STATUS_SUCCESS;
    vccrypt_key_agreement_context_t* ctx =
        (vccrypt_key_agreement_context_t*)context;
    MODEL_ASSERT(ctx != NULL);
    MODEL_ASSERT(ctx->options != NULL);
    MODEL_ASSERT(priv != NULL);
    MODEL_ASSERT(priv->data != NULL);
    MODEL_ASSERT(priv->size == X25519_KEY_LENGTH);
    MODEL_ASSERT(pub != NULL);
    MODEL_ASSERT(pub->data != NULL);
    MODEL_ASSERT(pub->size == X25519_KEY_LENGTH);
    MODEL_ASSERT(shared != NULL);
    MODEL_ASSERT(shared->data != NULL);
    MODEL_ASSERT(shared->size == ctx->options->shared_secret_size);

    /* create the buffer for holding the long term secret from curve */
    vccrypt_buffer_t ltprime;
    retval = vccrypt_buffer_init(
        &ltprime, ctx->options->alloc_opts, X25519_KEY_LENGTH);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        return retval;
    }

    /* generate the curve25519 long term secret */
    retval = X25519(ltprime.data, priv->data, pub->data);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto dispose_ltprime;
    }

    /* create a hash options instance */
    vccrypt_hash_options_t hash_opts;
    retval = vccrypt_hash_options_init(
        &hash_opts, ctx->options->alloc_opts,
        ctx->options->hash_algorithm);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto dispose_ltprime;
    }

    /* create hash instance */
    vccrypt_hash_context_t hash;
    retval = vccrypt_hash_init(&hash_opts, &hash);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto dispose_hash_opts;
    }

    /* digest the curve25519 long term secret */
    retval = vccrypt_hash_digest(&hash, ltprime.data, ltprime.size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto dispose_hash;
    }

    /* finalize the hash */
    retval = vccrypt_hash_finalize(&hash, shared);

    /* fall-through */

dispose_hash:
    dispose((disposable_t*)&hash);

dispose_hash_opts:
    dispose((disposable_t*)&hash_opts);

dispose_ltprime:
    dispose((disposable_t*)&ltprime);

    return retval;
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
static int vccrypt_curve25519_sha512_short_term_secret_create(
    void* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, const vccrypt_buffer_t* server_nonce,
    const vccrypt_buffer_t* client_nonce, vccrypt_buffer_t* shared)
{
    vccrypt_key_agreement_context_t* ctx =
        (vccrypt_key_agreement_context_t*)context;

    return
        vccrypt_key_agreement_short_term_secret_create_common(
            ctx, priv, pub, server_nonce, client_nonce, shared);
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
static int vccrypt_curve25519_sha512_keypair_create(
    void* context, vccrypt_buffer_t* priv, vccrypt_buffer_t* pub)
{
    vccrypt_key_agreement_context_t* ctx =
        (vccrypt_key_agreement_context_t*)context;
    MODEL_ASSERT(ctx != NULL);
    MODEL_ASSERT(ctx->options != NULL);
    MODEL_ASSERT(ctx->options->prng_opts != NULL);
    int retval = VCCRYPT_STATUS_SUCCESS;

    /* create a PRNG context for use by the keypair algorithm */
    vccrypt_prng_context_t prng_ctx;
    retval = vccrypt_prng_init(ctx->options->prng_opts, &prng_ctx);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        return retval;
    }

    /* generate the keypair */
    retval =
        X25519_keypair(pub->data, priv->data, &prng_ctx);

    /* dispose of the prng */
    dispose((disposable_t*)&prng_ctx);

    return retval;
}

/**
 * \brief Implementation specific options init method.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options structure for this method.
 *
 * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
 */
static int vccrypt_curve25519_sha512_options_init(
    void* UNUSED(options), allocator_options_t* UNUSED(alloc_opts))
{
    /* do nothing. */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure.
 *
 * \param options   the options structure to dispose.
 */
static void vccrypt_curve25519_sha512_options_dispose(void* disp)
{
    MODEL_ASSERT(disp != NULL);

    memset(disp, 0, sizeof(vccrypt_key_agreement_options_t));
}
