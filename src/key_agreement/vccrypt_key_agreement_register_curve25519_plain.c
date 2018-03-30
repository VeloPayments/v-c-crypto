/**
 * \file vccrypt_key_agreement_register_curve25519_plain.c
 *
 * Register plain curve25519 and force a link dependency so that this algorithm
 * can be used at runtime.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
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

/* forward decls */
static int vccrypt_curve25519_plain_init(void* options, void* context);
static void vccrypt_curve25519_plain_dispose(void* options, void* context);
static int vccrypt_curve25519_plain_long_term_secret_create(
    void* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, vccrypt_buffer_t* shared);
static int vccrypt_curve25519_plain_keypair_create(
    void* context, vccrypt_buffer_t* priv, vccrypt_buffer_t* pub);

/* static data for this instance */
static abstract_factory_registration_t curve25519_plain_impl;
static vccrypt_key_agreement_options_t curve25519_plain_options;
static bool curve25519_plain_impl_registered = false;

/**
 * Register curve25519_plain for use by the crypto library.
 */
void vccrypt_key_agreement_register_curve25519_plain()
{
    MODEL_ASSERT(!curve25519_plain_impl_registered);

    /* only register once */
    if (curve25519_plain_impl_registered)
    {
        return;
    }

    /* we need HMAC-SHA-512/256 for curve25519_plain */
    vccrypt_mac_register_SHA_2_512_256_HMAC();

    /* set up the options for curve25519_plain */
    curve25519_plain_options.hdr.dispose = 0; /* disposal handled by init */
    curve25519_plain_options.alloc_opts = 0; /* allocator handled by init */
    curve25519_plain_options.prng_opts = 0; /* prng options handled by init */
    curve25519_plain_options.hash_algorithm = 0; /* no hash for plain */
    curve25519_plain_options.hmac_algorithm =
        VCCRYPT_MAC_ALGORITHM_SHA_2_512_256_HMAC;
    curve25519_plain_options.shared_secret_size =
        VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_256_SECRET_SIZE;
    curve25519_plain_options.private_key_size =
        VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_256_PRIVATE_KEY_SIZE;
    curve25519_plain_options.public_key_size =
        VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_256_PUBLIC_KEY_SIZE;
    curve25519_plain_options.minimum_nonce_size =
        VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_256_NONCE_SIZE;
    curve25519_plain_options.vccrypt_key_agreement_alg_init =
        &vccrypt_curve25519_plain_init;
    curve25519_plain_options.vccrypt_key_agreement_alg_dispose =
        &vccrypt_curve25519_plain_dispose;
    curve25519_plain_options.vccrypt_key_agreement_alg_long_term_secret_create =
        &vccrypt_curve25519_plain_long_term_secret_create;
    curve25519_plain_options.vccrypt_key_agreement_alg_keypair_create =
        &vccrypt_curve25519_plain_keypair_create;

    /* set up this registration for the abstract factory */
    curve25519_plain_impl.interface = VCCRYPT_INTERFACE_KEY;
    curve25519_plain_impl.implementation =
        VCCRYPT_KEY_AGREEMENT_ALGORITHM_CURVE25519_PLAIN;
    curve25519_plain_impl.implementation_features =
        VCCRYPT_KEY_AGREEMENT_ALGORITHM_CURVE25519_PLAIN;
    curve25519_plain_impl.factory = 0;
    curve25519_plain_impl.context = &curve25519_plain_options;

    /* register this instance */
    abstract_factory_register(&curve25519_plain_impl);

    /* only register once */
    curve25519_plain_impl_registered = true;
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
static int vccrypt_curve25519_plain_init(void* UNUSED(options), void* context)
{
    vccrypt_key_agreement_context_t* ctx =
        (vccrypt_key_agreement_context_t*)context;
    MODEL_ASSERT(ctx != NULL);

    /* we don't need separate state for plain mode */
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
static void vccrypt_curve25519_plain_dispose(
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
static int vccrypt_curve25519_plain_long_term_secret_create(
    void* UNUSED(context), const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, vccrypt_buffer_t* shared)
{
    MODEL_ASSERT(priv != NULL);
    MODEL_ASSERT(priv->data != NULL);
    MODEL_ASSERT(priv->size == X25519_KEY_LENGTH);
    MODEL_ASSERT(pub != NULL);
    MODEL_ASSERT(pub->data != NULL);
    MODEL_ASSERT(pub->size == X25519_KEY_LENGTH);
    MODEL_ASSERT(shared != NULL);
    MODEL_ASSERT(shared->data != NULL);
    MODEL_ASSERT(shared->size == X25519_KEY_LENGTH);

    return X25519(shared->data, priv->data, pub->data);
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
static int vccrypt_curve25519_plain_keypair_create(
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
