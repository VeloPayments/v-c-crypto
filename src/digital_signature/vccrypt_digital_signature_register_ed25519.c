/**
 * \file vccrypt_digital_signature_register_ed25519.c
 *
 * Register ed25519 and force a link dependency so that this algorithm can be
 * used at runtime.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/digital_signature.h>
#include <vccrypt/hash.h>
#include <vpr/abstract_factory.h>
#include <vpr/allocator.h>
#include <vpr/parameters.h>

#include "ref/curve25519.h"

/* forward decls */
static int vccrypt_ed25519_init(
    void* options, void* context);
static void vccrypt_ed25519_dispose(void* options, void* context);
static int vccrypt_ed25519_options_init(
    void* options, allocator_options_t* alloc_opts);
static void vccrypt_ed25519_options_dispose(void* disp);
static int vccrypt_ed25519_sign(
    void* context, vccrypt_buffer_t* sign_buffer,
    const vccrypt_buffer_t* priv, const uint8_t* data, size_t size);
static int vccrypt_ed25519_verify(
    void* context, const vccrypt_buffer_t* signature,
    const vccrypt_buffer_t* pub, const uint8_t* message, size_t size);
static int vccrypt_ed25519_keypair_create(
    void* context, vccrypt_buffer_t* priv, vccrypt_buffer_t* pub);

/* static data for this instance */
static abstract_factory_registration_t ed25519_impl;
static vccrypt_digital_signature_options_t ed25519_options;
static bool ed25519_impl_registered = false;

/**
 * Register ed25519 for use by the crypto library.
 */
void vccrypt_digital_signature_register_ed25519()
{
    MODEL_ASSERT(!ed25519_impl_registered);

    /* only register once */
    if (ed25519_impl_registered)
    {
        return;
    }

    /* we need SHA-512 for ed25519 */
    vccrypt_hash_register_SHA_2_512();

    /* set up the options for ed25519 */
    ed25519_options.hdr.dispose = &vccrypt_ed25519_options_dispose;
    ed25519_options.alloc_opts = 0; /* allocator handled by init */
    ed25519_options.prng_opts = 0; /* prng options handled by init */
    ed25519_options.hash_algorithm = VCCRYPT_HASH_ALGORITHM_SHA_2_512;
    ed25519_options.signature_size =
        VCCRYPT_DIGITAL_SIGNATURE_ED25519_SIGNATURE_SIZE;
    ed25519_options.private_key_size =
        VCCRYPT_DIGITAL_SIGNATURE_ED25519_PRIVATE_KEY_SIZE;
    ed25519_options.public_key_size =
        VCCRYPT_DIGITAL_SIGNATURE_ED25519_PUBLIC_KEY_SIZE;
    ed25519_options.vccrypt_digital_signature_alg_init =
        &vccrypt_ed25519_init;
    ed25519_options.vccrypt_digital_signature_alg_dispose =
        &vccrypt_ed25519_dispose;
    ed25519_options.vccrypt_digital_signature_alg_sign =
        &vccrypt_ed25519_sign;
    ed25519_options.vccrypt_digital_signature_alg_verify =
        &vccrypt_ed25519_verify;
    ed25519_options.vccrypt_digital_signature_alg_keypair_create =
        &vccrypt_ed25519_keypair_create;
    ed25519_options.vccrypt_digital_signature_alg_options_init =
        &vccrypt_ed25519_options_init;

    /* set up this registration for the abstract factory. */
    ed25519_impl.interface =
        VCCRYPT_INTERFACE_SIGNATURE;
    ed25519_impl.implementation =
        VCCRYPT_DIGITAL_SIGNATURE_ALGORITHM_ED25519;
    ed25519_impl.implementation_features =
        VCCRYPT_DIGITAL_SIGNATURE_ALGORITHM_ED25519;
    ed25519_impl.factory = 0;
    ed25519_impl.context = &ed25519_options;

    /* register this instance. */
    abstract_factory_register(&ed25519_impl);

    /* only register once */
    ed25519_impl_registered = true;
}

/**
 * Algorithm-specific initialization for digital signatures.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_digital_signature_context_t
 *                  structure.
 *
 * \returns 0 on success and non-zero on error.
 */
static int vccrypt_ed25519_init(
    void* options, void* context)
{
    vccrypt_digital_signature_options_t* opts =
        (vccrypt_digital_signature_options_t*)options;
    vccrypt_digital_signature_context_t* ctx =
        (vccrypt_digital_signature_context_t*)context;

    /* initialize the hash options with SHA-512 */
    return vccrypt_hash_options_init(
        &ctx->hash_opts, opts->alloc_opts, opts->hash_algorithm);
}

/**
 * Algorithm-specific disposal for digital signatures.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_digital_signature_context_t
 *                  structure.
 */
static void vccrypt_ed25519_dispose(
    void* UNUSED(options), void* context)
{
    vccrypt_digital_signature_context_t* ctx =
        (vccrypt_digital_signature_context_t*)context;

    dispose((disposable_t*)&ctx->hash_opts);
}

/**
 * Sign a message, given a private key, a message, and a message length.
 *
 * \param context       An opaque pointer to the
 *                      vccrypt_digital_signature_context_t structure.
 * \param sign_buffer   The buffer to receive the signature.  Must be large
 *                      enough for the given digital signature algorithm.
 * \param priv          The private key to use for the signature.
 * \param message       The input message.
 * \param size          The size of the message in bytes.
 *
 * \returns 0 on success and 1 on failure.
 */
static int vccrypt_ed25519_sign(
    void* context, vccrypt_buffer_t* sign_buffer,
    const vccrypt_buffer_t* priv, const uint8_t* data,
    size_t size)
{
    vccrypt_digital_signature_context_t* ctx =
        (vccrypt_digital_signature_context_t*)context;

    return ED25519_sign((uint8_t*)sign_buffer->data, data, size,
        (const uint8_t*)priv->data, &ctx->hash_opts);
}

/**
 * Verify a message, given a public key, a message, and a message length.
 *
 * \param context       An opaque pointer to the
 *                      vccrypt_digital_signature_context_t structure.
 * \param signature     The signature to verify.
 * \param pub           The public key to use for signature verification.
 * \param message       The input message.
 * \param size          The size of the message in bytes.
 *
 * \returns 0 if the message signature is valid, and no-zero on error.
 */
static int vccrypt_ed25519_verify(
    void* context, const vccrypt_buffer_t* signature,
    const vccrypt_buffer_t* pub, const uint8_t* message,
    size_t size)
{
    vccrypt_digital_signature_context_t* ctx =
        (vccrypt_digital_signature_context_t*)context;

    return ED25519_verify(message, size, (const uint8_t*)signature->data,
        (const uint8_t*)pub->data, &ctx->hash_opts);
}

/**
 * Create a keypair.
 *
 * The output buffers must be large enough to accept the resultant keys.
 *
 * \param context       An opaque pointer to the
 *                      vccrypt_digital_signature_context_t structure.
 * \param priv          The output buffer to receive the private key.
 * \param pub           The output buffer to receive the public key.
 */
static int vccrypt_ed25519_keypair_create(
    void* context, vccrypt_buffer_t* priv, vccrypt_buffer_t* pub)
{
    vccrypt_digital_signature_context_t* ctx =
        (vccrypt_digital_signature_context_t*)context;
    int retval = VCCRYPT_STATUS_SUCCESS;

    /* create a PRNG context for use by the keypair algorithm. */
    vccrypt_prng_context_t prng_ctx;
    retval = vccrypt_prng_init(ctx->options->prng_opts, &prng_ctx);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        return retval;
    }

    /* generate the keypair */
    retval =
        ED25519_keypair(
            (uint8_t*)pub->data, (uint8_t*)priv->data, &prng_ctx,
            &ctx->hash_opts);

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
static int vccrypt_ed25519_options_init(
    void* UNUSED(options), allocator_options_t* UNUSED(alloc_opts))
{
    /* do nothing. */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure.
 *
 * \param disp      the options structure to dispose.
 */
static void vccrypt_ed25519_options_dispose(void* disp)
{
    MODEL_ASSERT(disp != NULL);

    memset(disp, 0, sizeof(vccrypt_digital_signature_options_t));
}
