/**
 * \file mock/digital_signature/vccrypt_digital_signature_register_mock.cpp
 *
 * \brief Register mock digital signature algorithm and force a link dependency
 * so that this algorithm can be used at runtime.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/digital_signature.h>
#include <vccrypt/hash.h>
#include <vccrypt/mock/digital_signature.h>
#include <vccrypt/mock/hash.h>
#include <vpr/abstract_factory.h>
#include <vpr/allocator.h>
#include <vpr/parameters.h>

/* forward decls */
static int vccrypt_digital_signature_mock_init(
    void* options, void* context);
static void vccrypt_digital_signature_mock_dispose(
    void* options, void* context);
static int vccrypt_digital_signature_mock_options_init(
    void* options, allocator_options_t* alloc_opts);
static void vccrypt_digital_signature_mock_options_dispose(void* disp);
static int vccrypt_digital_signature_mock_sign(
    void* context, vccrypt_buffer_t* sign_buffer,
    const vccrypt_buffer_t* priv, const uint8_t* data, size_t size);
static int vccrypt_digital_signature_mock_verify(
    void* context, const vccrypt_buffer_t* signature,
    const vccrypt_buffer_t* pub, const uint8_t* message, size_t size);
static int vccrypt_digital_signature_mock_keypair_create(
    void* context, vccrypt_buffer_t* priv, vccrypt_buffer_t* pub);

/* static data for this instance */
static abstract_factory_registration_t digital_signature_mock_impl;
static vccrypt_digital_signature_options_t digital_signature_mock_options;
static bool digital_signature_mock_impl_registered = false;

/**
 * Register digital_signature_mock for use by the crypto library.
 */
void vccrypt_digital_signature_register_mock()
{
    MODEL_ASSERT(!digital_signature_mock_impl_registered);

    /* only register once */
    if (digital_signature_mock_impl_registered)
    {
        return;
    }

    /* we need mock hash for mock digital signature. */
    vccrypt_hash_register_mock();

    /* set up the options for digital_signature_mock */
    digital_signature_mock_options.hdr.dispose =
        &vccrypt_digital_signature_mock_options_dispose;
    digital_signature_mock_options.alloc_opts =
        0; /* allocator handled by init */
    digital_signature_mock_options.prng_opts =
        0; /* prng options handled by init */
    digital_signature_mock_options.hash_algorithm =
        VCCRYPT_HASH_ALGORITHM_MOCK;
    digital_signature_mock_options.signature_size =
        VCCRYPT_DIGITAL_SIGNATURE_ED25519_SIGNATURE_SIZE;
    digital_signature_mock_options.private_key_size =
        VCCRYPT_DIGITAL_SIGNATURE_ED25519_PRIVATE_KEY_SIZE;
    digital_signature_mock_options.public_key_size =
        VCCRYPT_DIGITAL_SIGNATURE_ED25519_PUBLIC_KEY_SIZE;
    digital_signature_mock_options.vccrypt_digital_signature_alg_init =
        &vccrypt_digital_signature_mock_init;
    digital_signature_mock_options.vccrypt_digital_signature_alg_dispose =
        &vccrypt_digital_signature_mock_dispose;
    digital_signature_mock_options.vccrypt_digital_signature_alg_sign =
        &vccrypt_digital_signature_mock_sign;
    digital_signature_mock_options.vccrypt_digital_signature_alg_verify =
        &vccrypt_digital_signature_mock_verify;
    digital_signature_mock_options
        .vccrypt_digital_signature_alg_keypair_create =
            &vccrypt_digital_signature_mock_keypair_create;
    digital_signature_mock_options.vccrypt_digital_signature_alg_options_init =
        &vccrypt_digital_signature_mock_options_init;

    /* set up this registration for the abstract factory. */
    digital_signature_mock_impl.interface =
        VCCRYPT_INTERFACE_SIGNATURE;
    digital_signature_mock_impl.implementation =
        VCCRYPT_DIGITAL_SIGNATURE_MOCK;
    digital_signature_mock_impl.implementation_features =
        VCCRYPT_DIGITAL_SIGNATURE_MOCK;
    digital_signature_mock_impl.factory = 0;
    digital_signature_mock_impl.context = &digital_signature_mock_options;

    /* register this instance. */
    abstract_factory_register(&digital_signature_mock_impl);

    /* only register once */
    digital_signature_mock_impl_registered = true;
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
static int vccrypt_digital_signature_mock_init(
    void* options, void* context)
{
    vccrypt_digital_signature_options_t* sign_opts =
        (vccrypt_digital_signature_options_t*)options;
    vccrypt_digital_signature_context_t* sign =
        (vccrypt_digital_signature_context_t*)context;

    digital_signature_mock* mock =
        (digital_signature_mock*)sign_opts->options_context;

    if (!mock->digital_signature_init_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->digital_signature_init_mock)(sign_opts, sign);
    }
}

/**
 * Algorithm-specific disposal for digital signatures.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_digital_signature_context_t
 *                  structure.
 */
static void vccrypt_digital_signature_mock_dispose(
    void* options, void* context)
{
    vccrypt_digital_signature_options_t* sign_opts =
        (vccrypt_digital_signature_options_t*)options;
    vccrypt_digital_signature_context_t* sign =
        (vccrypt_digital_signature_context_t*)context;

    digital_signature_mock* mock =
        (digital_signature_mock*)sign_opts->options_context;

    if (!!mock->digital_signature_dispose_mock)
    {
        (*mock->digital_signature_dispose_mock)(sign_opts, sign);
    }
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
static int vccrypt_digital_signature_mock_sign(
    void* context, vccrypt_buffer_t* sign_buffer,
    const vccrypt_buffer_t* priv, const uint8_t* data,
    size_t size)
{
    vccrypt_digital_signature_context_t* sign =
        (vccrypt_digital_signature_context_t*)context;
    vccrypt_digital_signature_options_t* sign_opts =
        sign->options;

    digital_signature_mock* mock =
        (digital_signature_mock*)sign_opts->options_context;

    if (!mock->digital_signature_sign_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return
            (*mock->digital_signature_sign_mock)(
                sign, sign_buffer, priv, data, size);
    }
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
static int vccrypt_digital_signature_mock_verify(
    void* context, const vccrypt_buffer_t* signature,
    const vccrypt_buffer_t* pub, const uint8_t* message,
    size_t size)
{
    vccrypt_digital_signature_context_t* sign =
        (vccrypt_digital_signature_context_t*)context;
    vccrypt_digital_signature_options_t* sign_opts =
        sign->options;

    digital_signature_mock* mock =
        (digital_signature_mock*)sign_opts->options_context;

    if (!mock->digital_signature_verify_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return
            (*mock->digital_signature_verify_mock)(
                sign, signature, pub, message, size);
    }
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
static int vccrypt_digital_signature_mock_keypair_create(
    void* context, vccrypt_buffer_t* priv, vccrypt_buffer_t* pub)
{
    vccrypt_digital_signature_context_t* sign =
        (vccrypt_digital_signature_context_t*)context;
    vccrypt_digital_signature_options_t* sign_opts =
        sign->options;

    digital_signature_mock* mock =
        (digital_signature_mock*)sign_opts->options_context;

    if (!mock->digital_signature_keypair_create_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->digital_signature_keypair_create_mock)(sign, priv, pub);
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
static int vccrypt_digital_signature_mock_options_init(
    void* options, allocator_options_t* UNUSED(alloc_opts))
{
    vccrypt_digital_signature_options_t* sign_opts =
        (vccrypt_digital_signature_options_t*)options;

    sign_opts->options_context = new digital_signature_mock;

    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure.
 *
 * \param disp      the options structure to dispose.
 */
static void vccrypt_digital_signature_mock_options_dispose(void* disp)
{
    vccrypt_digital_signature_options_t* sign_opts =
        (vccrypt_digital_signature_options_t*)disp;
    MODEL_ASSERT(sign_opts != NULL);

    digital_signature_mock* mock =
        (digital_signature_mock*)sign_opts->options_context;
    delete mock;

    memset(sign_opts, 0, sizeof(vccrypt_digital_signature_options_t));
}
