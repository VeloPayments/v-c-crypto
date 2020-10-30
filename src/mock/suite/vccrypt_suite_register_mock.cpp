/**
 * \file vccrypt_suite_register_mock.cpp
 *
 * Register the mock crypto suite used by Velo and force a link dependency so
 * that all required algorithms and primitives can be used at runtime.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/mock_suite.h>
#include <vpr/abstract_factory.h>
#include <vpr/allocator.h>
#include <vpr/parameters.h>

/* forward decls */
static int velo_mock_hash_init(
    void* options, vccrypt_hash_context_t* context);
static int velo_mock_digital_signature_init(
    void* options, vccrypt_digital_signature_context_t* context);
static int velo_mock_prng_init(
    void* options, vccrypt_prng_context_t* context);
static int velo_mock_mac_init(
    void* options, vccrypt_mac_context_t* context, vccrypt_buffer_t* key);
static int velo_mock_mac_short_init(
    void* options, vccrypt_mac_context_t* context, vccrypt_buffer_t* key);
static int velo_mock_key_auth_init(
    void* options, vccrypt_key_agreement_context_t* context);
static int velo_mock_key_cipher_init(
    void* options, vccrypt_key_agreement_context_t* context);
static int velo_mock_key_derivation_init(
    vccrypt_key_derivation_context_t* context,
    vccrypt_suite_options_t* options);
static int velo_mock_block_cipher_init(
    void* options, vccrypt_block_context_t* context,
    vccrypt_buffer_t* key, bool encrypt);
static int velo_mock_stream_cipher_init(
    void* options, vccrypt_stream_context_t* context,
    vccrypt_buffer_t* key);
static int velo_mock_suite_options_init(
    void* options, allocator_options_t* alloc_opts);
static void velo_mock_suite_options_dispose(
    void* disp);

/* static data for this instance */
static abstract_factory_registration_t velo_mock_impl;
static vccrypt_suite_options_t velo_mock_options;
static bool velo_mock_impl_registered = false;

/**
 * Register the Velo mock crypto suite.
 */
void vccrypt_suite_register_mock()
{
    MODEL_ASSERT(!velo_mock_impl_registered);

    /* only register once */
    if (velo_mock_impl_registered)
    {
        return;
    }

    /* register all requisite algorithms and sources */
    /* TODO - fill out with all mocks. */
    vccrypt_hash_register_mock();
    vccrypt_prng_register_source_mock();
    vccrypt_mac_register_mock();
    vccrypt_mac_register_short_mock();
    vccrypt_digital_signature_register_mock();
    vccrypt_prng_register_source_operating_system();
    vccrypt_key_agreement_register_mock_auth();
    vccrypt_key_agreement_register_mock_cipher();
    vccrypt_key_derivation_register_mock();
    vccrypt_block_register_mock();
    vccrypt_stream_register_mock();

    /* clear the options structure. */
    memset(&velo_mock_options, 0, sizeof(velo_mock_options));

    /* set up the options for velo V1 */
    velo_mock_options.hdr.dispose = 0; /* disposal handled by init */
    velo_mock_options.alloc_opts = 0; /* allocator handled by init */
    velo_mock_options.suite_id = VCCRYPT_SUITE_MOCK;
    velo_mock_options.hash_alg = VCCRYPT_HASH_ALGORITHM_MOCK;
    velo_mock_options.sign_alg = VCCRYPT_DIGITAL_SIGNATURE_MOCK;
    velo_mock_options.prng_src = VCCRYPT_PRNG_SOURCE_MOCK;
    velo_mock_options.mac_alg = VCCRYPT_MAC_ALGORITHM_MOCK;
    velo_mock_options.mac_short_alg = VCCRYPT_MAC_ALGORITHM_SHORT_MOCK;
    velo_mock_options.key_auth_alg =
        VCCRYPT_KEY_AGREEMENT_ALGORITHM_MOCK_AUTH;
    velo_mock_options.key_cipher_alg =
        VCCRYPT_KEY_AGREEMENT_ALGORITHM_MOCK_CIPHER;
    velo_mock_options.key_derivation_alg =
        VCCRYPT_KEY_DERIVATION_ALGORITHM_MOCK;
    velo_mock_options.key_derivation_hmac_alg =
        VCCRYPT_MAC_ALGORITHM_SHORT_MOCK;
    velo_mock_options.block_cipher_alg =
        VCCRYPT_BLOCK_ALGORITHM_MOCK;
    velo_mock_options.stream_cipher_alg =
        VCCRYPT_STREAM_ALGORITHM_MOCK;

    velo_mock_options.vccrypt_suite_hash_alg_init =
        &velo_mock_hash_init;
    velo_mock_options.vccrypt_suite_digital_signature_alg_init =
        &velo_mock_digital_signature_init;
    velo_mock_options.vccrypt_suite_prng_alg_init =
        &velo_mock_prng_init;
    velo_mock_options.vccrypt_suite_mac_alg_init =
        &velo_mock_mac_init;
    velo_mock_options.vccrypt_suite_mac_short_alg_init =
        &velo_mock_mac_short_init;
    velo_mock_options.vccrypt_suite_key_auth_init =
        &velo_mock_key_auth_init;
    velo_mock_options.vccrypt_suite_key_cipher_init =
        &velo_mock_key_cipher_init;
    velo_mock_options.vccrypt_suite_key_derivation_alg_init =
        &velo_mock_key_derivation_init;
    velo_mock_options.vccrypt_suite_block_alg_init =
        &velo_mock_block_cipher_init;
    velo_mock_options.vccrypt_suite_stream_alg_init =
        &velo_mock_stream_cipher_init;
    velo_mock_options.vccrypt_suite_alg_options_init =
        &velo_mock_suite_options_init;
    velo_mock_options.vccrypt_suite_alg_options_dispose =
        &velo_mock_suite_options_dispose;

    /* set up this registration for the abstract factory. */
    velo_mock_impl.interface =
        VCCRYPT_INTERFACE_SUITE;
    velo_mock_impl.implementation =
        VCCRYPT_SUITE_MOCK;
    velo_mock_impl.implementation_features =
        VCCRYPT_SUITE_MOCK;
    velo_mock_impl.factory = 0;
    velo_mock_impl.context = &velo_mock_options;

    /* register this instance. */
    abstract_factory_register(&velo_mock_impl);

    /* only register once */
    velo_mock_impl_registered = true;
}

/**
 * Suite-specific initialization for a hash algorithm instance.
 *
 * \param options       Opaque pointer to the suite options.
 * \param context       Hash algorithm context to initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int velo_mock_hash_init(
    void* options, vccrypt_hash_context_t* context)
{
    vccrypt_suite_options_t* opts = (vccrypt_suite_options_t*)options;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(context != NULL);

    return vccrypt_hash_init(&opts->hash_opts, context);
}

/**
 * Suite-specific initialization for a digital signature algorithm instance.
 *
 * \param options       Opaque pointer to the suite options.
 * \param context       The digital signature instance to initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int velo_mock_digital_signature_init(
    void* options, vccrypt_digital_signature_context_t* context)
{
    vccrypt_suite_options_t* opts = (vccrypt_suite_options_t*)options;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(context != NULL);

    return vccrypt_digital_signature_init(&opts->sign_opts, context);
}

/**
 * Suite-specific initialization for a PRNG source.
 *
 * \param options       Opaque pointer to the suite options.
 * \param context       The PRNG context to initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int velo_mock_prng_init(
    void* options, vccrypt_prng_context_t* context)
{
    vccrypt_suite_options_t* opts = (vccrypt_suite_options_t*)options;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(context != NULL);

    return vccrypt_prng_init(&opts->prng_opts, context);
}

/**
 * Suite-specific initialization for a message authentication code algorithm
 * instance.
 *
 * \param options       Opaque pointer to the suite options.
 * \param context       The message authentication code instance to
 *                      initialize.
 * \param key           The key to use for this algorithm.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int velo_mock_mac_init(
    void* options, vccrypt_mac_context_t* context, vccrypt_buffer_t* key)
{
    vccrypt_suite_options_t* opts = (vccrypt_suite_options_t*)options;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(key != NULL);

    return vccrypt_mac_init(&opts->mac_opts, context, key);
}

/**
 * Suite-specific initialization for a short message authentication code
 * algorithm instance.
 *
 * \param options       Opaque pointer to the suite options.
 * \param context       The message authentication code instance to
 *                      initialize.
 * \param key           The key to use for this algorithm.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int velo_mock_mac_short_init(
    void* options, vccrypt_mac_context_t* context, vccrypt_buffer_t* key)
{
    vccrypt_suite_options_t* opts = (vccrypt_suite_options_t*)options;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(key != NULL);

    return vccrypt_mac_init(&opts->mac_short_opts, context, key);
}

/**
 * Suite-specific initialization for a key agreement algorithm instance to
 * be used for authentication purposes.
 *
 * \param options       Opaque pointer to the suite options.
 * \param context       The key agreement algorithm instance to initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int velo_mock_key_auth_init(
    void* options, vccrypt_key_agreement_context_t* context)
{
    vccrypt_suite_options_t* opts = (vccrypt_suite_options_t*)options;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(context != NULL);

    return vccrypt_key_agreement_init(&opts->key_auth_opts, context);
}

/**
 * Suite-specific initialization for a key agreement algorithm instance to
 * be used for creating shared secrets for symmetric ciphers.
 *
 * \param options       Opaque pointer to the suite options.
 * \param context       The key agreement algorithm instance to initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int velo_mock_key_cipher_init(
    void* options, vccrypt_key_agreement_context_t* context)
{
    vccrypt_suite_options_t* opts = (vccrypt_suite_options_t*)options;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(context != NULL);

    return vccrypt_key_agreement_init(&opts->key_cipher_opts, context);
}

/**
 * Suite-specific initialization for a key derivation algorithm instance to
 * be used for creating cryptographic keys from passwords or passphrases.
 *
 * \param context       The key derivation algorithm instance to initialize.
 * \param options       Pointer to the suite options.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int velo_mock_key_derivation_init(
    vccrypt_key_derivation_context_t* context,
    vccrypt_suite_options_t* options)
{
    return vccrypt_key_derivation_init(context, &options->key_derivation_opts);
}

/**
 * Suite-specific initialization for a stream cipher algorithm instance
 *
 * \param options       Opaque pointer to the suite options.
 * \param context       The stream cipher algorithm instance to initialize.
 * \param key           The key to use for this algorithm.
 * \param encrypt       Set to true if this is for encryption, and false for
 *                      decryption.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int velo_mock_block_cipher_init(
    void* options, vccrypt_block_context_t* context, vccrypt_buffer_t* key,
    bool encrypt)
{
    vccrypt_suite_options_t* opts = (vccrypt_suite_options_t*)options;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(key != NULL);

    return vccrypt_block_init(&opts->block_cipher_opts, context, key, encrypt);
}

/**
 * Suite-specific initialization for a stream cipher algorithm instance
 *
 * \param options       Opaque pointer to the suite options.
 * \param context       The stream cipher algorithm instance to initialize.
 * \param key           The key to use for this algorithm.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int velo_mock_stream_cipher_init(
    void* options, vccrypt_stream_context_t* context, vccrypt_buffer_t* key)
{
    vccrypt_suite_options_t* opts = (vccrypt_suite_options_t*)options;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(key != NULL);

    return vccrypt_stream_init(&opts->stream_cipher_opts, context, key);
}

/**
 * \brief Implementation specific options init method.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options structure for this method.
 *
 * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
 */
static int velo_mock_suite_options_init(
    void* UNUSED(options), allocator_options_t* UNUSED(alloc_opts))
{
    /* do nothing. */

    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * \brief Implementation specific options dispose method.
 *
 * \param disp          The options structure to dispose.
 */
static void velo_mock_suite_options_dispose(void* UNUSED(disp))
{
    /* do nothing. */
}
