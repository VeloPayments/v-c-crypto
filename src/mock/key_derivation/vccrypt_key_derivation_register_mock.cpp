/**
 * \file vccrypt_key_derivation_register_mock.cpp
 *
 * Register the mock key derivation interface and force a link dependency so
 * that this algorithm can be used at runtime.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/hash.h>
#include <vccrypt/key_derivation.h>
#include <vccrypt/mock/key_derivation.h>
#include <vccrypt/interfaces.h>
#include <vccrypt/mac.h>
#include <vpr/abstract_factory.h>
#include <vpr/allocator.h>
#include <vpr/parameters.h>

/* forward decls */
static int vccrypt_derive_mock_init(
    vccrypt_key_derivation_context_t* context,
    vccrypt_key_derivation_options_t* options);
static void vccrypt_derive_mock_dispose(
    vccrypt_key_derivation_context_t* context,
    vccrypt_key_derivation_options_t* options);
static int vccrypt_derive_mock_options_init(
    void* options, allocator_options_t* alloc_opts);
static void vccrypt_derive_mock_options_dispose(void* disp);
static int vccrypt_derive_mock_derive_key(
    vccrypt_buffer_t* derived_key,
    vccrypt_key_derivation_context_t* context,
    const vccrypt_buffer_t* pass, const vccrypt_buffer_t* salt,
    unsigned int rounds);

/* static data for this instance */
static abstract_factory_registration_t derive_mock_impl;
static vccrypt_key_derivation_options_t derive_mock_options;
static bool derive_mock_impl_registered = false;

/**
 * \brief Register the mock key derivation algorithm.
 * 
 */
void vccrypt_key_derivation_register_mock()
{
    MODEL_ASSERT(!derive_mock_impl_registered);

    /* only register once */
    if (derive_mock_impl_registered)
    {
        return;
    }

    /* register the HMACs for our pseudorandom function */
    vccrypt_mac_register_SHA_2_512_HMAC();
    vccrypt_mac_register_SHA_2_512_256_HMAC();

    /* clear the options structure. */
    memset(&derive_mock_options, 0, sizeof(derive_mock_options));

    /* set up the options for derive_mock */
    derive_mock_options.hdr.dispose = &vccrypt_derive_mock_options_dispose;
    derive_mock_options.alloc_opts = 0; /* allocator handled by init */
    derive_mock_options.hmac_algorithm = 0; /* HMAC algorithm handled by init */
    derive_mock_options.hmac_digest_length = 
        0; /* HMAC algorithm handled by init */

    derive_mock_options.vccrypt_key_derivation_alg_init =
        &vccrypt_derive_mock_init;
    derive_mock_options.vccrypt_key_derivation_alg_dispose =
        &vccrypt_derive_mock_dispose;
    derive_mock_options.vccrypt_key_derivation_alg_derive_key =
        &vccrypt_derive_mock_derive_key;
    derive_mock_options.vccrypt_key_derivation_alg_options_init =
        &vccrypt_derive_mock_options_init;

    /* set up this registration for the abstract factory */
    derive_mock_impl.interface = VCCRYPT_INTERFACE_KD;
    derive_mock_impl.implementation = VCCRYPT_KEY_DERIVATION_ALGORITHM_MOCK;
    derive_mock_impl.implementation_features =
        VCCRYPT_KEY_DERIVATION_ALGORITHM_MOCK;
    derive_mock_impl.factory = 0;
    derive_mock_impl.context = &derive_mock_options;

    /* register this instance */
    abstract_factory_register(&derive_mock_impl);

    derive_mock_impl_registered = true;
}

/**
 * Algorithm-specific initialization for key derivation.
 *
 * \param context   Pointer to the vccrypt_key_derivation_context_t
 *                  structure.
 * \param options   Pointer to this options structure.
 *
 * \returns 0 on success and non-zero on error.
 */
static int vccrypt_derive_mock_init(
    vccrypt_key_derivation_context_t* context,
    vccrypt_key_derivation_options_t* options)
{
    key_derivation_mock* mock = (key_derivation_mock*)options->options_context;

    if (!mock->key_derivation_init_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->key_derivation_init_mock)(context, options);
    }
}

/**
 * Algorithm-specific disposal for key agreement.
 *
 * \param context   Pointer to the vccrypt_key_agreement_context_t
 *                  structure.
 * \param options   Pointer to this options structure.
 */
static void vccrypt_derive_mock_dispose(
    vccrypt_key_derivation_context_t* context,
    vccrypt_key_derivation_options_t* options)
{
    key_derivation_mock* mock = (key_derivation_mock*)options->options_context;

    if (!!mock->key_derivation_dispose_mock)
    {
        (*mock->key_derivation_dispose_mock)(context, options);
    }
}

/**
 * \brief Derive a cryptographic key
 *
 * \param derived_key       A crypto buffer to receive the derived key.
 *                          The buffer should be the size of the desired 
 *                          key length.
 * \param context           Pointer to the vccrypt_key_derivation_context_t
 *                          structure.
 * \param pass              A buffer containing a password or passphrase
 * \param salt              A buffer containing a salt value
 * \param rounds            The number of rounds to process.  More rounds
 *                          increases randomness and computational cost.
 *
 * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
 */
static int vccrypt_derive_mock_derive_key(
    vccrypt_buffer_t* derived_key,
    vccrypt_key_derivation_context_t* context,
    const vccrypt_buffer_t* pass, const vccrypt_buffer_t* salt,
    unsigned int rounds)
{
    vccrypt_key_derivation_options_t* options = context->options;
    key_derivation_mock* mock = (key_derivation_mock*)options->options_context;

    if (!mock->key_derivation_derive_key_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return
            (*mock->key_derivation_derive_key_mock)(
                derived_key, context, pass, salt, rounds);
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
static int vccrypt_derive_mock_options_init(
    void* options, allocator_options_t* UNUSED(alloc_opts))
{
    vccrypt_key_derivation_options_t* opts =
        (vccrypt_key_derivation_options_t*)options;

    opts->options_context = new key_derivation_mock;

    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure.
 *
 * \param options   the options structure to dispose.
 */
static void vccrypt_derive_mock_options_dispose(void* disp)
{
    vccrypt_key_derivation_options_t* opts =
        (vccrypt_key_derivation_options_t*)disp;
    MODEL_ASSERT(NULL != opts);

    key_derivation_mock* mock = (key_derivation_mock*)opts->options_context;
    delete mock;

    memset(opts, 0, sizeof(vccrypt_key_derivation_options_t));
}
