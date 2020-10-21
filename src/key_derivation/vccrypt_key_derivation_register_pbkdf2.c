/**
 * \file vccrypt_key_derivation_register_pbkdf2.c
 *
 * Register pbkdf2 and force a link dependency so that this algorithm can be
 * used at runtime.
 *
 * \copyright 2019-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/hash.h>
#include <vccrypt/key_derivation.h>
#include <vccrypt/interfaces.h>
#include <vccrypt/mac.h>
#include <vpr/abstract_factory.h>
#include <vpr/allocator.h>
#include <vpr/parameters.h>

#include "pbkdf2/pbkdf2.h"

/* forward decls */
static int vccrypt_pbkdf2_init(
    vccrypt_key_derivation_context_t* context,
    vccrypt_key_derivation_options_t* options);
static void vccrypt_pbkdf2_dispose(
    vccrypt_key_derivation_context_t* context,
    vccrypt_key_derivation_options_t* options);
static int vccrypt_pbkdf2_options_init(
    void* options, allocator_options_t* alloc_opts);
static void vccrypt_pbkdf2_options_dispose(void* disp);
static int vccrypt_pbkdf2_derive_key(
    vccrypt_buffer_t* derived_key,
    vccrypt_key_derivation_context_t* context,
    const vccrypt_buffer_t* pass, const vccrypt_buffer_t* salt,
    unsigned int rounds);
static int hmac_prf(
    uint8_t* digest, size_t digest_len,
    vccrypt_key_derivation_options_t* options,
    const uint8_t* text, size_t text_len,
    const uint8_t* key, size_t key_len);


/* static data for this instance */
static abstract_factory_registration_t pbkdf2_impl;
static vccrypt_key_derivation_options_t pbkdf2_options;
static bool pbkdf2_impl_registered = false;

/**
 * Register PBKDF2 for use by the crypto library.
 */
void vccrypt_key_derivation_register_pbkdf2()
{
    MODEL_ASSERT(!pbkdf2_impl_registered);

    /* only register once */
    if (pbkdf2_impl_registered)
    {
        return;
    }

    /* register the HMACs for our pseudorandom function */
    vccrypt_mac_register_SHA_2_512_HMAC();
    vccrypt_mac_register_SHA_2_512_256_HMAC();

    /* clear the options structure. */
    memset(&pbkdf2_options, 0, sizeof(pbkdf2_options));

    /* set up the options for pbkdf2 */
    pbkdf2_options.hdr.dispose = &vccrypt_pbkdf2_options_dispose;
    pbkdf2_options.alloc_opts = 0; /* allocator handled by init */
    pbkdf2_options.hmac_algorithm = 0; /* HMAC algorithm handled by init */
    pbkdf2_options.hmac_digest_length = 0; /* HMAC algorithm handled by init */

    pbkdf2_options.vccrypt_key_derivation_alg_init = &vccrypt_pbkdf2_init;
    pbkdf2_options.vccrypt_key_derivation_alg_dispose = &vccrypt_pbkdf2_dispose;
    pbkdf2_options.vccrypt_key_derivation_alg_derive_key =
        &vccrypt_pbkdf2_derive_key;
    pbkdf2_options.vccrypt_key_derivation_alg_options_init =
        &vccrypt_pbkdf2_options_init;

    /* set up this registration for the abstract factory */
    pbkdf2_impl.interface = VCCRYPT_INTERFACE_KD;
    pbkdf2_impl.implementation = VCCRYPT_KEY_DERIVATION_ALGORITHM_PBKDF2;
    pbkdf2_impl.implementation_features =
        VCCRYPT_KEY_DERIVATION_ALGORITHM_PBKDF2;
    pbkdf2_impl.factory = 0;
    pbkdf2_impl.context = &pbkdf2_options;

    /* register this instance */
    abstract_factory_register(&pbkdf2_impl);

    pbkdf2_impl_registered = true;
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
static int vccrypt_pbkdf2_init(
    vccrypt_key_derivation_context_t* UNUSED(context),
    vccrypt_key_derivation_options_t* UNUSED(options))
{
    /* no special initialization needed */

    /* success */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Algorithm-specific disposal for key agreement.
 *
 * \param context   Pointer to the vccrypt_key_agreement_context_t
 *                  structure.
 * \param options   Pointer to this options structure.
 */
static void vccrypt_pbkdf2_dispose(
    vccrypt_key_derivation_context_t* UNUSED(context),
    vccrypt_key_derivation_options_t* UNUSED(options))
{
    /* no special cleanup needed */
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
static int vccrypt_pbkdf2_derive_key(
    vccrypt_buffer_t* derived_key,
    vccrypt_key_derivation_context_t* context,
    const vccrypt_buffer_t* pass, const vccrypt_buffer_t* salt,
    unsigned int rounds)
{
    pbkdf2_prf_t prf = &hmac_prf;

    vccrypt_key_derivation_context_t* ctx =
        (vccrypt_key_derivation_context_t*)context;

    return pkcs5_pbkdf2(
        derived_key->data, derived_key->size, ctx->options, prf,
        pass->data, pass->size, salt->data, salt->size, rounds);
}

/**
 * \brief Use the configured HMAC function to produce a digest value from
 * a password/passphrase and a key.
 *
 * \param digest        An array to hold the output data
 * \param digest_len    The length of the digest produced by the PRF
 * \param options       Pointer to the options to use
 * \param text          The input data, e.g. a password
 * \param text_len      The length of the input data
 * \param key           The key
 * \param key_len       The length of the key
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code indicating failure.
 */
static int hmac_prf(uint8_t* digest, size_t digest_len,
    vccrypt_key_derivation_options_t* options,
    const uint8_t* text, size_t text_len,
    const uint8_t* key, size_t key_len)
{
    vccrypt_key_derivation_options_t* opts =
        (vccrypt_key_derivation_options_t*)options;

    // create mac options
    vccrypt_mac_options_t mac_options;
    int retval = vccrypt_mac_options_init(
        &mac_options, opts->alloc_opts, opts->hmac_algorithm);
    if (0 != retval)
    {
        goto done;
    }

    // create a key buffer
    vccrypt_buffer_t keybuf;
    retval = vccrypt_buffer_init(&keybuf, opts->alloc_opts, key_len);
    if (0 != retval)
    {
        goto cleanup_mac_options;
    }
    memcpy(keybuf.data, key, key_len);

    // initialize MAC
    vccrypt_mac_context_t mac_context;
    retval = vccrypt_mac_init(&mac_options, &mac_context, &keybuf);
    if (0 != retval)
    {
        goto cleanup_keybuf;
    }

    // digest
    retval = vccrypt_mac_digest(&mac_context, text, text_len);
    if (0 != retval)
    {
        goto cleanup_mac_context;
    }

    // create an output buffer
    vccrypt_buffer_t outbuf;
    retval = vccrypt_buffer_init(&outbuf, opts->alloc_opts, digest_len);
    if (0 != retval)
    {
        goto cleanup_mac_context;
    }

    // finalize
    retval = vccrypt_mac_finalize(&mac_context, &outbuf);
    if (0 != retval)
    {
        goto cleanup_outbuf;
    }
    memcpy(digest, outbuf.data, digest_len);

    retval = VCCRYPT_STATUS_SUCCESS;

    // cleanup
cleanup_outbuf:
    dispose((disposable_t*)&outbuf);

cleanup_mac_context:
    dispose((disposable_t*)&mac_context);

cleanup_keybuf:
    dispose((disposable_t*)&keybuf);

cleanup_mac_options:
    dispose((disposable_t*)&mac_options);

done:
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
static int vccrypt_pbkdf2_options_init(
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
static void vccrypt_pbkdf2_options_dispose(void* disp)
{
    MODEL_ASSERT(NULL != disp);

    memset(disp, 0, sizeof(vccrypt_key_derivation_options_t));
}
