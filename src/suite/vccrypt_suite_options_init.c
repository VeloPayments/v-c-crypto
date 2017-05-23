/**
 * \file vccrypt_suite_options_init.c
 *
 * Initialize a crypto suite options structure.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/suite.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/* forward decls */
static void vccrypt_suite_options_dispose(void* options);

/**
 * Initialize a crypto suite options structure.
 *
 * This method initializes a crypto suite options structure so that it can be
 * used to instantiate cryptographic primitives for a given crypto suite.
 *
 * Note that the crypto suite selected must be registered prior to use in order
 * to instruct the linker to link the correct algorithms to this application.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options to use for this suite.
 * \param suite_id      The suite identifier to use for initialization.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_options_init(
    vccrypt_suite_options_t* options, allocator_options_t* alloc_opts,
    uint32_t suite_id)
{
    int retval = 0;

    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(alloc_opts != NULL);
    MODEL_ASSERT(suite_id != 0);

    abstract_factory_registration_t* reg = NULL;

    /* clear the options structure to start */
    memset(options, 0, sizeof(vccrypt_suite_options_t));

    /* attempt to find an applicable suite. */
    reg = abstract_factory_find(VCCRYPT_INTERFACE_SUITE, suite_id);
    if (reg == NULL)
    {
        return 1;
    }

    /* the context structure is the options structure to copy. */
    memcpy(options, reg->context, sizeof(vccrypt_suite_options_t));

    /* set the allocator. */
    options->alloc_opts = alloc_opts;

    /* set the disposer */
    options->hdr.dispose = &vccrypt_suite_options_dispose;

    /* initialize the hash algorithm options. */
    if (0 !=
        vccrypt_hash_options_init(
            &options->hash_opts, alloc_opts, options->hash_alg))
    {
        return 2;
    }

    /* initialize the prng options */
    if (0 !=
        vccrypt_prng_options_init(
            &options->prng_opts, alloc_opts, options->prng_src))
    {
        retval = 3;
        goto cleanup_hash_options;
    }

    /* initialize the digital signature options. */
    if (0 !=
        vccrypt_digital_signature_options_init(
            &options->sign_opts, alloc_opts, &options->prng_opts,
            options->sign_alg))
    {
        retval = 4;
        goto cleanup_prng_options;
    }

    /* initialize the MAC options */
    if (0 != vccrypt_mac_options_init(&options->mac_opts, alloc_opts, options->mac_alg))
    {
        retval = 5;
        goto cleanup_digital_signature_options;
    }

    /* initialize the auth key agreement options */
    if (0 != vccrypt_key_agreement_options_init(&options->key_auth_opts, alloc_opts, &options->prng_opts, options->key_auth_alg))
    {
        retval = 6;
        goto cleanup_mac_options;
    }

    /* initialize the cipher key agreement options */
    if (0 != vccrypt_key_agreement_options_init(&options->key_cipher_opts, alloc_opts, &options->prng_opts, options->key_cipher_alg))
    {
        retval = 7;
        goto cleanup_auth_key_options;
    }

    /* success */
    return 0;

cleanup_auth_key_options:
    dispose((disposable_t*)&options->key_auth_opts);

cleanup_mac_options:
    dispose((disposable_t*)&options->mac_opts);

cleanup_digital_signature_options:
    dispose((disposable_t*)&options->sign_opts);

cleanup_prng_options:
    dispose((disposable_t*)&options->prng_opts);

cleanup_hash_options:
    dispose((disposable_t*)&options->hash_opts);

    return retval;
}

/**
 * Dispose of the options structure.
 *
 * \param options   the options structure to dispose.
 */
static void vccrypt_suite_options_dispose(void* options)
{
    vccrypt_suite_options_t* opts = (vccrypt_suite_options_t*)options;
    MODEL_ASSERT(opts != NULL);

    /* dispose of options structures */
    dispose((disposable_t*)&opts->key_auth_opts);
    dispose((disposable_t*)&opts->key_cipher_opts);
    dispose((disposable_t*)&opts->mac_opts);
    dispose((disposable_t*)&opts->sign_opts);
    dispose((disposable_t*)&opts->prng_opts);
    dispose((disposable_t*)&opts->hash_opts);

    /* clear out this structure */
    memset(opts, 0, sizeof(vccrypt_suite_options_t));
}
