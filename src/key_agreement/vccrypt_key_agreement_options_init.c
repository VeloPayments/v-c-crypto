/**
 * \file vccrypt_key_agreement_options_init.c
 *
 * Initialize a key agreement options structure.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/key_agreement.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/* forward decls */
static void vccrypt_key_agreement_options_dispose(void* options);

/**
 * Initialize key agreement options, looking up an appropriate key agreement
 * algorithm registered in the abstract factory.  The options structure is owned
 * by the caller and must be disposed when no longer needed by calling
 * dispose().
 *
 * Note that the register method associated with the selected algorithm should
 * have been called during application or library initialization.  Otherwise,
 * the selected algorithm may not be linked to this executable.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options to use.
 * \param prng_opts     The PRNG to use for this algorithm.  MUST BE COMPATIBLE
 *                      WITH THIS ALGORITHM.
 * \param algorithm     The key agreement algorithm to use.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_key_agreement_options_init(
    vccrypt_key_agreement_options_t* options,
    allocator_options_t* alloc_opts, vccrypt_prng_options_t* prng_opts,
    uint32_t algorithm)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(alloc_opts != NULL);
    MODEL_ASSERT(prng_opts != NULL);
    MODEL_ASSERT(algorithm != 0);

    abstract_factory_registration_t* reg = NULL;

    /* clear the options structure to start */
    memset(options, 0, sizeof(vccrypt_key_agreement_options_t));

    /* attempt to find an applicable implementation. */
    reg = abstract_factory_find(VCCRYPT_INTERFACE_KEY, algorithm);
    if (reg == NULL)
    {
        return VCCRYPT_ERROR_KEY_AGREEMENT_OPTIONS_INIT_MISSING_IMPL;
    }

    /* the context structure is the options structure to copy. */
    memcpy(options, reg->context, sizeof(vccrypt_key_agreement_options_t));

    /* set the allocator. */
    options->alloc_opts = alloc_opts;

    /* set the prng. */
    options->prng_opts = prng_opts;

    /* set the disposer */
    options->hdr.dispose = &vccrypt_key_agreement_options_dispose;

    /* success */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure.
 *
 * \param options   the options structure to dispose.
 */
static void vccrypt_key_agreement_options_dispose(void* options)
{
    MODEL_ASSERT(options != NULL);

    memset(options, 0, sizeof(vccrypt_key_agreement_options_t));
}
