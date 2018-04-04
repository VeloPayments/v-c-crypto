/**
 * \file vccrypt_prng_options_init.c
 *
 * Initialize PRNG options for a cryptographic PRNG source.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/prng.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/* forward decls */
static void vccrypt_prng_options_dispose(void* options);

/**
 * \brief Initialize PRNG options, looking up an appropriate source registered
 * in the abstract factory.
 *
 * The options structure is owned by the caller and must be disposed when no
 * longer needed by calling dispose().
 *
 * Note that the register method associated with the selected source should have
 * been called during application or library initialization.  Otherwise, the
 * the selected source may not be linked to this executable.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options to use.
 * \param source        The PRNG source to use.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_PRNG_OPTIONS_INIT_MISSING_IMPL if the provided
 *             CPRNG source selector is either invalid or unregistered.
 *      - a non-zero error code indicating failure.
 */
int vccrypt_prng_options_init(
    vccrypt_prng_options_t* options, allocator_options_t* alloc_opts,
    uint32_t source)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(alloc_opts != NULL);
    MODEL_ASSERT(source != 0);

    abstract_factory_registration_t* reg = NULL;

    /* clear the options structure to start */
    memset(options, 0, sizeof(vccrypt_prng_options_t));

    /* attempt to find an applicable implementation. */
    reg = abstract_factory_find(VCCRYPT_INTERFACE_PRNG, source);
    if (reg == NULL)
    {
        return VCCRYPT_ERROR_PRNG_OPTIONS_INIT_MISSING_IMPL;
    }

    /* the context structure is the options structure to copy. */
    memcpy(options, reg->context, sizeof(vccrypt_prng_options_t));

    /* set the allocator. */
    options->alloc_opts = alloc_opts;

    /* set the disposer */
    options->hdr.dispose = &vccrypt_prng_options_dispose;

    /* success */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure.
 *
 * \param options   the options structure to dispose.
 */
static void vccrypt_prng_options_dispose(void* options)
{
    MODEL_ASSERT(options != NULL);

    memset(options, 0, sizeof(vccrypt_prng_options_t));
}
