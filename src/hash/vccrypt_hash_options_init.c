/**
 * \file vccrypt_hash_options_init.c
 *
 * Initialize a hash options structure for a cryptographic hash algorithm.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/hash.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * \brief Initialize hash options, looking up an appropriate hash algorithm
 * registered in the abstract factory.
 *
 * The options structure is owned by the caller and must be disposed when no
 * longer needed by calling dispose().
 *
 * Note that the register method associated with the selected algorithm should
 * have been called during application or library initialization.  Otherwise,
 * the selected algorithm may not be linked to this executable.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options to use.
 * \param algorithm     The hash algorithm to use.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_HASH_OPTIONS_INIT_MISSING_IMPL if the requested
 *             implementation either does not exist or was not registered.
 *      - a non-zero error code on failure.
 */
int vccrypt_hash_options_init(
    vccrypt_hash_options_t* options, allocator_options_t* alloc_opts,
    uint32_t algorithm)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(alloc_opts != NULL);
    MODEL_ASSERT(algorithm != 0);

    abstract_factory_registration_t* reg = NULL;

    /* clear the options structure to start */
    memset(options, 0, sizeof(vccrypt_hash_options_t));

    /* attempt to find an applicable implementation. */
    reg = abstract_factory_find(VCCRYPT_INTERFACE_HASH, algorithm);
    if (reg == NULL)
    {
        return VCCRYPT_ERROR_HASH_OPTIONS_INIT_MISSING_IMPL;
    }

    /* the context structure is the options structure to copy. */
    memcpy(options, reg->context, sizeof(vccrypt_hash_options_t));

    /* set the allocator. */
    options->alloc_opts = alloc_opts;

    /* verify that the disposer and options init were set. */
    if (
        0 == options->hdr.dispose
     || 0 == options->vccrypt_hash_alg_options_init)
    {
        return VCCRYPT_ERROR_HASH_OPTIONS_INIT_MISSING_IMPL;
    }

    /* Finally, run the options init function. */
    return options->vccrypt_hash_alg_options_init(options, alloc_opts);
}
