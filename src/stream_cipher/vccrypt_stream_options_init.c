/**
 * \file vccrypt_stream_options_init.c
 *
 * Initialize a stream cipher options structure.
 *
 * \copyright 2018-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/stream_cipher.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * \brief Initialize Stream Cipher options, looking up an appropriate Stream
 * Cipher algorithm registered in the abstract factory.
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
 * \param algorithm     The Stream Cipher algorithm to use.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_STREAM_OPTIONS_INIT_MISSING_IMPL if the provided
 *             implementation selector is invalid or if the implementation has
 *             not been registered.
 *      - a non-zero error code on failure.
 */
int vccrypt_stream_options_init(
    vccrypt_stream_options_t* options, allocator_options_t* alloc_opts,
    uint32_t algorithm)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(alloc_opts != NULL);
    MODEL_ASSERT(algorithm != 0);

    abstract_factory_registration_t* reg = NULL;

    /* clear the options structure to start */
    memset(options, 0, sizeof(vccrypt_stream_options_t));

    /* attempt to find an applicable implementation. */
    reg = abstract_factory_find(VCCRYPT_INTERFACE_STREAM, algorithm);
    if (reg == NULL)
    {
        return VCCRYPT_ERROR_STREAM_OPTIONS_INIT_MISSING_IMPL;
    }

    /* the context structure is the options structure to copy. */
    memcpy(options, reg->context, sizeof(vccrypt_stream_options_t));

    /* set the allocator */
    options->alloc_opts = alloc_opts;

    /* verify that the disposer and options_init methods are set. */
    if (
        0 == options->hdr.dispose
     || 0 == options->vccrypt_stream_alg_options_init)
    {
        return VCCRYPT_ERROR_STREAM_OPTIONS_INIT_MISSING_IMPL;
    }

    /* call the implementation options init method. */
    return options->vccrypt_stream_alg_options_init(options, alloc_opts);
}
