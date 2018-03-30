/**
 * \file vccrypt_block_options_init.c
 *
 * Initialize a block cipher options structure.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/block_cipher.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/* forward decls */
static void vccrypt_block_options_dispose(void* options);

/**
 * Initialize Block Cipher options, looking up an appropriate Block Cipher
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
 * \param algorithm     The Block Cipher algorithm to use.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_block_options_init(
    vccrypt_block_options_t* options, allocator_options_t* alloc_opts,
    uint32_t algorithm)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(alloc_opts != NULL);
    MODEL_ASSERT(algorithm != 0);

    abstract_factory_registration_t* reg = NULL;

    /* clear the options structure to start. */
    memset(options, 0, sizeof(vccrypt_block_options_t));

    /* attempt to find an applicable implementation. */
    reg = abstract_factory_find(VCCRYPT_INTERFACE_BLOCK, algorithm);
    if (reg == NULL)
    {
        return VCCRYPT_ERROR_BLOCK_OPTIONS_INIT_MISSING_IMPL;
    }

    /* copy the context structure into our options structure. */
    memcpy(options, reg->context, sizeof(vccrypt_block_options_t));

    /* set the allocator */
    options->alloc_opts = alloc_opts;

    /* set the disposer */
    options->hdr.dispose = &vccrypt_block_options_dispose;

    /* success */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure.
 *
 * \param options   the options structure to dispose.
 */
static void vccrypt_block_options_dispose(void* options)
{
    MODEL_ASSERT(options != NULL);

    memset(options, 0, sizeof(vccrypt_block_options_t));
}
