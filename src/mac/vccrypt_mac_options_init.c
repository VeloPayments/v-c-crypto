/**
 * \file vccrypt_mac_options_init.c
 *
 * Initialize a mac options structure for a message authentication code
 * algorithm.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/mac.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * \brief Initialize MAC options, looking up an appropriate MAC algorithm
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
 * \param algorithm     The MAC algorithm to use.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_MAC_OPTIONS_INIT_MISSING_IMPL if the implementation
 *             is missing or was not registered. 
 *      - a non-zero return code on error.
 */
int vccrypt_mac_options_init(
    vccrypt_mac_options_t* options, allocator_options_t* alloc_opts,
    uint32_t algorithm)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(alloc_opts != NULL);
    MODEL_ASSERT(algorithm != 0);

    abstract_factory_registration_t* reg = NULL;

    /* clear the options structure to start */
    memset(options, 0, sizeof(vccrypt_mac_options_t));

    /* attempt to find an applicable implementation */
    reg = abstract_factory_find(VCCRYPT_INTERFACE_MAC, algorithm);
    if (reg == NULL)
    {
        return VCCRYPT_ERROR_MAC_OPTIONS_INIT_MISSING_IMPL;
    }

    /* the context structure is the options structure to copy. */
    memcpy(options, reg->context, sizeof(vccrypt_mac_options_t));

    /* set the allocator */
    options->alloc_opts = alloc_opts;

    /* verify that the disposer and options init methods are set. */
    if (
        0 == options->hdr.dispose
     || 0 == options->vccrypt_mac_alg_options_init)
    {
        return VCCRYPT_ERROR_MAC_OPTIONS_INIT_MISSING_IMPL;
    }
    
    /* call the implementation specific options init method. */
    return options->vccrypt_mac_alg_options_init(options, alloc_opts);
}

#if 0
/**
 * Dispose of the options structure.
 *
 * \param options   the options structure to dispose.
 */
static void vccrypt_mac_options_dispose(void* options)
{
    MODEL_ASSERT(options != NULL);

    memset(options, 0, sizeof(vccrypt_mac_options_t));
}
#endif
