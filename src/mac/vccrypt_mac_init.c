/**
 * \file vccrypt_mac_init.c
 *
 * Initialize a mac context structure.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/mac.h>
#include <vpr/parameters.h>

/* forward decls */
static void vccrypt_mac_dispose(void* context);

/**
 * Initialize a MAC algorithm instance with the given options and key.
 *
 * Note that the key length must correspond to a length appropriate for the MAC
 * algorithm.  If the key length is not the correct length, an attempt will be
 * made to use the appropriate key expansion strategy if supported by the
 * algorithm.
 *
 * If initialization is successful, then this mac algorithm instance is owned by
 * the caller and must be disposed by calling dispose() when no longer needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The MAC instance to initialize.
 * \param key           The key to use for this algorithm instance.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_mac_init(
    vccrypt_mac_options_t* options, vccrypt_mac_context_t* context,
    vccrypt_buffer_t* key)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(options->alloc_opts != NULL);
    MODEL_ASSERT(options->vccrypt_mac_alg_init != NULL);
    MODEL_ASSERT(context != NULL);

    /* sanity check on parameters */
    if (options == NULL || options->alloc_opts == NULL ||
        options->vccrypt_mac_alg_init == NULL || context == NULL)
    {
        return 1;
    }

    /* set up the context structure */
    memset(context, 0, sizeof(vccrypt_mac_context_t));
    context->options = options;

    /* call the algorithm-specific initialization method */
    int ret = options->vccrypt_mac_alg_init(options, context, key);
    if (ret != 0)
    {
        /* failure.  Clean up and return error code to caller. */
        memset(context, 0, sizeof(vccrypt_mac_context_t));
        return ret;
    }

    /* set the dispose method for cleaning up this context */
    context->hdr.dispose = &vccrypt_mac_dispose;

    /* success */
    return 0;
}

/**
 * Dispose of the mac context structure.
 *
 * \param context   the mac context structure to dispose.
 */
static void vccrypt_mac_dispose(void* context)
{
    MODEL_ASSERT(context != NULL);

    memset(context, 0, sizeof(vccrypt_mac_context_t));
}
