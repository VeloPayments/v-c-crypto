/**
 * \file vccrypt_hash_init.c
 *
 * Initialize a hash context structure.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/hash.h>
#include <vpr/parameters.h>

/* forward decls */
static void vccrypt_hash_dispose(void* context);

/**
 * \brief Initialize a hash algorithm instance with the given options.
 *
 * If initialization is successful, then this hash algorithm instance is owned
 * by the caller and must be disposed by calling dispose() when no longer
 * needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The hash instance to initialize.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_HASH_INIT_INVALID_ARG if an invalid argument is
 *             provided.
 *      - a non-zero error code on failure.
 */
int vccrypt_hash_init(
    vccrypt_hash_options_t* options, vccrypt_hash_context_t* context)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(options->alloc_opts != NULL);
    MODEL_ASSERT(options->vccrypt_hash_alg_init != NULL);
    MODEL_ASSERT(context != NULL);

    /* sanity check on parameters */
    if (options == NULL || options->alloc_opts == NULL ||
        options->vccrypt_hash_alg_init == NULL || context == NULL)
    {
        return VCCRYPT_ERROR_HASH_INIT_INVALID_ARG;
    }

    /* set up the context structure. */
    memset(context, 0, sizeof(vccrypt_hash_context_t));
    context->options = options;

    /* call the algorithm specific initialization method */
    int ret = options->vccrypt_hash_alg_init(options, context);
    if (ret != 0)
    {
        /* failure.  Clean up and return error code to caller. */
        memset(context, 0, sizeof(vccrypt_hash_context_t));
        return ret;
    }

    /* set the dispose method for cleaning up this context */
    context->hdr.dispose = &vccrypt_hash_dispose;

    /* success */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the hash context structure.
 *
 * \param context   the hash context structure to dispose.
 */
static void vccrypt_hash_dispose(void* context)
{
    vccrypt_hash_context_t* ctx = (vccrypt_hash_context_t*)context;
    MODEL_ASSERT(ctx != NULL);
    MODEL_ASSERT(ctx->options != NULL);
    MODEL_ASSERT(ctx->options->vccrypt_hash_alg_dispose != NULL);

    /* dispose any algorithm-specific resources */
    ctx->options->vccrypt_hash_alg_dispose(ctx->options, ctx);

    /* clear out this structure */
    memset(ctx, 0, sizeof(vccrypt_hash_context_t));
}
