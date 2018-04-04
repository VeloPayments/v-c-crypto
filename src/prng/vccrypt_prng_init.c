/**
 * \file vccrypt_prng_init.c
 *
 * Initialize a PRNG instance.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/prng.h>
#include <vpr/parameters.h>

/* forward decls */
static void vccrypt_prng_dispose(void* context);

/**
 * \brief Initialize a prng instance with the given options.
 *
 * If initialization is successful, then this prng instance is owned by the
 * caller and must be disposed by calling dispose() when no longer needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The prng instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code indicating failure.
 */
int vccrypt_prng_init(
    vccrypt_prng_options_t* options, vccrypt_prng_context_t* context)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(options->vccrypt_prng_alg_init != NULL);
    MODEL_ASSERT(context != NULL);

    /* initialize context */
    context->hdr.dispose = &vccrypt_prng_dispose;
    context->options = options;

    /* perform algorithm-specific initialization. */
    return options->vccrypt_prng_alg_init(options, context);
}

/**
 * Dispose of a prng instance.
 */
static void vccrypt_prng_dispose(void* context)
{
    vccrypt_prng_context_t* ctx = (vccrypt_prng_context_t*)context;
    MODEL_ASSERT(ctx != NULL);
    MODEL_ASSERT(ctx->options != NULL);
    MODEL_ASSERT(ctx->options->vccrypt_prng_alg_dispose != NULL);

    /* call algorithm-specific disposal method */
    ctx->options->vccrypt_prng_alg_dispose(ctx->options, ctx);

    /* clear structure */
    memset(ctx, 0, sizeof(vccrypt_prng_context_t));
}
