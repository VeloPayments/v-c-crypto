/**
 * \file vccrypt_key_derivation_init.c
 *
 * Initialize a key derivation instance from an options structure.
 *
 * \copyright 2019 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/key_derivation.h>
#include <vpr/parameters.h>

/* forward decls */
static void vccrypt_key_derivation_dispose(void* context);

/**
 * \brief Initialize a key derivation algorithm instance with the given options.
 *
 * If initialization is successful, then this key derivation algorithm
 * instance is owned by the caller and must be disposed by calling dispose()
 * when no longer needed.
 *
 * \param context       The key derivation algorithm instance to initialize.
 * \param options       The options to use for this algorithm instance.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_KEY_DERIVATION_INIT_INVALID_ARG if one of the
 *             provided arguments is invalid.
 *      - a non-zero error code indicating failure.
 */
int vccrypt_key_derivation_init(
    vccrypt_key_derivation_context_t* context,
    vccrypt_key_derivation_options_t* options)
{
    MODEL_ASSERT(NULL != options);
    MODEL_ASSERT(NULL != options->vccrypt_key_derivation_alg_init);
    MODEL_ASSERT(NULL != options->vccrypt_key_derivation_alg_dispose);
    MODEL_ASSERT(NULL != context);

    if (NULL == options || NULL == options->vccrypt_key_derivation_alg_init ||
        NULL == options->vccrypt_key_derivation_alg_dispose ||
        NULL == context)
    {
        return VCCRYPT_ERROR_KEY_DERIVATION_INIT_INVALID_ARG;
    }

    memset(context, 0, sizeof(vccrypt_key_derivation_context_t));
    context->hdr.dispose = &vccrypt_key_derivation_dispose;
    context->options = options;

    return options->vccrypt_key_derivation_alg_init(context, options);
}


/**
 * Dispose of a key derivation instance.
 *
 * \param context           The opaque pointer to this instance.
 */
static void vccrypt_key_derivation_dispose(void* context)
{
    vccrypt_key_derivation_context_t* ctx =
        (vccrypt_key_derivation_context_t*)context;

    MODEL_ASSERT(NULL != ctx);
    MODEL_ASSERT(NULL != ctx->options);
    MODEL_ASSERT(NULL != ctx->options->vccrypt_key_derivation_alg_dispose);

    /* perform the algorithm-specific disposal */
    ctx->options->vccrypt_key_derivation_alg_dispose(ctx, ctx->options);

    /* clear out the structure */
    memset(ctx, 0, sizeof(vccrypt_key_derivation_context_t));
}
