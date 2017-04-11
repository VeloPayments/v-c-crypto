/**
 * \file vccrypt_digital_signature_init.c
 *
 * Initialize a digital signature instance from an options structure.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/digital_signature.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/* forward decls */
static void vccrypt_digital_signature_dispose(void* context);

/**
 * Initialize a digital signature instance with the given options.
 *
 * If initialization is successful, then this digital signature algorithm
 * instance is owned by the caller and must be disposed by calling dispose()
 * when no longer needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The digital signature instance to initialize.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_digital_signature_init(
    vccrypt_digital_signature_options_t* options,
    vccrypt_digital_signature_context_t* context)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(options->vccrypt_digital_signature_alg_init != NULL);
    MODEL_ASSERT(options->vccrypt_digital_signature_alg_dispose != NULL);
    MODEL_ASSERT(context != NULL);

    if (options == NULL || options->vccrypt_digital_signature_alg_init == NULL || options->vccrypt_digital_signature_alg_dispose == NULL || context == NULL)
    {
        return 1;
    }

    memset(context, 0, sizeof(vccrypt_digital_signature_context_t));
    context->hdr.dispose = &vccrypt_digital_signature_dispose;
    context->options = options;

    return options->vccrypt_digital_signature_alg_init(options, context);
}

/**
 * Dispose of a digital signature instance.
 *
 * \param context           The opaque pointer to this instance.
 */
static void vccrypt_digital_signature_dispose(void* context)
{
    vccrypt_digital_signature_context_t* ctx =
        (vccrypt_digital_signature_context_t*)context;

    MODEL_ASSERT(ctx != NULL);
    MODEL_ASSERT(ctx->options != NULL);
    MODEL_ASSERT(ctx->options->vccrypt_digital_signature_alg_dispose != NULL);

    /* perform the algorithm-specific disposal */
    ctx->options->vccrypt_digital_signature_alg_dispose(ctx->options, ctx);

    /* clear out the structure */
    memset(ctx, 0, sizeof(vccrypt_digital_signature_context_t));
}
