/**
 * \file vccrypt_stream_init.c
 *
 * Generic initialization method for a stream cipher.
 *
 * \copyright 2018-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/stream_cipher.h>
#include <vpr/parameters.h>

/* forward decls. */
static void vccrypt_stream_dispose(void* disp);

/**
 * \brief Initialize a Stream Cipher algorithm instance with the given options
 * and key.
 *
 * Note that the key length must correspond to a length appropriate for the
 * Stream Cipher algorithm.
 *
 * If initialization is successful, then this Stream Cipher algorithm instance
 * is owned by the caller and must be disposed by calling dispose() when no
 * longer needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The stream cipher instance to initialize.
 * \param key           The key to use for this algorithm instance.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_STREAM_INIT_INVALID_ARG if one of the provided
 *             arguments is invalid.
 *      - a non-zero error code on failure.
 */
int vccrypt_stream_init(
    vccrypt_stream_options_t* options, vccrypt_stream_context_t* context,
    vccrypt_buffer_t* key)
{
    MODEL_ASSERT(NULL != options);
    MODEL_ASSERT(NULL != options->vccrypt_stream_alg_init);
    MODEL_ASSERT(NULL != context);
    MODEL_ASSERT(NULL != key);

    if (NULL == options || NULL == options->vccrypt_stream_alg_init
     || NULL == context || NULL == key)
    {
        return VCCRYPT_ERROR_STREAM_INIT_INVALID_ARG;
    }

    /* set the basics. */
    context->hdr.dispose = &vccrypt_stream_dispose;
    context->options = options;

    return options->vccrypt_stream_alg_init(options, context, key);
}

/**
 * \brief Dispose of a stream cipher instance.
 *
 * \param disp      The instance to dispose.
 */
static void vccrypt_stream_dispose(void* disp)
{
    vccrypt_stream_context_t* ctx = (vccrypt_stream_context_t*)disp;

    MODEL_ASSERT(NULL != ctx);
    MODEL_ASSERT(NULL != ctx->options);

    /* call the implementation-specific disposal method. */
    (*ctx->options->vccrypt_stream_alg_dispose)(ctx->options, ctx);

    /* clear the structure. */
    memset(ctx, 0, sizeof(vccrypt_stream_context_t));
}
