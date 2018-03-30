/**
 * \file vccrypt_stream_init.c
 *
 * Generic initialization method for a stream cipher.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vccrypt/stream_cipher.h>
#include <vpr/parameters.h>

/**
 * Initialize a Stream Cipher algorithm instance with the given options and key.
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
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_stream_init(
    vccrypt_stream_options_t* options, vccrypt_stream_context_t* context,
    vccrypt_buffer_t* key)
{
    MODEL_ASSERT(NULL != options);
    MODEL_ASSERT(NULL != options->vccrypt_stream_alg_init);
    MODEL_ASSERT(NULL != context);
    MODEL_ASSERT(NULL != key);

    if (NULL == options || NULL == options->vccrypt_stream_alg_init || NULL == context || NULL == key)
    {
        return VCCRYPT_ERROR_STREAM_INIT_INVALID_ARG;
    }

    return options->vccrypt_stream_alg_init(options, context, key);
}
