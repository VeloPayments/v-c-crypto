/**
 * \file vccrypt_stream_start_encryption.c
 *
 * Generic encryption start method for a stream cipher.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vccrypt/stream_cipher.h>
#include <vpr/parameters.h>

/**
 * Algorithm-specific start for the stream cipher encryption.  Initializes
 * output buffer with IV.
 *
 * \param context   Pointer to the stream cipher context.
 * \param iv        The IV to use for this instance.  MUST ONLY BE USED ONCE
 *                  PER KEY, EVER.
 * \param ivSize    The size of the IV in bytes.
 * \param output    The output buffer to initialize. Must be at least
 *                  IV_bytes in size.
 * \param offset    Pointer to the current offset of the buffer.  Will be
 *                  set to IV_bytes.  The value in this offset is ignored.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_stream_start_encryption(
    vccrypt_stream_context_t* context, const void* iv, size_t ivSize,
    void* output, size_t* offset)
{
    MODEL_ASSERT(NULL != context);
    MODEL_ASSERT(NULL != context->options);
    MODEL_ASSERT(NULL != context->options->vccrypt_stream_alg_start_encryption);
    MODEL_ASSERT(NULL != iv);
    MODEL_ASSERT(0 < ivSize);
    MODEL_ASSERT(NULL != output);
    MODEL_ASSERT(NULL != offset);

    return context->options->vccrypt_stream_alg_start_encryption(
        context->options, context, iv, ivSize, output, offset);
}
