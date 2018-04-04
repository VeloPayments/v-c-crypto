/**
 * \file vccrypt_stream_start_decryption.c
 *
 * Generic decryption start method for a stream cipher.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vccrypt/stream_cipher.h>
#include <vpr/parameters.h>

/**
 * \brief Algorithm-specific start for the stream cipher decryption.  Reads IV
 * from input buffer.
 *
 * \param context   Pointer to stream cipher context.
 * \param input     The input buffer to read the IV from. Must be at least
 *                  IV_bytes in size.
 * \param offset    Pointer to the current offset of the buffer.  Will be
 *                  set to IV_bytes.  The value in this offset is ignored.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vccrypt_stream_start_decryption(
    vccrypt_stream_context_t* context, const void* input, size_t* offset)
{
    MODEL_ASSERT(NULL != context);
    MODEL_ASSERT(NULL != context->options);
    MODEL_ASSERT(NULL != input);
    MODEL_ASSERT(NULL != offset);

    return context->options->vccrypt_stream_alg_start_decryption(
        context->options, context, input, offset);
}
