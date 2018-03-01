/**
 * \file vccrypt_stream_decrypt.c
 *
 * Generic method for decrypting bytes using a started stream cipher instance.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vccrypt/stream_cipher.h>
#include <vpr/parameters.h>

/**
 * Decrypt data using the stream cipher.
 *
 * \param context       The stream cipher context for this operation.
 * \param input         A pointer to the ciphertext input to decrypt.
 * \param size          The size of the ciphertext input, in bytes.
 * \param output        The output buffer where plaintext data is written.
 *                      There must be at least *offset + size bytes
 *                      available in this buffer.
 * \param offset        A pointer to the current offset in the buffer.  Will
 *                      be incremented by size.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_stream_decrypt(
    vccrypt_stream_context_t* context, const void* input, size_t size,
    void* output, size_t* offset)
{
    MODEL_ASSERT(NULL != context);
    MODEL_ASSERT(NULL != context->options);
    MODEL_ASSERT(NULL != context->options->vccrypt_aes_ctr_alg_decrypt);
    MODEL_ASSERT(NULL != input);
    MODEL_ASSERT(0 < size);
    MODEL_ASSERT(NULL != output);
    MODEL_ASSERT(NULL != offset);

    return context->options->vccrypt_stream_alg_decrypt(
        context->options, context, input, size, output, offset);
}
