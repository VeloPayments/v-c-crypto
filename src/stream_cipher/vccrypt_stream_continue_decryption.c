/**
 * \file vccrypt_stream_continue_decryption.c
 *
 * Generic decryption continue method for a stream cipher.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vccrypt/stream_cipher.h>
#include <vpr/parameters.h>

/**
 * \brief Algorithm-specific continuation for the stream cipher decryption.
 *
 * \param context       Opaque pointer to vccrypt_stream_context_t structure.
 * \param iv            The IV to use for this instance.  MUST ONLY BE USED ONCE
 * \param iv_size       The size of the IV in bytes.
 * \param input_offset  Current offset of the input buffer.
 *
 * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
 */
int vccrypt_stream_continue_decryption(
    vccrypt_stream_context_t* context, const void* iv, size_t iv_size,
    size_t input_offset)
{

    MODEL_ASSERT(NULL != context);
    MODEL_ASSERT(NULL != context->options);
    MODEL_ASSERT(NULL != context->options->vccrypt_stream_alg_continue_decryption);
    MODEL_ASSERT(NULL != iv);
    MODEL_ASSERT(0 < iv_size);
    MODEL_ASSERT(0 < input_offset);


    return context->options->vccrypt_stream_alg_continue_decryption(
        context->options, context, iv, iv_size, input_offset);
}
