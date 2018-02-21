/**
 * \file vccrypt_aes_ctr_alg_encrypt.c
 *
 * Encrypt data using the given AES CTR mode stream.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vpr/parameters.h>

#include "stream_cipher_private.h"

/**
 * Encrypt data using the stream cipher.
 *
 * \param options       Opaque pointer to this options structure.
 * \param context       An opaque pointer to the vccrypt_stream_context_t
 *                      structure.
 * \param input         A pointer to the plaintext input to encrypt.
 * \param size          The size of the plaintext input, in bytes.
 * \param output        The output buffer where data is written.  There must
 *                      be at least *offset + size bytes available in this
 *                      buffer.
 * \param offset        A pointer to the current offset in the buffer.  Will
 *                      be incremented by size.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_aes_ctr_alg_encrypt(
    void* UNUSED(options), void* context, const void* input,
    size_t size, void* output, size_t* offset)
{
    vccrypt_stream_context_t* ctx = (vccrypt_stream_context_t*)context;
    aes_ctr_context_data_t* ctx_data =
        (aes_ctr_context_data_t*)ctx->stream_state;

    const uint8_t* in = (const uint8_t*)input;
    uint8_t* out = (uint8_t*)output;
    out += *offset;

    while (size--)
    {
        /* generate more stream bytes if needed */
        if (ctx_data->count >= 16)
        {
            ctx_data->count = 0;
            vccrypt_aes_ctr_incr(ctx_data->ctr);
            AES_encrypt(ctx_data->ctr, ctx_data->stream, &ctx_data->key);
        }

        /* encrypt a byte and update the output offset */
        *(out++) = *(in++) ^ ctx_data->stream[ctx_data->count++];
        ++(*offset);
    }

    return 0;
}
