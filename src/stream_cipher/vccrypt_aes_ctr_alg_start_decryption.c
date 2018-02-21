/**
 * \file vccrypt_aes_ctr_alg_start_decryption.c
 *
 * Start decryption for a given AES CTR mode stream cipher instance.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "stream_cipher_private.h"

/**
 * Algorithm-specific start for the stream cipher decryption.  Reads IV from
 * input buffer.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_stream_context_t structure.
 * \param input     The input buffer to read the IV from. Must be at least
 *                  IV_bytes in size.
 * \param offset    Pointer to the current offset of the buffer.  Will be
 *                  set to IV_bytes.  The value in this offset is ignored.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_aes_ctr_alg_start_decryption(
    void* UNUSED(options), void* context, const void* input,
    size_t* offset)
{
    vccrypt_stream_context_t* ctx = (vccrypt_stream_context_t*)context;
    aes_ctr_context_data_t* ctx_data =
        (aes_ctr_context_data_t*)ctx->stream_state;

    /* set up stream state */
    memset(ctx_data->ctr, 0, sizeof(ctx_data->ctr));
    memcpy(ctx_data->ctr, input, 8);
    AES_encrypt(ctx_data->ctr, ctx_data->stream, &ctx_data->key);
    ctx_data->count = 0;

    /* update offset */
    *offset = 8;

    return 0;
}
