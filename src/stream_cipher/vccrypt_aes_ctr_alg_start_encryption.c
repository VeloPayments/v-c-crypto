/**
 * \file vccrypt_aes_ctr_alg_start_encryption.c
 *
 * Start encryption for a given AES CTR mode stream cipher instance.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "stream_cipher_private.h"

/**
 * Algorithm-specific start for the stream cipher encryption.  Initializes
 * output buffer with IV.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_stream_context_t structure.
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
int vccrypt_aes_ctr_alg_start_encryption(
    void* UNUSED(options), void* context, const void* iv, size_t ivSize,
    void* output, size_t* offset)
{
    /* ivSize *MUST* be 8 */
    MODEL_ASSERT(8 == ivSize);
    if (8 != ivSize)
        return 1;

    vccrypt_stream_context_t* ctx = (vccrypt_stream_context_t*)context;
    aes_ctr_context_data_t* ctx_data =
        (aes_ctr_context_data_t*)ctx->stream_state;

    /* set up stream state */
    memset(ctx_data->ctr, 0, sizeof(ctx_data->ctr));
    memcpy(ctx_data->ctr, iv, ivSize);
    AES_encrypt(ctx_data->ctr, ctx_data->stream, &ctx_data->key);
    ctx_data->count = 0;

    /* write iv to output. */
    memcpy(output, iv, ivSize);
    *offset = ivSize;

    return 0;
}
