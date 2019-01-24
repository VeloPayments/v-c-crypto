/**
 * \file vccrypt_aes_ctr_alg_continue_encryption.c
 *
 * Continue encryption for a given AES CTR mode stream cipher instance.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "stream_cipher_private.h"

/*
 * TODO: this same implementation exists elsewhere in the code
 * DRY it up.  Ultimately this will be in vpr
 */
static uint64_t mmhtonll(uint64_t n)
{
    return ((((0xFF00000000000000 & n) >> 56) << 0) | (((0x00FF000000000000 & n) >> 48) << 8) | (((0x0000FF0000000000 & n) >> 40) << 16) | (((0x000000FF00000000 & n) >> 32) << 24) | (((0x00000000FF000000 & n) >> 24) << 32) | (((0x0000000000FF0000 & n) >> 16) << 40) | (((0x000000000000FF00 & n) >> 8) << 48) | (((0x00000000000000FF & n) >> 0) << 56));
}


/**
 * Algorithm-specific continuation for the stream cipher encryption.
 *
 * \param options       Opaque pointer to this options structure.
 * \param context       Opaque pointer to vccrypt_stream_context_t structure.
 * \param iv            The IV to use for this instance.  MUST ONLY BE USED ONCE
 * \param iv_size       The size of the IV in bytes.
 * \param input_offset  Current offset of the input buffer.
 *
 * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
 */
int vccrypt_aes_ctr_alg_continue_encryption(
    void* UNUSED(options), void* context, const void* iv,
    size_t iv_size, size_t input_offset)
{

    vccrypt_stream_context_t* ctx = (vccrypt_stream_context_t*)context;
    aes_ctr_context_data_t* ctx_data =
        (aes_ctr_context_data_t*)ctx->stream_state;

    memcpy(ctx_data->ctr, iv, iv_size);
    size_t net_offset = mmhtonll(input_offset / 16);
    memcpy(ctx_data->ctr + 8, &net_offset, sizeof(net_offset));

    AES_encrypt(ctx_data->ctr, ctx_data->stream, &ctx_data->key);
    ctx_data->count = input_offset % 16;

    return VCCRYPT_STATUS_SUCCESS;
}
