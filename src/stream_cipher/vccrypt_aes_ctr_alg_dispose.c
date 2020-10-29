/**
 * \file vccrypt_aes_ctr_alg_dispose.c
 *
 * \brief Implementation-specific disposal for a stream cipher algorithm ctx.
 *
 * \copyright 2018-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "stream_cipher_private.h"

/**
 * Algorithm-specific disposal for stream cipher.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_stream_context_t structure.
 */
void vccrypt_aes_ctr_alg_dispose(void* UNUSED(options), void* context)
{
    vccrypt_stream_context_t* ctx = (vccrypt_stream_context_t*)context;
    aes_ctr_context_data_t* ctx_data =
        (aes_ctr_context_data_t*)ctx->stream_state;

    memset(ctx_data, 0, sizeof(aes_ctr_context_data_t));
    release(ctx->options->alloc_opts, ctx_data);
}
