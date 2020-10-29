/**
 * \file vccrypt_aes_cbc_alg_dispose.c
 *
 * \brief Dispose the given AES CBC Mode block cipher context.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "block_cipher_private.h"

/**
 * Algorithm-specific disposal for block cipher.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_block_context_t structure.
 */
void vccrypt_aes_cbc_alg_dispose(void* UNUSED(options), void* context)
{
    vccrypt_block_context_t* ctx = (vccrypt_block_context_t*)context;
    aes_cbc_context_data_t* ctx_data =
        (aes_cbc_context_data_t*)ctx->block_state;

    memset(ctx_data, 0, sizeof(aes_cbc_context_data_t));
    release(ctx->options->alloc_opts, ctx_data);
}
