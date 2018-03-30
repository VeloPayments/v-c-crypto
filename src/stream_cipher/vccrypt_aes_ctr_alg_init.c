/**
 * \file vccrypt_aes_ctr_alg_init.c
 *
 * Initialize an AES CTR mode stream cipher instance.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "stream_cipher_private.h"

/* forward decls */
static void vccrypt_aes_ctr_alg_ctx_dispose(void* context);

/**
 * Algorithm-specific initialization for stream cipher.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_stream_context_t structure.
 * \param key       The key to use for this instance.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_aes_ctr_alg_init(
    void* options, void* context, vccrypt_buffer_t* key)
{
    vccrypt_stream_options_t* opt = (vccrypt_stream_options_t*)options;

    MODEL_ASSERT(NULL != opt->alloc_opts);

    if (NULL == opt->alloc_opts)
        return VCCRYPT_ERROR_STREAM_INIT_OUT_OF_MEMORY;

    vccrypt_stream_context_t* ctx = (vccrypt_stream_context_t*)context;
    aes_ctr_options_data_t* opt_data = (aes_ctr_options_data_t*)opt->data;
    aes_ctr_context_data_t* ctx_data = (aes_ctr_context_data_t*)
        allocate(opt->alloc_opts, sizeof(aes_ctr_context_data_t));

    ctx->hdr.dispose = &vccrypt_aes_ctr_alg_ctx_dispose;
    ctx->options = opt;
    ctx->stream_state = ctx_data;

    memset(ctx_data, 0, sizeof(aes_ctr_context_data_t));
    if (0 !=
        AES_set_encrypt_key(
            key->data, 256, opt_data->round_multiplier, &ctx_data->key))
    {
        memset(ctx_data, 0, sizeof(aes_ctr_context_data_t));
        release(opt->alloc_opts, ctx_data);
        return VCCRYPT_ERROR_STREAM_INIT_BAD_ENCRYPTION_KEY;
    }

    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Clean up this stream cipher context.
 */
static void vccrypt_aes_ctr_alg_ctx_dispose(void* context)
{
    vccrypt_stream_context_t* ctx = (vccrypt_stream_context_t*)context;
    aes_ctr_context_data_t* ctx_data =
        (aes_ctr_context_data_t*)ctx->stream_state;

    memset(ctx_data, 0, sizeof(aes_ctr_context_data_t));
    release(ctx->options->alloc_opts, ctx_data);

    memset(ctx, 0, sizeof(vccrypt_stream_context_t));
}
