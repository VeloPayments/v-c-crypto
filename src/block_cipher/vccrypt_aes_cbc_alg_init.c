/**
 * \file vccrypt_aes_cbc_alg_init.c
 *
 * Initialize the given AES CBC Mode block cipher context.
 *
 * \copyright 2018-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "block_cipher_private.h"

/**
 * Algorithm-specific initialization for block cipher.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_block_context_t structure.
 * \param key       The key to use for this instance.
 * \param encrypt   Set to true if this is for encryption, and false for
 *                  decryption.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_aes_cbc_alg_init(
    void* options, void* context, vccrypt_buffer_t* key, bool encrypt)
{
    vccrypt_block_options_t* opt = (vccrypt_block_options_t*)options;

    MODEL_ASSERT(NULL != opt->alloc_opts);

    if (NULL == opt->alloc_opts)
    {
        return VCCRYPT_ERROR_BLOCK_INIT_BAD_ALLOCATOR;
    }

    vccrypt_block_context_t* ctx = (vccrypt_block_context_t*)context;
    aes_cbc_options_data_t* opt_data = (aes_cbc_options_data_t*)opt->data;
    aes_cbc_context_data_t* ctx_data = (aes_cbc_context_data_t*)
        allocate(opt->alloc_opts, sizeof(aes_cbc_context_data_t));
    ctx->block_state = ctx_data;

    memset(ctx_data, 0, sizeof(aes_cbc_context_data_t));

    if (encrypt)
    {
        if (0 !=
            AES_set_encrypt_key(
                key->data, 256, opt_data->round_multiplier, &ctx_data->key))
        {
            memset(ctx_data, 0, sizeof(aes_cbc_context_data_t));
            release(opt->alloc_opts, ctx_data);
            return VCCRYPT_ERROR_BLOCK_INIT_BAD_ENCRYPTION_KEY;
        }
    }
    else
    {
        if (0 !=
            AES_set_decrypt_key(
                key->data, 256, opt_data->round_multiplier, &ctx_data->key))
        {
            memset(ctx_data, 0, sizeof(aes_cbc_context_data_t));
            release(opt->alloc_opts, ctx_data);
            return VCCRYPT_ERROR_BLOCK_INIT_BAD_DECRYPTION_KEY;
        }
    }

    return VCCRYPT_STATUS_SUCCESS;
}
