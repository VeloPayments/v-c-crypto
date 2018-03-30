/**
 * \file vccrypt_aes_cbc_alg_encrypt.c
 *
 * Encrypt a single block using AES CBC Mode.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "block_cipher_private.h"

/**
 * Encrypt a single block of data using the block cipher.
 *
 * \param options       Opaque pointer to this options structure.
 * \param context       An opaque pointer to the vccrypt_block_context_t
 *                      structure.
 * \param iv            The initialization vector to use for this block.
 *                      Must be cryptographically random for the first
 *                      block.  Subsequent blocks should use the previous
 *                      output block for the iv (hence, cipher block
 *                      chaining).  Must be the block size in length.
 * \param input         A pointer to the plaintext input to encrypt.  Must
 *                      be the block size in length.
 * \param output        The output buffer where data is written.  The output
 *                      buffer must be at least the block size in length.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_aes_cbc_alg_encrypt(
    void* UNUSED(options), void* context, const void* iv, const void* input,
    void* output)
{
    uint8_t block[16];
    vccrypt_block_context_t* ctx = (vccrypt_block_context_t*)context;
    aes_cbc_context_data_t* ctx_data =
        (aes_cbc_context_data_t*)ctx->block_state;

    const uint8_t* vec = (const uint8_t*)iv;
    const uint8_t* in = (const uint8_t*)input;

    for (int i = 0; i < 16; ++i)
        block[i] = vec[i] ^ in[i];

    AES_encrypt(block, output, &ctx_data->key);
    memset(block, 0, sizeof(block));

    return VCCRYPT_STATUS_SUCCESS;
}
