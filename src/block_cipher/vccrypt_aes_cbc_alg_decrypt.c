/**
 * \file vccrypt_aes_cbc_alg_decrypt.c
 *
 * Decrypt a single block using AES CBC Mode.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vpr/parameters.h>

#include "block_cipher_private.h"

/**
 * Decrypt a single block of data using the block cipher.
 *
 * \param options       Opaque pointer to this options structure.
 * \param context       An opaque pointer to the vccrypt_block_context_t
 *                      structure.
 * \param iv            The initialization vector to use for this block.
 *                      The first block should be the first block of input.
 *                      Subsequent blocks should be the previous block of
 *                      ciphertext. (hence, cipher block chaining).  Must be
 *                      the block size in length.
 * \param input         A pointer to the plaintext input to encrypt.  The
 *                      first input block should be the second block of
 *                      input.  Must be the block size in length.
 * \param output        The output buffer where data is written.  The output
 *                      buffer must be at least the block size in length.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_aes_cbc_alg_decrypt(
    void* UNUSED(options), void* context, const void* iv, const void* input,
    void* output)
{
    vccrypt_block_context_t* ctx = (vccrypt_block_context_t*)context;
    aes_cbc_context_data_t* ctx_data =
        (aes_cbc_context_data_t*)ctx->block_state;

    AES_decrypt(input, output, &ctx_data->key);

    const uint8_t* vec = (const uint8_t*)iv;
    uint8_t* out = (uint8_t*)output;
    for (int i = 0; i < 16; ++i)
        out[i] ^= vec[i];

    return VCCRYPT_STATUS_SUCCESS;
}
