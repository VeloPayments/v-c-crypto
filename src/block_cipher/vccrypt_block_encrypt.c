/**
 * \file vccrypt_block_encrypt.c
 *
 * Generic method for encrypting a block using a block cipher instance.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vccrypt/block_cipher.h>
#include <vpr/parameters.h>

/**
 * Encrypt a single block of data using the block cipher.
 *
 * \param context       The block cipher context to use.
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
int vccrypt_block_encrypt(
    vccrypt_block_context_t* context, const void* iv, const void* input,
    void* output)
{
    MODEL_ASSERT(NULL != context);
    MODEL_ASSERT(NULL != context->options);
    MODEL_ASSERT(NULL != context->options->vccrypt_aes_cbc_alg_encrypt);
    MODEL_ASSERT(NULL != iv);
    MODEL_ASSERT(NULL != input);
    MODEL_ASSERT(NULL != output);

    return context->options->vccrypt_block_alg_encrypt(
        context->options, context, iv, input, output);
}
