/**
 * \file vccrypt_block_init.c
 *
 * Generic initialization method for a block cipher.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vccrypt/block_cipher.h>
#include <vpr/parameters.h>

/**
 * \brief Initialize a Block Cipher algorithm instance with the given options
 * and key.
 *
 * Note that the key length must correspond to a length appropriate for the
 * Block Cipher algorithm.
 *
 * If initialization is successful, then this Block Cipher algorithm instance
 * is owned by the caller and must be disposed by calling dispose() when no
 * longer needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The block cipher instance to initialize.
 * \param key           The key to use for this algorithm instance.
 * \param encrypt       Set to true if this is for encryption, and false for
 *                      decryption.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BLOCK_INIT_INVALID_ARG if an invalid argument is
 *             provided.
 *      - a non-zero return code on failure.
 */
int vccrypt_block_init(
    vccrypt_block_options_t* options, vccrypt_block_context_t* context,
    vccrypt_buffer_t* key, bool encrypt)
{
    MODEL_ASSERT(NULL != options);
    MODEL_ASSERT(NULL != options->vccrypt_block_alg_init);
    MODEL_ASSERT(NULL != context);
    MODEL_ASSERT(NULL != key);

    if (NULL == options || NULL == options->vccrypt_block_alg_init || NULL == context || NULL == key)
    {
        return VCCRYPT_ERROR_BLOCK_INIT_INVALID_ARG;
    }

    return options->vccrypt_block_alg_init(options, context, key, encrypt);
}
