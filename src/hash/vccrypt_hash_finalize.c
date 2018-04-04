/**
 * \file vccrypt_hash_finalize.c
 *
 * Finalize the hash and write the digest to the output buffer.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/hash.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * \brief Finalize the hash, copying the output data to the given buffer.
 *
 * \param context       The hash instance.
 * \param hash_buffer   The buffer to receive the hash.  Must be large enough
 *                      for the given hash algorithm.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_HASH_DIGEST_INVALID_ARG if an invalid argument is
 *             provided.
 */
int vccrypt_hash_finalize(
    vccrypt_hash_context_t* context, vccrypt_buffer_t* hash_buffer)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->options != NULL);
    MODEL_ASSERT(context->options->hash_size > 0);
    MODEL_ASSERT(context->options->vccrypt_hash_alg_finalize != NULL);
    MODEL_ASSERT(hash_buffer != NULL);
    MODEL_ASSERT(hash_buffer->data != NULL);
    MODEL_ASSERT(hash_buffer->size >= context->options->hash_size);

    /* sanity check on parameters */
    if (context == NULL || context->options == NULL ||
        context->options->vccrypt_hash_alg_finalize == NULL ||
        hash_buffer == NULL || hash_buffer->data == NULL ||
        hash_buffer->size < context->options->hash_size)
    {
        return VCCRYPT_ERROR_HASH_FINALIZE_INVALID_ARG;
    }

    return context->options->vccrypt_hash_alg_finalize(context, hash_buffer);
}
