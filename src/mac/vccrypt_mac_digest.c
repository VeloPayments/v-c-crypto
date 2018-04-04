/**
 * \file vccrypt_mac_digest.c
 *
 * Digest data into a mac context structure.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/mac.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * \brief Digest data for the given MAC instance.
 *
 * \param context       The MAC instance.
 * \param data          A pointer to raw data to digest.
 * \param size          The size of the data to digest, in bytes.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_MAC_DIGEST_INVALID_ARG if an invalid argument is
 *             provided.
 *      - a non-zero return code on error.
 */
int vccrypt_mac_digest(
    vccrypt_mac_context_t* context, const uint8_t* data, size_t size)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->options != NULL);
    MODEL_ASSERT(context->options->vccrypt_mac_alg_digest != NULL);
    MODEL_ASSERT(data != NULL && size > 0);

    /* sanity check of parameters */
    if (context == NULL || context->options == NULL ||
        context->options->vccrypt_mac_alg_digest == NULL || data == NULL)
    {
        return VCCRYPT_ERROR_MAC_DIGEST_INVALID_ARG;
    }

    return context->options->vccrypt_mac_alg_digest(context, data, size);
}
