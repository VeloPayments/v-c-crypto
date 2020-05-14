/**
 * \file vccrypt_prng_read_uuid.c
 *
 * Read a random uuid from a PRNG source.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/prng.h>
#include <vpr/parameters.h>

/**
 * \brief Read a cryptographically random UUID from the prng.
 *
 * Internally, the PRNG source may need to reseed, which may cause the current
 * thread to block until the reseeding process is complete.
 *
 * \param context       The prng instance to initialize.
 * \param uuid          The uuid to read.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_prng_read_uuid(
    vccrypt_prng_context_t* context, vpr_uuid* uuid)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->options != NULL);
    MODEL_ASSERT(context->options->vccrypt_prng_alg_read != NULL);
    MODEL_ASSERT(uuid != NULL);

    return context->options->vccrypt_prng_alg_read(
        context, uuid->data, sizeof(uuid->data));
}
