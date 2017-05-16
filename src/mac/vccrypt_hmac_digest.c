/**
 * \file vccrypt_hmac_digest.c
 *
 * Digest data into the hmac structure.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "hmac.h"

/**
 * Digest data for the given hmac instance.
 *
 * \param state         The hmac state to receive data.
 * \param data          A pointer to raw data to digest.
 * \param size          The size of the data to digest, in bytes.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_hmac_digest(
    vccrypt_hmac_state_t* state, const uint8_t* data, size_t size)
{
    MODEL_ASSERT(state != NULL);
    MODEL_ASSERT(data != NULL);

    return vccrypt_hash_digest(&state->hash, data, size);
}
