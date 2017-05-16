/**
 * \file vccrypt_hmac_finalize.c
 *
 * Finalize an hmac, writing the final hmac to the provided buffer.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "hmac.h"

/**
 * Finalize the hmac, copying the output data to the given buffer.
 *
 * \param state         The hmac state to finalize.
 * \param hmac_buffer   The buffer to receive the hmac.  Must be large enough
 *                      for the given hmac algorithm.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_hmac_finalize(
    vccrypt_hmac_state_t* state, vccrypt_buffer_t* hmac_buffer)
{
    MODEL_ASSERT(state != NULL);
    MODEL_ASSERT(state->hash_options != NULL);
    MODEL_ASSERT(state->hash_options->alloc_opts != NULL);
    MODEL_ASSERT(hmac_buffer != NULL);
    MODEL_ASSERT(hmac_buffer->size == state->hash_options->hash_size);

    /* parameter sanity check */
    if (state == NULL || state->hash_options == NULL ||
        state->hash_options->alloc_opts == NULL || hmac_buffer == NULL ||
        hmac_buffer->size != state->hash_options->hash_size)
    {
        return 1;
    }

    /* create a buffer to hold the inner hash */
    vccrypt_buffer_t inner;
    int ret = vccrypt_buffer_init(
        &inner, state->hash_options->alloc_opts,
        state->hash_options->hash_size);
    if (ret != 0)
    {
        return ret;
    }

    /* finalize the inner hash */
    ret = vccrypt_hash_finalize(&state->hash, &inner);
    if (ret != 0)
    {
        goto cleanup_inner;
    }

    /* dispose of the hash and re-initialize */
    dispose((disposable_t*)&state->hash);
    ret = vccrypt_hash_init(state->hash_options, &state->hash);
    if (ret != 0)
    {
        goto cleanup_inner;
    }

    /* create the outer key */
    vccrypt_buffer_t okey;
    ret = vccrypt_buffer_init(
        &okey, state->hash_options->alloc_opts,
        state->hash_options->hash_block_size);
    if (ret != 0)
    {
        goto cleanup_inner;
    }

    /* enrich the outer key with our key data */
    uint8_t* okeybuf = (uint8_t*)okey.data;
    const uint8_t* keybuf = (const uint8_t*)state->key.data;
    for (size_t i = 0; i < state->key.size; ++i)
    {
        okeybuf[i] = keybuf[i] ^ 0x5c;
    }

    /* digest the outer key */
    ret = vccrypt_hash_digest(&state->hash, okey.data, okey.size);
    if (ret != 0)
    {
        goto cleanup_outer_key;
    }

    /* digest the inner hash */
    ret = vccrypt_hash_digest(&state->hash, inner.data, inner.size);
    if (ret != 0)
    {
        goto cleanup_outer_key;
    }

    /* finalize the hash */
    ret = vccrypt_hash_finalize(&state->hash, hmac_buffer);

    /* fall-through */

cleanup_outer_key:
    dispose((disposable_t*)&okey);

cleanup_inner:
    dispose((disposable_t*)&inner);

    return ret;
}
