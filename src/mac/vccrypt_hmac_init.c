/**
 * \file vccrypt_hmac_init.c
 *
 * Initialize an hmac state structure.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "hmac.h"

/* forward decls */
static void vccrypt_hmac_dispose(void* context);
static int vccrypt_hmac_key_init(
    vccrypt_hmac_state_t* state, const vccrypt_buffer_t* key);

/**
 * Initialize an hmac_state_t using the given hash options and key.
 *
 * \param state             The vccrypt_hmac_state_t structure to initialize.
 * \param hash_options      The vccrypt_hash_options_t hash options to use for
 *                          this hmac.
 * \param key               The key to use to initialize this state structure.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_hmac_init(
    vccrypt_hmac_state_t* state, vccrypt_hash_options_t* hash_options,
    const vccrypt_buffer_t* key)
{
    MODEL_ASSERT(hash_options != NULL);
    MODEL_ASSERT(hash_options->alloc_opts != NULL);
    MODEL_ASSERT(hash_options->hash_size > 0);
    MODEL_ASSERT(state != NULL);
    MODEL_ASSERT(key != NULL);
    MODEL_ASSERT(key->size > 0);

    /* sanity check on parameters */
    if (hash_options == NULL || hash_options->alloc_opts == NULL ||
        hash_options->hash_size == 0 || state == NULL || key == NULL ||
        key->size == 0)
    {
        return VCCRYPT_ERROR_MAC_INIT_INVALID_ARG;
    }

    /* set the disposal method */
    state->hdr.dispose = &vccrypt_hmac_dispose;

    /* save the hash options */
    state->hash_options = hash_options;

    /* create the hash context for this hmac instance. */
    int ret = vccrypt_hash_init(state->hash_options, &state->hash);
    if (ret != 0)
    {
        return ret;
    }

    /* create the key buffer for our state buffer */
    ret = vccrypt_buffer_init(
        &state->key, state->hash_options->alloc_opts,
        state->hash_options->hash_block_size);
    if (ret != 0)
    {
        goto cleanup_hash;
    }

    /* initialize the key for our state buffer */
    ret = vccrypt_hmac_key_init(state, key);
    if (ret != 0)
    {
        goto cleanup_key;
    }

    /* create the inner key */
    vccrypt_buffer_t ikey;
    ret = vccrypt_buffer_init(
        &ikey, state->hash_options->alloc_opts,
        hash_options->hash_block_size);
    if (ret != 0)
    {
        goto cleanup_key;
    }

    /* enrich the inner key with our key data */
    uint8_t* ikeybuf = (uint8_t*)ikey.data;
    const uint8_t* keybuf = (const uint8_t*)state->key.data;
    for (size_t i = 0; i < state->key.size; ++i)
    {
        ikeybuf[i] = keybuf[i] ^ 0x36;
    }

    /* digest the inner key with the inner hash */
    ret = vccrypt_hash_digest(&state->hash, ikey.data, ikey.size);
    dispose((disposable_t*)&ikey);
    if (ret != 0)
    {
        goto cleanup_key;
    }

    return ret;

    /* error cleanup */

cleanup_key:
    dispose((disposable_t*)&state->key);

cleanup_hash:
    dispose((disposable_t*)&state->hash);

    return ret;
}

/**
 * Initialize the key for the HMAC, performing any pre-digest needed.
 *
 * \param state             The state structure to use for init.
 * \param key               The key to use for this HMAC.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int vccrypt_hmac_key_init(
    vccrypt_hmac_state_t* state, const vccrypt_buffer_t* key)
{
    const vccrypt_buffer_t* kv = key;
    size_t kv_size = key->size;
    int ret = 0;

    /* handle the case where the key is larger than the hash block size */
    if (kv_size > state->hash_options->hash_block_size)
    {
        /* create a hash instance */
        vccrypt_hash_context_t keyhash;
        ret = vccrypt_hash_init(state->hash_options, &keyhash);
        if (ret != 0)
        {
            return ret;
        }

        /* digest the key */
        ret = vccrypt_hash_digest(&keyhash, kv->data, kv_size);
        if (ret != 0)
        {
            dispose((disposable_t*)&keyhash);
            return ret;
        }

        /* finalize the key hash */
        ret = vccrypt_hash_finalize(&keyhash, &state->key);
        if (ret != 0)
        {
            dispose((disposable_t*)&keyhash);
            return ret;
        }

        /* set kv to the state key for the next part */
        kv = &state->key;
        kv_size = state->hash_options->hash_size;

        /* clean up */
        dispose((disposable_t*)&keyhash);
    }

    /* handle the case where the key is smaller than the hash block size */
    if (kv_size < state->hash_options->hash_block_size)
    {
        uint8_t* keybuf = (uint8_t*)state->key.data;

        /* copy the key to the beginning of the buffer */
        memmove(keybuf, kv->data, kv_size);
        /* clear the buffer after the key */
        memset(keybuf + kv_size, 0, state->key.size - kv_size);
    }
    /* handle the case where the key is exactly the hash size */
    else
    {
        MODEL_ASSERT(kv_size == state->key.size);

        memmove(state->key.data, kv->data, state->key.size);
    }

    /* success */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the hmac state structure.
 *
 * \param state         the hmac state structure to dispose.
 */
static void vccrypt_hmac_dispose(void* state)
{
    vccrypt_hmac_state_t* st = (vccrypt_hmac_state_t*)state;
    MODEL_ASSERT(st != NULL);

    /* dispose of algorithm-specific resources */
    dispose((disposable_t*)&st->hash);
    dispose((disposable_t*)&st->key);

    /* clear out this structure */
    memset(st, 0, sizeof(vccrypt_hmac_state_t));
}
