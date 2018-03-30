/**
 * \file vccrypt_mac_register_SHA_2_512_256_HMAC.c
 *
 * Register HMAC-SHA-512/256 for use as a mac algorithm.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/mac.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

#include "hmac.h"

/* forward decls */
static int hmac512_256_alg_init(
    void* options, void* context, vccrypt_buffer_t* key);
static void hmac512_256_alg_dispose(void* options, void* context);
static int hmac512_256_alg_digest(
    void* context, const uint8_t* data, size_t size);
static int hmac512_256_alg_finalize(void* context, vccrypt_buffer_t* mac_buffer);

/* static data for this instance */
static abstract_factory_registration_t hmac512_256_impl;
static vccrypt_mac_options_t hmac512_256_options;
static bool hmac512_256_impl_registered = false;

/* internal state structure */
typedef struct hmac512_256_state
{
    vccrypt_hash_options_t sha512_256_options;
    vccrypt_hmac_state_t hmac_state;
} hmac512_256_state_t;

/**
 * Register SHA-512/256 as a MAC algorithm instance.
 */
void vccrypt_mac_register_SHA_2_512_256_HMAC()
{
    /* only register once */
    if (hmac512_256_impl_registered)
    {
        return;
    }

    /* HMAC-512/256 depends on SHA-512/256 */
    vccrypt_hash_register_SHA_2_512_256();

    /* set up the options for HMAC-512/256 */
    hmac512_256_options.hdr.dispose = 0; /* disposal handled by init */
    hmac512_256_options.alloc_opts = 0; /* allocator handled by init */
    hmac512_256_options.key_size = VCCRYPT_MAC_SHA_512_256_KEY_SIZE;
    hmac512_256_options.key_expansion_supported = true;
    hmac512_256_options.mac_size = VCCRYPT_MAC_SHA_512_256_MAC_SIZE;
    hmac512_256_options.maximum_message_size = SIZE_MAX; /* actually, 2^128-1 */
    hmac512_256_options.vccrypt_mac_alg_init = &hmac512_256_alg_init;
    hmac512_256_options.vccrypt_mac_alg_dispose = &hmac512_256_alg_dispose;
    hmac512_256_options.vccrypt_mac_alg_digest = &hmac512_256_alg_digest;
    hmac512_256_options.vccrypt_mac_alg_finalize = &hmac512_256_alg_finalize;

    /* set up this registration for the abstract factory. */
    hmac512_256_impl.interface = VCCRYPT_INTERFACE_MAC;
    hmac512_256_impl.implementation =
        VCCRYPT_MAC_ALGORITHM_SHA_2_512_256_HMAC;
    hmac512_256_impl.implementation_features =
        VCCRYPT_MAC_ALGORITHM_SHA_2_512_256_HMAC;
    hmac512_256_impl.factory = 0;
    hmac512_256_impl.context = &hmac512_256_options;

    /* register this instance */
    abstract_factory_register(&hmac512_256_impl);

    /* only register once */
    hmac512_256_impl_registered = true;
}

/**
 * Algorithm-specific initialization for HMAC-512/256.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_mac_context_t structure.
 * \param key       The key to use for this instance.
 *
 * \returns 0 on success and non-zero on error.
*/
static int hmac512_256_alg_init(
    void* options, void* context, vccrypt_buffer_t* key)
{
    vccrypt_mac_options_t* opts = (vccrypt_mac_options_t*)options;
    vccrypt_mac_context_t* ctx = (vccrypt_mac_context_t*)context;
    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(opts->alloc_opts != NULL);
    MODEL_ASSERT(ctx != NULL);

    /* allocate space for our state structure */
    ctx->mac_state = allocate(opts->alloc_opts, sizeof(hmac512_256_state_t));
    hmac512_256_state_t* state = (hmac512_256_state_t*)ctx->mac_state;
    if (state == NULL)
    {
        return VCCRYPT_ERROR_MAC_INIT_OUT_OF_MEMORY;
    }

    /* initialize the SHA-512/256 options for this instance */
    int ret = vccrypt_hash_options_init(
        &state->sha512_256_options, opts->alloc_opts,
        VCCRYPT_HASH_ALGORITHM_SHA_2_512_256);
    if (ret != 0)
    {
        goto cleanup_state;
    }

    /* initialize hmac options for this instance */
    ret = vccrypt_hmac_init(
        &state->hmac_state, &state->sha512_256_options, key);
    if (ret != 0)
    {
        goto dispose_hash_options;
    }

    /* success */
    return VCCRYPT_STATUS_SUCCESS;

dispose_hash_options:
    dispose((disposable_t*)&state->sha512_256_options);

cleanup_state:
    release(opts->alloc_opts, ctx->mac_state);

    return ret;
}

/**
 * Algorithm-specific disposal for HMAC-SHA-512/256.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_mac_context_t structure.
 */
static void hmac512_256_alg_dispose(void* options, void* context)
{
    vccrypt_mac_options_t* opts = (vccrypt_mac_options_t*)options;
    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(opts->alloc_opts != NULL);
    vccrypt_mac_context_t* ctx = (vccrypt_mac_context_t*)context;
    MODEL_ASSERT(ctx != NULL);
    hmac512_256_state_t* state = (hmac512_256_state_t*)ctx->mac_state;
    MODEL_ASSERT(state != NULL);

    /* algorithm-specific cleanup */
    dispose((disposable_t*)&state->hmac_state);
    dispose((disposable_t*)&state->sha512_256_options);

    /* release this data structure */
    release(opts->alloc_opts, state);
}

/**
 * Digest data for this HMAC-SHA-512/256 instance.
 *
 * \param context       An opaque pointer to the vccrypt_mac_context_t
 *                      structure.
 * \param data          A pointer to raw data to digest.
 * \param size          The size of the data to digest, in bytes.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int hmac512_256_alg_digest(
    void* context, const uint8_t* data, size_t size)
{
    vccrypt_mac_context_t* ctx = (vccrypt_mac_context_t*)context;
    MODEL_ASSERT(ctx != NULL);
    hmac512_256_state_t* state = (hmac512_256_state_t*)ctx->mac_state;
    MODEL_ASSERT(state != NULL);

    return vccrypt_hmac_digest(&state->hmac_state, data, size);
}

/**
 * Finalize the message authentication code, copying the output data to the
 * given buffer.
 *
 * \param context       An opaque pointer to the vccrypt_mac_context_t
 *                      structure.
 * \param mac_buffer    The buffer to receive the MAC.  Must be large enough
 *                      for the given MAC algorithm.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int hmac512_256_alg_finalize(
    void* context, vccrypt_buffer_t* mac_buffer)
{
    vccrypt_mac_context_t* ctx = (vccrypt_mac_context_t*)context;
    MODEL_ASSERT(ctx != NULL);
    hmac512_256_state_t* state = (hmac512_256_state_t*)ctx->mac_state;
    MODEL_ASSERT(state != NULL);

    return vccrypt_hmac_finalize(&state->hmac_state, mac_buffer);
}
