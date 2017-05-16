/**
 * \file vccrypt_hash_register_SHA_2_384.c
 *
 * Register SHA-384 and force a link dependency so that this algorithm can be
 * used at runtime.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/hash.h>
#include <vpr/abstract_factory.h>
#include <vpr/allocator.h>
#include <vpr/parameters.h>

#include "ref/sha512.h"

/* forward decls */
static int vccrypt_sha_384_init(void* options, void* context);
static void vccrypt_sha_384_dispose(void* options, void* context);
static int vccrypt_sha_384_digest(
    void* context, const uint8_t* data, size_t size);
static int vccrypt_sha_384_finalize(
    void* context, vccrypt_buffer_t* hash_buffer);

/* static data for this instance */
static abstract_factory_registration_t sha384_impl;
static vccrypt_hash_options_t sha384_options;
static bool sha384_impl_registered = false;

/**
 * Register SHA-384 for use by the crypto library.
 */
void vccrypt_hash_register_SHA_2_384()
{
    /* only register once */
    if (sha384_impl_registered)
    {
        return;
    }

    /* set up the options for SHA-384 */
    sha384_options.hdr.dispose = 0; /* disposal handled by init */
    sha384_options.alloc_opts = 0; /* allocator handled by init */
    sha384_options.hash_size = 48;
    sha384_options.hash_block_size = 128;
    sha384_options.vccrypt_hash_alg_init = &vccrypt_sha_384_init;
    sha384_options.vccrypt_hash_alg_dispose = &vccrypt_sha_384_dispose;
    sha384_options.vccrypt_hash_alg_digest = &vccrypt_sha_384_digest;
    sha384_options.vccrypt_hash_alg_finalize = &vccrypt_sha_384_finalize;

    /* set up this registration for the abstract factory. */
    sha384_impl.interface = VCCRYPT_INTERFACE_HASH;
    sha384_impl.implementation = VCCRYPT_HASH_ALGORITHM_SHA_2_384;
    sha384_impl.implementation_features = VCCRYPT_HASH_ALGORITHM_SHA_2_384;
    sha384_impl.factory = 0;
    sha384_impl.context = &sha384_options;

    /* register this instance. */
    abstract_factory_register(&sha384_impl);

    /* only register once */
    sha384_impl_registered = true;
}

/**
 * Algorithm-specific initialization for hash.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_hash_context_t structure.
 *
 * \returns 0 on success and non-zero on error.
 */
static int vccrypt_sha_384_init(void* options, void* context)
{
    vccrypt_hash_options_t* opts = (vccrypt_hash_options_t*)options;
    vccrypt_hash_context_t* ctx = (vccrypt_hash_context_t*)context;

    /* allocate space for the SHA-384 context. */
    ctx->hash_state = allocate(opts->alloc_opts, sizeof(SHA512_CTX));
    if (ctx->hash_state == NULL)
    {
        return 1;
    }

    /* initialize this context. */
    SHA384_Init((SHA512_CTX*)ctx->hash_state);

    /* success */
    return 0;
}

/**
 * Algorithm-specific disposal for hash.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_hash_context_t structure.
 */
static void vccrypt_sha_384_dispose(void* options, void* context)
{
    vccrypt_hash_options_t* opts = (vccrypt_hash_options_t*)options;
    vccrypt_hash_context_t* ctx = (vccrypt_hash_context_t*)context;

    /* clear the hash state structure if allocated. */
    if (ctx->hash_state != NULL)
    {
        memset(ctx->hash_state, 0, sizeof(SHA512_CTX));
        release(opts->alloc_opts, ctx->hash_state);
    }
}

/**
 * Digest data for the given hash instance.
 *
 * \param context       An opaque pointer to the vccrypt_hash_context_t
 *                      structure.
 * \param data          A pointer to raw data to digest.
 * \param size          The size of the data to digest, in bytes.
 *
 * \returns 0 on success and 1 on failure.
 */
static int vccrypt_sha_384_digest(
    void* context, const uint8_t* data, size_t size)
{
    vccrypt_hash_context_t* ctx = (vccrypt_hash_context_t*)context;

    SHA384_Update((SHA512_CTX*)ctx->hash_state, data, size);

    /* success */
    return 0;
}

/**
 * Finalize the hash, copying the output data to the given buffer.
 *
 * \param context       An opaque pointer to the vccrypt_hash_context_t
 *                      structure.
 * \param hash_buffer   The buffer to receive the hash.  Must be large
 *                      enough for the given hash algorithm.
 *
 * \returns 0 on success and 1 on failure.
 */
static int vccrypt_sha_384_finalize(
    void* context, vccrypt_buffer_t* hash_buffer)
{
    vccrypt_hash_context_t* ctx = (vccrypt_hash_context_t*)context;

    return SHA384_Final((SHA512_CTX*)ctx->hash_state, hash_buffer->data);
}
