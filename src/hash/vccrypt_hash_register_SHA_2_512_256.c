/**
 * \file vccrypt_hash_register_SHA_2_512_256.c
 *
 * Register SHA-512/256 and force a link dependency so that this algorithm can be
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
static int vccrypt_sha_512_256_init(void* options, void* context);
static void vccrypt_sha_512_256_dispose(void* options, void* context);
static int vccrypt_sha_512_256_digest(
    void* context, const uint8_t* data, size_t size);
static int vccrypt_sha_512_256_finalize(
    void* context, vccrypt_buffer_t* hash_buffer);

/* static data for this instance */
static abstract_factory_registration_t sha512_256_impl;
static vccrypt_hash_options_t sha512_256_options;
static bool sha512_256_impl_registered = false;

/**
 * Register SHA-512/256 for use by the crypto library.
 */
void vccrypt_hash_register_SHA_2_512_256()
{
    /* only register once */
    if (sha512_256_impl_registered)
    {
        return;
    }

    /* set up the options for SHA-512_256 */
    sha512_256_options.hdr.dispose = 0; /* disposal handled by init */
    sha512_256_options.alloc_opts = 0; /* allocator handled by init */
    sha512_256_options.hash_size =
        VCCRYPT_HASH_SHA_512_256_DIGEST_SIZE;
    sha512_256_options.hash_block_size =
        VCCRYPT_HASH_SHA_512_256_BLOCK_SIZE;
    sha512_256_options.vccrypt_hash_alg_init = &vccrypt_sha_512_256_init;
    sha512_256_options.vccrypt_hash_alg_dispose = &vccrypt_sha_512_256_dispose;
    sha512_256_options.vccrypt_hash_alg_digest = &vccrypt_sha_512_256_digest;
    sha512_256_options.vccrypt_hash_alg_finalize =
        &vccrypt_sha_512_256_finalize;

    /* set up this registration for the abstract factory. */
    sha512_256_impl.interface = VCCRYPT_INTERFACE_HASH;
    sha512_256_impl.implementation =
        VCCRYPT_HASH_ALGORITHM_SHA_2_512_256;
    sha512_256_impl.implementation_features =
        VCCRYPT_HASH_ALGORITHM_SHA_2_512_256;
    sha512_256_impl.factory = 0;
    sha512_256_impl.context = &sha512_256_options;

    /* register this instance. */
    abstract_factory_register(&sha512_256_impl);

    /* only register once */
    sha512_256_impl_registered = true;
}

/**
 * Algorithm-specific initialization for hash.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_hash_context_t structure.
 *
 * \returns 0 on success and non-zero on error.
 */
static int vccrypt_sha_512_256_init(void* options, void* context)
{
    vccrypt_hash_options_t* opts = (vccrypt_hash_options_t*)options;
    vccrypt_hash_context_t* ctx = (vccrypt_hash_context_t*)context;

    /* allocate space for the SHA-512/256 context. */
    ctx->hash_state = allocate(opts->alloc_opts, sizeof(SHA512_CTX));
    if (ctx->hash_state == NULL)
    {
        return VCCRYPT_ERROR_HASH_INIT_OUT_OF_MEMORY;
    }

    /* initialize this context. */
    SHA512_256_Init((SHA512_CTX*)ctx->hash_state);

    /* success */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Algorithm-specific disposal for hash.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_hash_context_t structure.
 */
static void vccrypt_sha_512_256_dispose(void* options, void* context)
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
static int vccrypt_sha_512_256_digest(
    void* context, const uint8_t* data, size_t size)
{
    vccrypt_hash_context_t* ctx = (vccrypt_hash_context_t*)context;

    SHA512_256_Update((SHA512_CTX*)ctx->hash_state, data, size);

    /* success */
    return VCCRYPT_STATUS_SUCCESS;
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
static int vccrypt_sha_512_256_finalize(
    void* context, vccrypt_buffer_t* hash_buffer)
{
    vccrypt_hash_context_t* ctx = (vccrypt_hash_context_t*)context;

    return SHA512_256_Final((SHA512_CTX*)ctx->hash_state, hash_buffer->data);
}
