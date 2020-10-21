/**
 * \file vccrypt_hash_register_SHA_2_512.c
 *
 * Register SHA-512 and force a link dependency so that this algorithm can be
 * used at runtime.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
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
static int vccrypt_sha_512_init(void* options, void* context);
static void vccrypt_sha_512_dispose(void* options, void* context);
static int vccrypt_sha_512_options_init(
    void* options, allocator_options_t* alloc_opts);
static void vccrypt_sha_512_options_dispose(void* disp);
static int vccrypt_sha_512_digest(
    void* context, const uint8_t* data, size_t size);
static int vccrypt_sha_512_finalize(
    void* context, vccrypt_buffer_t* hash_buffer);

/* static data for this instance */
static abstract_factory_registration_t sha512_impl;
static vccrypt_hash_options_t sha512_options;
static bool sha512_impl_registered = false;

/**
 * Register SHA-512 for use by the crypto library.
 */
void vccrypt_hash_register_SHA_2_512()
{
    /* only register once */
    if (sha512_impl_registered)
    {
        return;
    }

    /* set up the options for SHA-512 */
    sha512_options.hdr.dispose = &vccrypt_sha_512_options_dispose;
    sha512_options.alloc_opts = 0; /* allocator handled by init */
    sha512_options.hash_size = VCCRYPT_HASH_SHA_512_DIGEST_SIZE;
    sha512_options.hash_block_size = VCCRYPT_HASH_SHA_512_BLOCK_SIZE;
    sha512_options.vccrypt_hash_alg_init = &vccrypt_sha_512_init;
    sha512_options.vccrypt_hash_alg_dispose = &vccrypt_sha_512_dispose;
    sha512_options.vccrypt_hash_alg_digest = &vccrypt_sha_512_digest;
    sha512_options.vccrypt_hash_alg_finalize = &vccrypt_sha_512_finalize;
    sha512_options.vccrypt_hash_alg_options_init =
        &vccrypt_sha_512_options_init;

    /* set up this registration for the abstract factory. */
    sha512_impl.interface = VCCRYPT_INTERFACE_HASH;
    sha512_impl.implementation = VCCRYPT_HASH_ALGORITHM_SHA_2_512;
    sha512_impl.implementation_features = VCCRYPT_HASH_ALGORITHM_SHA_2_512;
    sha512_impl.factory = 0;
    sha512_impl.context = &sha512_options;

    /* register this instance. */
    abstract_factory_register(&sha512_impl);

    /* only register once */
    sha512_impl_registered = true;
}

/**
 * Algorithm-specific initialization for hash.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_hash_context_t structure.
 *
 * \returns 0 on success and non-zero on error.
 */
static int vccrypt_sha_512_init(void* options, void* context)
{
    vccrypt_hash_options_t* opts = (vccrypt_hash_options_t*)options;
    vccrypt_hash_context_t* ctx = (vccrypt_hash_context_t*)context;

    /* allocate space for the SHA-512 context. */
    ctx->hash_state = allocate(opts->alloc_opts, sizeof(SHA512_CTX));
    if (ctx->hash_state == NULL)
    {
        return VCCRYPT_ERROR_HASH_INIT_OUT_OF_MEMORY;
    }

    /* initialize this context. */
    SHA512_Init((SHA512_CTX*)ctx->hash_state);

    /* success */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Algorithm-specific disposal for hash.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_hash_context_t structure.
 */
static void vccrypt_sha_512_dispose(void* options, void* context)
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
static int vccrypt_sha_512_digest(
    void* context, const uint8_t* data, size_t size)
{
    vccrypt_hash_context_t* ctx = (vccrypt_hash_context_t*)context;

    SHA512_Update((SHA512_CTX*)ctx->hash_state, data, size);

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
static int vccrypt_sha_512_finalize(
    void* context, vccrypt_buffer_t* hash_buffer)
{
    vccrypt_hash_context_t* ctx = (vccrypt_hash_context_t*)context;

    return SHA512_Final((SHA512_CTX*)ctx->hash_state, hash_buffer->data);
}

/**
 * \brief Implementation specific options init method.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options structure for this method.
 *
 * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
 */
static int vccrypt_sha_512_options_init(
    void* UNUSED(options), allocator_options_t* UNUSED(alloc_opts))
{
    /* do nothing. */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * \brief Dispose of this options structure.
 *
 * \param disp          The options structure to dispose.
 */
static void vccrypt_sha_512_options_dispose(void* disp)
{
    MODEL_ASSERT(disp != NULL);

    memset(disp, 0, sizeof(vccrypt_hash_options_t));
}
