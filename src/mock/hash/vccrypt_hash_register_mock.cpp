/**
 * \file src/mock/hash/vccrypt_hash_register_mock.cpp
 *
 * Register mock hash algorithm and force a link dependency so that this
 * algorithm can be used at runtime.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/mock_suite.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

using namespace std;

/* forward decls */
static int vccrypt_hash_mock_init(void* options, void* context);
static void vccrypt_hash_mock_dispose(void* options, void* context);
static int vccrypt_hash_mock_options_init(
    void* options, allocator_options_t* alloc_opts);
static void vccrypt_hash_mock_options_dispose(void* disp);
static int vccrypt_hash_mock_digest(
    void* context, const uint8_t* data, size_t size);
static int vccrypt_hash_mock_finalize(
    void* context, vccrypt_buffer_t* hash_buffer);

/* static data for this instance */
static abstract_factory_registration_t mock_hash_impl;
static vccrypt_hash_options_t mock_hash_options;
static bool mock_hash_impl_registered = false;

/**
 * \brief Register the mock algorithm.
 */
void vccrypt_hash_register_mock()
{
    /* only register once */
    if (mock_hash_impl_registered)
    {
        return;
    }

    /* set up the options for SHA-512 */
    mock_hash_options.hdr.dispose = &vccrypt_hash_mock_options_dispose;
    mock_hash_options.alloc_opts = 0; /* allocator handled by init */
    mock_hash_options.hash_size = VCCRYPT_HASH_SHA_512_DIGEST_SIZE;
    mock_hash_options.hash_block_size = VCCRYPT_HASH_SHA_512_BLOCK_SIZE;
    mock_hash_options.vccrypt_hash_alg_init = &vccrypt_hash_mock_init;
    mock_hash_options.vccrypt_hash_alg_dispose = &vccrypt_hash_mock_dispose;
    mock_hash_options.vccrypt_hash_alg_digest = &vccrypt_hash_mock_digest;
    mock_hash_options.vccrypt_hash_alg_finalize = &vccrypt_hash_mock_finalize;
    mock_hash_options.vccrypt_hash_alg_options_init =
        &vccrypt_hash_mock_options_init;
    mock_hash_options.options_context = nullptr;

    /* set up this registration for the abstract factory. */
    mock_hash_impl.interface = VCCRYPT_INTERFACE_HASH;
    mock_hash_impl.implementation = VCCRYPT_HASH_ALGORITHM_MOCK;
    mock_hash_impl.implementation_features = VCCRYPT_HASH_ALGORITHM_MOCK;
    mock_hash_impl.factory = 0;
    mock_hash_impl.context = &mock_hash_options;

    /* register this instance. */
    abstract_factory_register(&mock_hash_impl);

    /* only register once */
    mock_hash_impl_registered = true;
}

/**
 * Algorithm-specific initialization for hash.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_hash_context_t structure.
 *
 * \returns 0 on success and non-zero on error.
 */
static int vccrypt_hash_mock_init(void* options, void* context)
{
    vccrypt_hash_options_t* hash_options = (vccrypt_hash_options_t*)options;
    vccrypt_hash_context_t* hash_context = (vccrypt_hash_context_t*)context;

    hash_mock* mock = (hash_mock*)hash_options->options_context;

    if (!mock->hash_init_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->hash_init_mock)(hash_options, hash_context);
    }
}

/**
 * Algorithm-specific disposal for hash.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_hash_context_t structure.
 */
static void vccrypt_hash_mock_dispose(void* options, void* context)
{
    vccrypt_hash_options_t* hash_options = (vccrypt_hash_options_t*)options;
    vccrypt_hash_context_t* hash_context = (vccrypt_hash_context_t*)context;

    hash_mock* mock = (hash_mock*)hash_options->options_context;

    if (!!mock->hash_dispose_mock)
    {
        (*mock->hash_dispose_mock)(hash_options, hash_context);
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
static int vccrypt_hash_mock_digest(
    void* context, const uint8_t* data, size_t size)
{
    vccrypt_hash_context_t* hash_context = (vccrypt_hash_context_t*)context;
    vccrypt_hash_options_t* hash_options = hash_context->options;

    hash_mock* mock = (hash_mock*)hash_options->options_context;

    if (!mock->hash_digest_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->hash_digest_mock)(hash_context, data, size);
    }
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
static int vccrypt_hash_mock_finalize(
    void* context, vccrypt_buffer_t* hash_buffer)
{
    vccrypt_hash_context_t* hash_context = (vccrypt_hash_context_t*)context;
    vccrypt_hash_options_t* hash_options = hash_context->options;

    hash_mock* mock = (hash_mock*)hash_options->options_context;

    if (!mock->hash_finalize_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->hash_finalize_mock)(hash_context, hash_buffer);
    }
}

/**
 * \brief Implementation specific options init method.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options structure for this method.
 *
 * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
 */
static int vccrypt_hash_mock_options_init(
    void* options, allocator_options_t* UNUSED(alloc_opts))
{
    vccrypt_hash_options_t* hash_options = (vccrypt_hash_options_t*)options;

    hash_options->options_context = new hash_mock;

    /* do nothing. */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * \brief Dispose of this options structure.
 *
 * \param disp          The options structure to dispose.
 */
static void vccrypt_hash_mock_options_dispose(void* disp)
{
    vccrypt_hash_options_t* hash_options = (vccrypt_hash_options_t*)disp;
    MODEL_ASSERT(hash_options != NULL);

    hash_mock* mock = (hash_mock*)hash_options->options_context;
    delete mock;

    memset(hash_options, 0, sizeof(vccrypt_hash_options_t));
}
