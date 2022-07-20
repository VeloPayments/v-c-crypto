/**
 * \file vccrypt_block_register_mock.cpp
 *
 * \brief Register the mock block cipher.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/block_cipher.h>
#include <vccrypt/mock/block_cipher.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/* forward decls. */
static int vccrypt_block_mock_init(
    void* options, void* context, const vccrypt_buffer_t* key, bool encrypt);
static void vccrypt_block_mock_dispose(void* options, void* context);
static int vccrypt_block_mock_encrypt(
    void* options, void* context, const void* iv, const void* input,
    void* output);
static int vccrypt_block_mock_decrypt(
    void* options, void* context, const void* iv, const void* input,
    void* output);
static int vccrypt_block_mock_options_init(
    void* options, allocator_options_t* alloc_opts);
static void vccrypt_block_mock_options_dispose(
    void* disp);

/* instance data for block mock algorithm. */
static abstract_factory_registration_t block_mock_impl;
static vccrypt_block_options_t block_mock_options;
static bool block_mock_impl_registered = false;

/**
 * Register the mock block algorithm.
 */
void vccrypt_block_register_mock()
{
    MODEL_ASSERT(!block_mock_impl_registered);

    /* only register once */
    if (block_mock_impl_registered)
    {
        return;
    }

    /* set up options for aes-256-cbc-fips */
    block_mock_options.hdr.dispose = &vccrypt_block_mock_options_dispose;
    block_mock_options.alloc_opts = 0; /* alloc by init */
    block_mock_options.key_size = 32;
    block_mock_options.IV_size = 16;;
    block_mock_options.maximum_message_size = UINT64_MAX;
    block_mock_options.vccrypt_block_alg_init = &vccrypt_block_mock_init;
    block_mock_options.vccrypt_block_alg_dispose = &vccrypt_block_mock_dispose;
    block_mock_options.vccrypt_block_alg_encrypt = &vccrypt_block_mock_encrypt;
    block_mock_options.vccrypt_block_alg_decrypt = &vccrypt_block_mock_decrypt;
    block_mock_options.vccrypt_block_alg_options_init =
        &vccrypt_block_mock_options_init;

    /* set up this registration for the abstract factory. */
    block_mock_impl.interface =
        VCCRYPT_INTERFACE_BLOCK;
    block_mock_impl.implementation =
        VCCRYPT_BLOCK_ALGORITHM_MOCK;
    block_mock_impl.implementation_features =
        VCCRYPT_BLOCK_ALGORITHM_MOCK;
    block_mock_impl.factory = 0;
    block_mock_impl.context = &block_mock_options;

    /* register this instance. */
    abstract_factory_register(&block_mock_impl);

    /* only register once */
    block_mock_impl_registered = true;
}

/**
 * Algorithm-specific initialization for block cipher.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_block_context_t structure.
 * \param key       The key to use for this instance.
 * \param encrypt   Set to true if this is for encryption, and false for
 *                  decryption.
 *
 * \returns 0 on success and non-zero on error.
 */
static int vccrypt_block_mock_init(
    void* options, void* context, const vccrypt_buffer_t* key, bool encrypt)
{
    vccrypt_block_options_t* block_opts = (vccrypt_block_options_t*)options;
    vccrypt_block_context_t* block_ctx = (vccrypt_block_context_t*)context;

    block_mock* mock = (block_mock*)block_opts->options_context;

    if (!mock->block_init_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->block_init_mock)(block_opts, block_ctx, key, encrypt);
    }
}

/**
 * Algorithm-specific disposal for block cipher.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_block_context_t structure.
 */
static void vccrypt_block_mock_dispose(void* options, void* context)
{
    vccrypt_block_options_t* block_opts = (vccrypt_block_options_t*)options;
    vccrypt_block_context_t* block_ctx = (vccrypt_block_context_t*)context;

    block_mock* mock = (block_mock*)block_opts->options_context;

    if (!!mock->block_dispose_mock)
    {
        return (*mock->block_dispose_mock)(block_opts, block_ctx);
    }
}

/**
 * Encrypt a single block of data using the block cipher.
 *
 * \param options       Opaque pointer to this options structure.
 * \param context       An opaque pointer to the vccrypt_block_context_t
 *                      structure.
 * \param iv            The initialization vector to use for this block.
 *                      Must be cryptographically random for the first
 *                      block.  Subsequent blocks should use the previous
 *                      output block for the iv (hence, cipher block
 *                      chaining).  Must be the block size in length.
 * \param input         A pointer to the plaintext input to encrypt.  Must
 *                      be the block size in length.
 * \param output        The output buffer where data is written.  The output
 *                      buffer must be at least the block size in length.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int vccrypt_block_mock_encrypt(
    void* options, void* context, const void* iv, const void* input,
    void* output)
{
    vccrypt_block_options_t* block_opts = (vccrypt_block_options_t*)options;
    vccrypt_block_context_t* block_ctx = (vccrypt_block_context_t*)context;

    block_mock* mock = (block_mock*)block_opts->options_context;

    if (!mock->block_encrypt_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return
            (*mock->block_encrypt_mock)(block_ctx, iv, input, output);
    }
}

/**
 * Decrypt a single block of data using the block cipher.
 *
 * \param options       Opaque pointer to this options structure.
 * \param context       An opaque pointer to the vccrypt_block_context_t
 *                      structure.
 * \param iv            The initialization vector to use for this block.
 *                      The first block should be the first block of input.
 *                      Subsequent blocks should be the previous block of
 *                      ciphertext. (hence, cipher block chaining).  Must be
 *                      the block size in length.
 * \param input         A pointer to the plaintext input to encrypt.  The
 *                      first input block should be the second block of
 *                      input.  Must be the block size in length.
 * \param output        The output buffer where data is written.  The output
 *                      buffer must be at least the block size in length.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int vccrypt_block_mock_decrypt(
    void* options, void* context, const void* iv, const void* input,
    void* output)
{
    vccrypt_block_options_t* block_opts = (vccrypt_block_options_t*)options;
    vccrypt_block_context_t* block_ctx = (vccrypt_block_context_t*)context;

    block_mock* mock = (block_mock*)block_opts->options_context;

    if (!mock->block_decrypt_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return
            (*mock->block_decrypt_mock)(block_ctx, iv, input, output);
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
static int vccrypt_block_mock_options_init(
    void* options, allocator_options_t* UNUSED(alloc_opts))
{
    vccrypt_block_options_t* block_opts = (vccrypt_block_options_t*)options;

    block_opts->options_context = new block_mock;

    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure.
 *
 * \param options   the options structure to dispose.
 */
static void vccrypt_block_mock_options_dispose(
    void* disp)
{
    vccrypt_block_options_t* block_opts = (vccrypt_block_options_t*)disp;
    MODEL_ASSERT(block_opts != NULL);

    block_mock* mock = (block_mock*)block_opts->options_context;
    delete mock;

    memset(block_opts, 0, sizeof(vccrypt_block_options_t));
}
