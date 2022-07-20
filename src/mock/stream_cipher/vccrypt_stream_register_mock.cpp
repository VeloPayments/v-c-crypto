/**
 * \file vccrypt_stream_register_mock.cpp
 *
 * \brief Registration for the mock stream cipher.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/mock/stream_cipher.h>
#include <vccrypt/stream_cipher.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/* forward decls. */
static int vccrypt_stream_mock_init(
    void* options, void* context, const vccrypt_buffer_t* key);
static void vccrypt_stream_mock_dispose(void* options, void* context);
static int vccrypt_stream_mock_start_encryption(
    void* options, void* context, const void* iv, size_t ivSize,
    void* output, size_t* offset);
static int vccrypt_stream_mock_continue_encryption(
    void* options, void* context, const void* iv,
    size_t iv_size, size_t input_offset);
static int vccrypt_stream_mock_start_decryption(
    void* options, void* context, const void* input, size_t* offset);
static int vccrypt_stream_mock_continue_decryption(
    void* options, void* context, const void* iv,
    size_t iv_size, size_t input_offset);
static int vccrypt_stream_mock_encrypt(
    void* options, void* context, const void* input, size_t size,
    void* output, size_t* offset);
static int vccrypt_stream_mock_decrypt(
    void* options, void* context, const void* input, size_t size,
    void* output, size_t* offset);
static int vccrypt_stream_mock_options_init(
    void* options, allocator_options_t* alloc_opts);
static void vccrypt_stream_mock_options_dispose(void* disp);

/* instance data for AES-256-CTR-FIPS. */
static abstract_factory_registration_t stream_mock_impl;
static vccrypt_stream_options_t stream_mock_options;
static bool stream_mock_impl_registered = false;

/**
 * \brief Register the mock algorithm.
 */
void vccrypt_stream_register_mock()
{
    MODEL_ASSERT(!stream_mock_impl_registered);

    /* only register once */
    if (stream_mock_impl_registered)
    {
        return;
    }

    /* set up options for stream mock. */
    stream_mock_options.hdr.dispose = &vccrypt_stream_mock_options_dispose;
    stream_mock_options.alloc_opts = 0; /* alloc by init */
    stream_mock_options.key_size = 32;
    stream_mock_options.IV_size = 16;
    stream_mock_options.maximum_message_size = UINT64_MAX;
    stream_mock_options.vccrypt_stream_alg_init = &vccrypt_stream_mock_init;
    stream_mock_options.vccrypt_stream_alg_dispose =
        &vccrypt_stream_mock_dispose;
    stream_mock_options.vccrypt_stream_alg_start_encryption =
        &vccrypt_stream_mock_start_encryption;
    stream_mock_options.vccrypt_stream_alg_continue_encryption =
        &vccrypt_stream_mock_continue_encryption;
    stream_mock_options.vccrypt_stream_alg_start_decryption =
        &vccrypt_stream_mock_start_decryption;
    stream_mock_options.vccrypt_stream_alg_continue_decryption =
        &vccrypt_stream_mock_continue_decryption;
    stream_mock_options.vccrypt_stream_alg_encrypt =
        &vccrypt_stream_mock_encrypt;
    stream_mock_options.vccrypt_stream_alg_decrypt =
        &vccrypt_stream_mock_decrypt;
    stream_mock_options.vccrypt_stream_alg_options_init =
        &vccrypt_stream_mock_options_init;

    /* set up this registration for the abstract factory. */
    stream_mock_impl.interface =
        VCCRYPT_INTERFACE_STREAM;
    stream_mock_impl.implementation =
        VCCRYPT_STREAM_ALGORITHM_MOCK;
    stream_mock_impl.implementation_features =
        VCCRYPT_STREAM_ALGORITHM_MOCK;
    stream_mock_impl.factory = 0;
    stream_mock_impl.context = &stream_mock_options;

    /* register this instance. */
    abstract_factory_register(&stream_mock_impl);

    /* only register once */
    stream_mock_impl_registered = true;
}

/**
 * Algorithm-specific initialization for stream cipher.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_stream_context_t structure.
 * \param key       The key to use for this instance.
 *
 * \returns 0 on success and non-zero on error.
 */
static int vccrypt_stream_mock_init(
    void* options, void* context, const vccrypt_buffer_t* key)
{
    vccrypt_stream_options_t* stream_opts = (vccrypt_stream_options_t*)options;
    vccrypt_stream_context_t* stream_ctx = (vccrypt_stream_context_t*)context;

    stream_mock* mock = (stream_mock*)stream_opts->options_context;

    if (!mock->stream_init_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->stream_init_mock)(stream_opts, stream_ctx, key);
    }
}

/**
 * Algorithm-specific disposal for stream cipher.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_stream_context_t structure.
 */
static void vccrypt_stream_mock_dispose(void* options, void* context)
{
    vccrypt_stream_options_t* stream_opts = (vccrypt_stream_options_t*)options;
    vccrypt_stream_context_t* stream_ctx = (vccrypt_stream_context_t*)context;

    stream_mock* mock = (stream_mock*)stream_opts->options_context;

    if (!!mock->stream_dispose_mock)
    {
        return (*mock->stream_dispose_mock)(stream_opts, stream_ctx);
    }
}

/**
 * Algorithm-specific start for the stream cipher encryption.  Initializes
 * output buffer with IV.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_stream_context_t structure.
 * \param iv        The IV to use for this instance.  MUST ONLY BE USED ONCE
 *                  PER KEY, EVER.
 * \param ivSize    The size of the IV in bytes.
 * \param output    The output buffer to initialize. Must be at least
 *                  IV_bytes in size.
 * \param offset    Pointer to the current offset of the buffer.  Will be
 *                  set to IV_bytes.  The value in this offset is ignored.
 *
 * \returns 0 on success and non-zero on error.
 */
static int vccrypt_stream_mock_start_encryption(
    void* options, void* context, const void* iv, size_t ivSize,
    void* output, size_t* offset)
{
    vccrypt_stream_options_t* stream_opts = (vccrypt_stream_options_t*)options;
    vccrypt_stream_context_t* stream_ctx = (vccrypt_stream_context_t*)context;

    stream_mock* mock = (stream_mock*)stream_opts->options_context;

    if (!mock->stream_start_encyption_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return
            (*mock->stream_start_encyption_mock)(
                stream_ctx, iv, ivSize, output, offset);
    }
}

/**
 * Algorithm-specific continuation for the stream cipher encryption.
 *
 * \param options       Opaque pointer to this options structure.
 * \param context       Opaque pointer to vccrypt_stream_context_t structure.
 * \param iv            The IV to use for this instance.  MUST ONLY BE USED ONCE
 * \param iv_size       The size of the IV in bytes.
 * \param input_offset  Current offset of the input buffer.
 *
 * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
 */
static int vccrypt_stream_mock_continue_encryption(
    void* options, void* context, const void* iv,
    size_t iv_size, size_t input_offset)
{
    vccrypt_stream_options_t* stream_opts = (vccrypt_stream_options_t*)options;
    vccrypt_stream_context_t* stream_ctx = (vccrypt_stream_context_t*)context;

    stream_mock* mock = (stream_mock*)stream_opts->options_context;

    if (!mock->stream_continue_encyption_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return
            (*mock->stream_continue_encyption_mock)(
                stream_ctx, iv, iv_size, input_offset);
    }
}

/**
 * Algorithm-specific start for the stream cipher decryption.  Reads IV from
 * input buffer.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_stream_context_t structure.
 * \param input     The input buffer to read the IV from. Must be at least
 *                  IV_bytes in size.
 * \param offset    Pointer to the current offset of the buffer.  Will be
 *                  set to IV_bytes.  The value in this offset is ignored.
 *
 * \returns 0 on success and non-zero on error.
 */
static int vccrypt_stream_mock_start_decryption(
    void* options, void* context, const void* input, size_t* offset)
{
    vccrypt_stream_options_t* stream_opts = (vccrypt_stream_options_t*)options;
    vccrypt_stream_context_t* stream_ctx = (vccrypt_stream_context_t*)context;

    stream_mock* mock = (stream_mock*)stream_opts->options_context;

    if (!mock->stream_start_decryption_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return
            (*mock->stream_start_decryption_mock)(stream_ctx, input, offset);
    }
}

/**
 * Algorithm-specific continuation for the stream cipher decryption.
 *
 * \param options       Opaque pointer to this options structure.
 * \param context       Opaque pointer to vccrypt_stream_context_t structure.
 * \param iv            The IV to use for this instance.  MUST ONLY BE USED ONCE
 * \param iv_size       The size of the IV in bytes.
 * \param input_offset  Current offset of the input buffer.
 *
 * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
 */
static int vccrypt_stream_mock_continue_decryption(
    void* options, void* context, const void* iv,
    size_t iv_size, size_t input_offset)
{
    vccrypt_stream_options_t* stream_opts = (vccrypt_stream_options_t*)options;
    vccrypt_stream_context_t* stream_ctx = (vccrypt_stream_context_t*)context;

    stream_mock* mock = (stream_mock*)stream_opts->options_context;

    if (!mock->stream_continue_decryption_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return
            (*mock->stream_continue_decryption_mock)(
                stream_ctx, iv, iv_size, input_offset);
    }
}

/**
 * Encrypt data using the stream cipher.
 *
 * \param options       Opaque pointer to this options structure.
 * \param context       An opaque pointer to the vccrypt_stream_context_t
 *                      structure.
 * \param input         A pointer to the plaintext input to encrypt.
 * \param size          The size of the plaintext input, in bytes.
 * \param output        The output buffer where data is written.  There must
 *                      be at least *offset + size bytes available in this
 *                      buffer.
 * \param offset        A pointer to the current offset in the buffer.  Will
 *                      be incremented by size.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int vccrypt_stream_mock_encrypt(
    void* options, void* context, const void* input, size_t size,
    void* output, size_t* offset)
{
    vccrypt_stream_options_t* stream_opts = (vccrypt_stream_options_t*)options;
    vccrypt_stream_context_t* stream_ctx = (vccrypt_stream_context_t*)context;

    stream_mock* mock = (stream_mock*)stream_opts->options_context;

    if (!mock->stream_encrypt_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return
            (*mock->stream_encrypt_mock)(
                stream_ctx, input, size, output, offset);
    }
}

/**
 * Decrypt data using the stream cipher.
 *
 * \param options       Opaque pointer to this options structure.
 * \param context       An opaque pointer to the vccrypt_stream_context_t
 *                      structure.
 * \param input         A pointer to the plaintext input to decrypt.
 * \param size          The size of the plaintext input, in bytes.
 * \param output        The output buffer where data is written.  There must
 *                      be at least *offset + size bytes available in this
 *                      buffer.
 * \param offset        A pointer to the current offset in the buffer.  Will
 *                      be incremented by size.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int vccrypt_stream_mock_decrypt(
    void* options, void* context, const void* input, size_t size,
    void* output, size_t* offset)
{
    vccrypt_stream_options_t* stream_opts = (vccrypt_stream_options_t*)options;
    vccrypt_stream_context_t* stream_ctx = (vccrypt_stream_context_t*)context;

    stream_mock* mock = (stream_mock*)stream_opts->options_context;

    if (!mock->stream_decrypt_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return
            (*mock->stream_decrypt_mock)(
                stream_ctx, input, size, output, offset);
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
static int vccrypt_stream_mock_options_init(
    void* options, allocator_options_t* UNUSED(alloc_opts))
{
    vccrypt_stream_options_t* stream_opts = (vccrypt_stream_options_t*)options;

    stream_opts->options_context = new stream_mock;

    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure.
 *
 * \param options   the options structure to dispose.
 */
static void vccrypt_stream_mock_options_dispose(void* disp)
{
    vccrypt_stream_options_t* stream_opts = (vccrypt_stream_options_t*)disp;

    stream_mock* mock = (stream_mock*)stream_opts->options_context;
    delete mock;

    memset(stream_opts, 0, sizeof(vccrypt_stream_options_t));
}
