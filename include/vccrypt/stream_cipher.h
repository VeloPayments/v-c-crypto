/**
 * \file stream_cipher.h
 *
 * Stream Cipher.  The Stream Cipher interface provides an API by which data can
 * be encrypted using a stream cipher.  Stream ciphers use a short-term secret
 * and a 64-bit nonce to create a stream that can be used to encrypt up to
 * 2^64-1 bytes.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_STREAM_CIPHER_HEADER_GUARD
#define VCCRYPT_STREAM_CIPHER_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

#include <stdint.h>
#include <stdlib.h>
#include <vccrypt/buffer.h>
#include <vccrypt/interfaces.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/**
 * \defgroup STREAMAlgorithms Stream Cipher Algorithms.
 *
 * Algorithms optionally supported by the Stream Cipher subsystem.  Note that
 * the appropriate register method must be called during startup before using
 * one of these Stream Cipher algorithms to initialize a
 * vccrypt_stream_options_t structure. Registration is a link-time optimization
 * that ensures that only cryptographic primitives needed by the application are
 * linked in the application or library.
 *
 * @{
 */
#define VCCRYPT_STREAM_ALGORITHM_AES_256_CTR_FIPS 0x00000100
#define VCCRYPT_STREAM_ALGORITHM_AES_256_2X_CTR 0x00000200
#define VCCRYPT_STREAM_ALGORITHM_AES_256_3X_CTR 0x00000400
#define VCCRYPT_STREAM_ALGORITHM_AES_256_4X_CTR 0x00000800
/**
 * @}
 */

/**
 * \defgroup STREAMRegistration Registration functions for Stream Cipher
 *           Algorithms.
 * @{
 */
void vccrypt_stream_register_AES_256_CTR_FIPS();
void vccrypt_stream_register_AES_256_2X_CTR();
void vccrypt_stream_register_AES_256_3X_CTR();
void vccrypt_stream_register_AES_256_4X_CTR();
/**
 * @}
 */

/**
 * \brief Stream Cipher Options.
 *
 * These options are returned by the vccrypt_stream_options_init() method, which
 * can be used to select options for an appropriate stream cipher.
 * Alternatively, the vccrypt_suite_stream_options_init() method can be used to
 * select the appropriate stream cipher options for a given crypto suite.
 */
typedef struct vccrypt_stream_options
{
    /**
     * This options structure is disposable.
     */
    disposable_t hdr;

    /**
     * The allocation options to use.
     */
    allocator_options_t* alloc_opts;

    /**
     * The required key size in bytes.
     */
    size_t key_size;

    /**
     * The IV size in bytes.
     */
    size_t IV_size;

    /**
     * The maximum message size, in bytes.
     */
    size_t maximum_message_size;

    /**
     * Algorithm-specific initialization for stream cipher.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_stream_context_t structure.
     * \param key       The key to use for this instance.
     *
     * \returns 0 on success and non-zero on error.
     */
    int (*vccrypt_stream_alg_init)(
        void* options, void* context, vccrypt_buffer_t* key);

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
    int (*vccrypt_stream_alg_start_encryption)(
        void* options, void* context, const void* iv, size_t ivSize,
        void* output, size_t* offset);

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
    int (*vccrypt_stream_alg_start_decryption)(
        void* options, void* context, const void* input, size_t* offset);

    /**
     * Algorithm-specific disposal for stream cipher.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_stream_context_t structure.
     */
    void (*vccrypt_stream_alg_dispose)(void* options, void* context);

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
    int (*vccrypt_stream_alg_encrypt)(
        void* options, void* context, const void* input, size_t size,
        void* output, size_t* offset);

    /**
     * Decrypt data using the stream cipher.
     *
     * \param options       Opaque pointer to this options structure.
     * \param context       An opaque pointer to the vccrypt_stream_context_t
     *                      structure.
     * \param input         A pointer to the ciphertext input to decrypt.
     * \param size          The size of the ciphertext input, in bytes.
     * \param output        The output buffer where plaintext data is written.
     *                      There must be at least *offset + size bytes
     *                      available in this buffer.
     * \param offset        A pointer to the current offset in the buffer.  Will
     *                      be incremented by size.
     *
     * \returns 0 on success and non-zero on failure.
     */
    int (*vccrypt_stream_alg_decrypt)(
        void* options, void* context, const void* input, size_t size,
        void* output, size_t* offset);

} vccrypt_stream_options_t;

/**
 * Stream Cipher context.  This structure is used to hold the
 * algorithm-dependent Stream Cipher state used when encrypting or decrypting
 * data.
 */
typedef struct vccrypt_stream_context
{
    /**
     * This context is disposable.
     */
    disposable_t hdr;

    /**
     * The options to use for this context.
     */
    vccrypt_stream_options_t* options;

    /**
     * The opaque state structure used to store stream cipher state.
     */
    void* stream_state;

} vccrypt_stream_context_t;

/**
 * Initialize Stream Cipher options, looking up an appropriate Stream Cipher
 * algorithm registered in the abstract factory.  The options structure is owned
 * by the caller and must be disposed when no longer needed by calling
 * dispose().
 *
 * Note that the register method associated with the selected algorithm should
 * have been called during application or library initialization.  Otherwise,
 * the selected algorithm may not be linked to this executable.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options to use.
 * \param algorithm     The Stream Cipher algorithm to use.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_stream_options_init(
    vccrypt_stream_options_t* options, allocator_options_t* alloc_opts,
    uint32_t algorithm);

/**
 * Initialize a Stream Cipher algorithm instance with the given options and key.
 *
 * Note that the key length must correspond to a length appropriate for the
 * Stream Cipher algorithm.
 *
 * If initialization is successful, then this Stream Cipher algorithm instance
 * is owned by the caller and must be disposed by calling dispose() when no
 * longer needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The stream cipher instance to initialize.
 * \param key           The key to use for this algorithm instance.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_stream_init(
    vccrypt_stream_options_t* options, vccrypt_stream_context_t* context,
    vccrypt_buffer_t* key);

/**
 * Algorithm-specific start for the stream cipher encryption.  Initializes
 * output buffer with IV.
 *
 * \param context   Pointer to the stream cipher context.
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
int vccrypt_stream_start_encryption(
    vccrypt_stream_context_t* context, const void* iv, size_t ivSize,
    void* output, size_t* offset);

/**
 * Algorithm-specific start for the stream cipher decryption.  Reads IV from
 * input buffer.
 *
 * \param context   Pointer to stream cipher context.
 * \param input     The input buffer to read the IV from. Must be at least
 *                  IV_bytes in size.
 * \param offset    Pointer to the current offset of the buffer.  Will be
 *                  set to IV_bytes.  The value in this offset is ignored.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_stream_start_decryption(
    vccrypt_stream_context_t* context, const void* input, size_t* offset);

/**
 * Encrypt data using the stream cipher.
 *
 * \param context       The stream cipher context for this operation.
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
int vccrypt_stream_encrypt(
    vccrypt_stream_context_t* context, const void* input, size_t size,
    void* output, size_t* offset);

/**
 * Decrypt data using the stream cipher.
 *
 * \param context       The stream cipher context for this operation.
 * \param input         A pointer to the ciphertext input to decrypt.
 * \param size          The size of the ciphertext input, in bytes.
 * \param output        The output buffer where plaintext data is written.
 *                      There must be at least *offset + size bytes
 *                      available in this buffer.
 * \param offset        A pointer to the current offset in the buffer.  Will
 *                      be incremented by size.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_stream_decrypt(
    vccrypt_stream_context_t* context, const void* input, size_t size,
    void* output, size_t* offset);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_STREAM_CIPHER_HEADER_GUARD
