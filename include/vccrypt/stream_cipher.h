/**
 * \file stream_cipher.h
 *
 * \brief The Stream Cipher interface provides an API by which data can be
 * encrypted using a stream cipher.
 *
 * Stream ciphers use a short-term secret and a 64-bit nonce to create a stream
 * that can be used to encrypt up to 2^64-1 bytes.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_STREAM_CIPHER_HEADER_GUARD
#define VCCRYPT_STREAM_CIPHER_HEADER_GUARD

#include <stdint.h>
#include <stdlib.h>
#include <vccrypt/buffer.h>
#include <vccrypt/error_codes.h>
#include <vccrypt/function_decl.h>
#include <vccrypt/interfaces.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup STREAMAlgorithms Stream Cipher Algorithms.
 *
 * \brief Algorithms optionally supported by the Stream Cipher subsystem.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these Stream Cipher algorithms to initialize a
 * vccrypt_stream_options_t structure. Registration is a link-time optimization
 * that ensures that only cryptographic primitives needed by the application are
 * linked in the application or library.
 *
 * @{
 */

/**
 * \brief Selector for AES-256-CTR FIPS mode.
 */
#define VCCRYPT_STREAM_ALGORITHM_AES_256_CTR_FIPS 0x00000100

/**
 * \brief Selector for AES-256-CTR-2X mode.
 */
#define VCCRYPT_STREAM_ALGORITHM_AES_256_2X_CTR 0x00000200

/**
 * \brief Selector for AES-256-CTR-3X mode.
 */
#define VCCRYPT_STREAM_ALGORITHM_AES_256_3X_CTR 0x00000400

/**
 * \brief Selector for AES-256-CTR-4X mode.
 */
#define VCCRYPT_STREAM_ALGORITHM_AES_256_4X_CTR 0x00000800
/**
 * @}
 */

/**
 * \defgroup STREAMRegistration Registration functions for Stream Cipher Algorithms.
 *
 * \brief An appropriate function in this group must be called before using the
 * associated stream cipher functionality.
 *
 * This resolves linking of the dependent methods for a given stream cipher
 * algorithm.
 * @{
 */

/**
 * \brief Register the AES-256-CTR-FIPS algorithm.
 */
void vccrypt_stream_register_AES_256_CTR_FIPS();

/**
 * \brief Register the AES-256-CTR-2X algorithm.
 */
void vccrypt_stream_register_AES_256_2X_CTR();

/**
 * \brief Register the AES-256-CTR-3X algorithm.
 */
void vccrypt_stream_register_AES_256_3X_CTR();

/**
 * \brief Register the AES-256-CTR-4X algorithm.
 */
void vccrypt_stream_register_AES_256_4X_CTR();
/**
 * @}
 */

/**
 * \brief These options are returned by the vccrypt_stream_options_init()
 * method, which can be used to select options for an appropriate stream cipher.
 * 
 * Alternatively, the vccrypt_suite_stream_options_init() method can be used to
 * select the appropriate stream cipher options for a given crypto suite.
 */
typedef struct vccrypt_stream_options
{
    /**
     * \brief This options structure is disposable.
     */
    disposable_t hdr;

    /**
     * \brief The allocation options to use.
     */
    allocator_options_t* alloc_opts;

    /**
     * \brief The required key size in bytes.
     */
    size_t key_size;

    /**
     * \brief The IV size in bytes.
     */
    size_t IV_size;

    /**
     * \brief The maximum message size, in bytes.
     */
    uint64_t maximum_message_size;

    /**
     * \brief Algorithm-specific initialization for stream cipher.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_stream_context_t structure.
     * \param key       The key to use for this instance.
     *
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
     */
    int (*vccrypt_stream_alg_init)(
        void* options, void* context, const vccrypt_buffer_t* key);

    /**
     * \brief Algorithm-specific disposal for stream cipher.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_stream_context_t structure.
     */
    void (*vccrypt_stream_alg_dispose)(void* options, void* context);

    /**
     * \brief Algorithm-specific start for the stream cipher encryption.
     * Initializes output buffer with IV.
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
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
     */
    int (*vccrypt_stream_alg_start_encryption)(
        void* options, void* context, const void* iv, size_t ivSize,
        void* output, size_t* offset);

    /**
     * \brief Algorithm-specific continuation of the stream cipher encryption.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Pointer to the stream cipher context.
     * \param iv        The IV to use for this instance.  MUST ONLY BE USED ONCE
     *                  PER KEY, EVER.
     * \param ivSize    The size of the IV in bytes.
     * \param offset    The current offset of the buffer.  
     *
     * \returns a status indicating success or failure.
     *      - \ref VCCRYPT_STATUS_SUCCESS on success.
     *      - a non-zero error code on failure.
     */
    int (*vccrypt_stream_alg_continue_encryption)(
        void* options, void* context, const void* iv, size_t ivSize,
        size_t offset);

    /**
     * \brief Algorithm-specific start for the stream cipher decryption.  Reads
     * IV from input buffer.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_stream_context_t structure.
     * \param input     The input buffer to read the IV from. Must be at least
     *                  IV_bytes in size.
     * \param offset    Pointer to the current offset of the buffer.  Will be
     *                  set to IV_bytes.  The value in this offset is ignored.
     *
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
     */
    int (*vccrypt_stream_alg_start_decryption)(
        void* options, void* context, const void* input, size_t* offset);

    /**
     * \brief Algorithm-specific continuation of the stream cipher decryption.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Pointer to the stream cipher context.
     * \param iv        The IV to use for this instance.  MUST ONLY BE USED ONCE
     *                  PER KEY, EVER.
     * \param ivSize    The size of the IV in bytes.
     * \param offset    The current offset of the buffer.
     *
     * \returns a status indicating success or failure.
     *      - \ref VCCRYPT_STATUS_SUCCESS on success.
     *      - a non-zero error code on failure.
     */
    int (*vccrypt_stream_alg_continue_decryption)(
        void* options, void* context, const void* iv, size_t ivSize, size_t offset);

    /**
     * \brief Encrypt data using the stream cipher.
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
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_stream_alg_encrypt)(
        void* options, void* context, const void* input, size_t size,
        void* output, size_t* offset);

    /**
     * \brief Decrypt data using the stream cipher.
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
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_stream_alg_decrypt)(
        void* options, void* context, const void* input, size_t size,
        void* output, size_t* offset);

    /**
     * \brief Algorithm-specific data.
     */
    void* data;

    /**
     * \brief Implementation specific options init method.
     *
     * \param options       The options structure to initialize.
     * \param alloc_opts    The allocator options structure for this method.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_stream_alg_options_init)(
        void* options, allocator_options_t* alloc_opts);

    /**
     * \brief Options level context pointer.
     */
    void* options_context;

} vccrypt_stream_options_t;

/**
 * \brief This structure is used to hold the algorithm-dependent Stream Cipher
 * state used when encrypting or decrypting data.
 */
typedef struct vccrypt_stream_context
{
    /**
     * \brief This context is disposable.
     */
    disposable_t hdr;

    /**
     * \brief The options to use for this context.
     */
    vccrypt_stream_options_t* options;

    /**
     * \brief The opaque state structure used to store stream cipher state.
     */
    void* stream_state;

} vccrypt_stream_context_t;

/**
 * \brief Initialize Stream Cipher options, looking up an appropriate Stream
 * Cipher algorithm registered in the abstract factory.
 *
 * The options structure is owned by the caller and must be disposed when no
 * longer needed by calling dispose().
 *
 * Note that the register method associated with the selected algorithm should
 * have been called during application or library initialization.  Otherwise,
 * the selected algorithm may not be linked to this executable.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options to use.
 * \param algorithm     The Stream Cipher algorithm to use.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_STREAM_OPTIONS_INIT_MISSING_IMPL if the provided
 *             implementation selector is invalid or if the implementation has
 *             not been registered.
 *      - a non-zero error code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_stream_options_init(
    vccrypt_stream_options_t* options, allocator_options_t* alloc_opts,
    uint32_t algorithm);

/**
 * \brief Initialize a Stream Cipher algorithm instance with the given options
 * and key.
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
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_STREAM_INIT_INVALID_ARG if one of the provided
 *             arguments is invalid.
 *      - a non-zero error code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_stream_init(
    vccrypt_stream_options_t* options, vccrypt_stream_context_t* context,
    vccrypt_buffer_t* key);

/**
 * \brief Algorithm-specific start for the stream cipher encryption.
 * Initializes output buffer with IV.
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
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_stream_start_encryption(
    vccrypt_stream_context_t* context, const void* iv, size_t ivSize,
    void* output, size_t* offset);

/**
 * \brief Algorithm-specific continuation of the stream cipher encryption.
 *
 * \param context   Pointer to the stream cipher context.
 * \param iv        The IV to use for this instance.  MUST ONLY BE USED ONCE
 *                  PER KEY, EVER.
 * \param ivSize    The size of the IV in bytes.
 * \param offset    The current offset of the buffer.  
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_stream_continue_encryption(
    vccrypt_stream_context_t* context, const void* iv, size_t ivSize,
    size_t offset);

/**
 * \brief Algorithm-specific start for the stream cipher decryption.  Reads IV
 * from input buffer.
 *
 * \param context   Pointer to stream cipher context.
 * \param input     The input buffer to read the IV from. Must be at least
 *                  IV_bytes in size.
 * \param offset    Pointer to the current offset of the buffer.  Will be
 *                  set to IV_bytes.  The value in this offset is ignored.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_stream_start_decryption(
    vccrypt_stream_context_t* context, const void* input, size_t* offset);


/**
 * \brief Algorithm-specific continuation for the stream cipher decryption.
 *
 * \param context       Opaque pointer to vccrypt_stream_context_t structure.
 * \param input_offset  Current offset of the input buffer.
 *
 * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_stream_continue_decryption(
    vccrypt_stream_context_t* context, const void* iv, size_t iv_size,
    size_t input_offset);

/**
 * \brief Encrypt data using the stream cipher.
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
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_stream_encrypt(
    vccrypt_stream_context_t* context, const void* input, size_t size,
    void* output, size_t* offset);

/**
 * \brief Decrypt data using the stream cipher.
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
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_stream_decrypt(
    vccrypt_stream_context_t* context, const void* input, size_t size,
    void* output, size_t* offset);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_STREAM_CIPHER_HEADER_GUARD
