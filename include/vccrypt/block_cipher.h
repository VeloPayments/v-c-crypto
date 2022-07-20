/**
 * \file block_cipher.h
 *
 * \brief The Block Cipher interface provides an API by which blocks of data can
 * be encrypted using CBC (Cipher Block Chaining) mode.
 *
 * With a cryptographically random IV, it is possible to safely encrypt
 * short-term keys using long-term shared secrets, as long as both the IV and
 * the short-term keys are cryptographically random data, and the total key size
 * is a multiple of the block size.  For encrypting regular data, the stream
 * cipher mechanism is preferred.  This interface complements the stream cipher
 * when used as part of the cipher assembly interface.  The block cipher is used
 * to encrypt the short-term secret used in the cipher assembly for each of the
 * recipients.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_BLOCK_CIPHER_HEADER_GUARD
#define VCCRYPT_BLOCK_CIPHER_HEADER_GUARD

#include <stdbool.h>
#include <stdint.h>
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
 * \defgroup BLOCKAlgorithms Block Cipher Algorithms.
 *
 * \brief Algorithms optionally supported by the Block Cipher subsystem.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these Block Cipher algorithms to initialize a \brief
 * vccrypt_block_options_t structure. Registration is a link-time optimization
 * that ensures that only cryptographic primitives needed by the application are
 * linked in the application or library.
 *
 * @{
 */

/**
 * \brief Selector for AES-256-CBC FIPS mode.
 */
#define VCCRYPT_BLOCK_ALGORITHM_AES_256_CBC_FIPS 0x01000000

/**
 * \brief Selector for AES-256-CBC-2X mode.
 */
#define VCCRYPT_BLOCK_ALGORITHM_AES_256_2X_CBC 0x02000000

/**
 * \brief Selector for AES-256-CBC-3X mode.
 */
#define VCCRYPT_BLOCK_ALGORITHM_AES_256_3X_CBC 0x04000000

/**
 * \brief Selector for AES-256-CBC-4X mode.
 */
#define VCCRYPT_BLOCK_ALGORITHM_AES_256_4X_CBC 0x08000000
/**
 * @}
 */

/**
 * \defgroup BLOCKRegistration Registration functions for Block Cipher Algorithms.
 *
 * \brief An appropriate function in this group must be called before using the
 * associated block cipher functionality.
 *
 * This resolves linking of the dependent methods for a given block cipher
 * algorithm.
 * @{
 */

/**
 * \brief Register the AES-256-CBC-FIPS algorithm.
 */
void vccrypt_block_register_AES_256_CBC_FIPS();

/**
 * \brief Register the AES-256-CBC-2X algorithm.
 */
void vccrypt_block_register_AES_256_2X_CBC();

/**
 * \brief Register the AES-256-CBC-3X algorithm.
 */
void vccrypt_block_register_AES_256_3X_CBC();

/**
 * \brief Register the AES-256-CBC-4X algorithm.
 */
void vccrypt_block_register_AES_256_4X_CBC();
/**
 * @}
 */

/**
 * \brief These options are returned by the vccrypt_block_options_init() method,
 * which can be used to select options for an appropriate block cipher.
 *
 * Alternatively, the vccrypt_suite_block_init() method can be used to
 * select an appropriate block cipher instance for a given crypto suite.
 */
typedef struct vccrypt_block_options
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
     * \brief Algorithm-specific initialization for block cipher.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_block_context_t structure.
     * \param key       The key to use for this instance.
     * \param encrypt   Set to true if this is for encryption, and false for
     *                  decryption.
     *
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
     */
    int (*vccrypt_block_alg_init)(
        void* options, void* context, const vccrypt_buffer_t* key,
        bool encrypt);

    /**
     * \brief Algorithm-specific disposal for block cipher.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_block_context_t structure.
     */
    void (*vccrypt_block_alg_dispose)(void* options, void* context);

    /**
     * \brief Encrypt a single block of data using the block cipher.
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
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_block_alg_encrypt)(
        void* options, void* context, const void* iv, const void* input,
        void* output);

    /**
     * \brief Decrypt a single block of data using the block cipher.
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
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_block_alg_decrypt)(
        void* options, void* context, const void* iv, const void* input,
        void* output);

    /**
     * \brief Algorithm-specific data for a block cipher.
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
    int (*vccrypt_block_alg_options_init)(
        void* options, allocator_options_t* alloc_opts);

    /**
     * \brief Options level context pointer.
     */
    void* options_context;

} vccrypt_block_options_t;

/**
 * \brief This structure is used to hold the algorithm-dependent Block Cipher
 * state used when encrypting or decrypting data.
 */
typedef struct vccrypt_block_context
{
    /**
     * \brief This context is disposable.
     */
    disposable_t hdr;

    /**
     * \brief The options to use for this context.
     */
    vccrypt_block_options_t* options;

    /**
     * \brief The opaque state structure used to store block cipher state.
     */
    void* block_state;

} vccrypt_block_context_t;

/**
 * \brief Initialize Block Cipher options, looking up an appropriate Block
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
 * \param algorithm     The Block Cipher algorithm to use.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BLOCK_OPTIONS_INIT_MISSING_IMPL if the provided
 *             selector does not reference a valid implementation or if the
 *             implementation was not registered.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK vccrypt_block_options_init(
    vccrypt_block_options_t* options, allocator_options_t* alloc_opts,
    uint32_t algorithm);

/**
 * \brief Initialize a Block Cipher algorithm instance with the given options
 * and key.
 *
 * Note that the key length must correspond to a length appropriate for the
 * Block Cipher algorithm.
 *
 * If initialization is successful, then this Block Cipher algorithm instance
 * is owned by the caller and must be disposed by calling dispose() when no
 * longer needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The block cipher instance to initialize.
 * \param key           The key to use for this algorithm instance.
 * \param encrypt       Set to true if this is for encryption, and false for
 *                      decryption.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BLOCK_INIT_INVALID_ARG if an invalid argument is
 *             provided.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK vccrypt_block_init(
    vccrypt_block_options_t* options, vccrypt_block_context_t* context,
    const vccrypt_buffer_t* key, bool encrypt);

/**
 * \brief Encrypt a single block of data using the block cipher.
 *
 * \param context       The block cipher context to use.
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
 * \returns a status indicating succes or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK vccrypt_block_encrypt(
    vccrypt_block_context_t* context, const void* iv, const void* input,
    void* output);

/**
 * \brief Decrypt a single block of data using the block cipher.
 *
 * \param context       The block cipher context to use.
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
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK vccrypt_block_decrypt(
    vccrypt_block_context_t* context, const void* iv, const void* input,
    void* output);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_BLOCK_CIPHER_HEADER_GUARD
