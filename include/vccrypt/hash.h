/**
 * \file hash.h
 *
 * \brief The Cryptographic Hash Function interface provides a method by which a
 * value can be mapped to a number that is hard to predict based on input, has
 * high collision resistance, and in which a small change to the input value
 * results in a large and unpredictible change to the output value.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_HASH_HEADER_GUARD
#define VCCRYPT_HASH_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <vccrypt/buffer.h>
#include <vccrypt/function_decl.h>
#include <vccrypt/interfaces.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/**
 * \defgroup HashConstants Algorithm-specific constants.
 *
 * \brief These constants describe parameters for hash algorithms.
 *
 * @{
 */

/**
 * \brief Digest size for SHA-2 512/256.
 */
#define VCCRYPT_HASH_SHA_512_256_DIGEST_SIZE 32

/**
 * \brief Block size for SHA-2 512/256.
 */
#define VCCRYPT_HASH_SHA_512_256_BLOCK_SIZE 128

/**
 * \brief Digest size for SHA-2 512/384.
 */
#define VCCRYPT_HASH_SHA_512_384_DIGEST_SIZE 48

/**
 * \brief Block size for SHA-2 512/384.
 */
#define VCCRYPT_HASH_SHA_512_384_BLOCK_SIZE 128

/**
 * \brief Digest size for SHA-2 512.
 */
#define VCCRYPT_HASH_SHA_512_DIGEST_SIZE 64

/**
 * \brief Block size for SHA-2 512.
 */
#define VCCRYPT_HASH_SHA_512_BLOCK_SIZE 128
/**
 * @}
 */

/**
 * \defgroup HashAlgorithms Cryptographic Hash Algorithms.
 *
 * \brief Algorithms optionally supported by the hash subsystem.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these hash algorithms to initialize a \ref
 * vccrypt_hash_options_t structure.  Registration is a link-time optimization
 * that ensures that only cryptographic primitives needed by the application are
 * linked in the application or library.
 *
 * @{
 */

/**
 * \brief Selector for SHA-2 256.
 */
#define VCCRYPT_HASH_ALGORITHM_SHA_2_256 0x00000100

/**
 * \brief Selector for SHA-2 512/384.
 */
#define VCCRYPT_HASH_ALGORITHM_SHA_2_384 0x00000200

/**
 * \brief Selector for SHA-2 512.
 */
#define VCCRYPT_HASH_ALGORITHM_SHA_2_512 0x00000400

/**
 * \brief Selector for SHA-2 512/224.
 */
#define VCCRYPT_HASH_ALGORITHM_SHA_2_512_224 0x00000800

/**
 * \brief Selector for SHA-2 512/256.
 */
#define VCCRYPT_HASH_ALGORITHM_SHA_2_512_256 0x00001000
/**
 * @}
 */

/**
 * \defgroup HashRegistration Registration functions for Hash Algorithms.
 *
 * \brief An appropriate function in this group must be called before using the
 * associated hash functionality.
 *
 * This resolves linking of the dependent methods for a given hash algorithm.
 * @{
 */

/**
 * \brief Register the SHA-2 256 algorithm.
 */
void vccrypt_hash_register_SHA_2_256();

/**
 * \brief Register the SHA-2 512/384 algorithm.
 */
void vccrypt_hash_register_SHA_2_384();

/**
 * \brief Register the SHA-2 512 algorithm.
 */
void vccrypt_hash_register_SHA_2_512();

/**
 * \brief Register the SHA-2 512/224 algorithm.
 */
void vccrypt_hash_register_SHA_2_512_224();

/**
 * \brief Register the SHA-2 512/256 algorithm.
 */
void vccrypt_hash_register_SHA_2_512_256();
/**
 * @}
 */

/**
 * \brief These options are returned by the vccrypt_hash_options_init() method,
 * which can be used to select options for an appropriate message authentication
 * code.
 *
 * Alternately, the vccrypt_suite_hash_init() method can be used to select an
 * appropriate hash instancefor a given crypto suite.
 */
typedef struct vccrypt_hash_options
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
     * \brief The hash size in bytes.
     */
    size_t hash_size;

    /**
     * \brief The hash block size in bytes.
     */
    size_t hash_block_size;

    /**
     * \brief Algorithm-specific initialization for hash.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_hash_context_t structure.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
     */
    int (*vccrypt_hash_alg_init)(void* options, void* context);

    /**
     * \brief Algorithm-specific disposal for hash.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_hash_context_t structure.
     */
    void (*vccrypt_hash_alg_dispose)(void* options, void* context);

    /**
     * \brief Digest data for the given hash instance.
     *
     * \param context       An opaque pointer to the vccrypt_hash_context_t
     *                      structure.
     * \param data          A pointer to raw data to digest.
     * \param size          The size of the data to digest, in bytes.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_hash_alg_digest)(
        void* context, const uint8_t* data, size_t size);

    /**
     * \brief Finalize the hash, copying the output data to the given buffer.
     *
     * \param context       An opaque pointer to the vccrypt_hash_context_t
     *                      structure.
     * \param hash_buffer   The buffer to receive the hash.  Must be large
     *                      enough for the given hash algorithm.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_hash_alg_finalize)(
        void* context, vccrypt_buffer_t* hash_buffer);

} vccrypt_hash_options_t;

/**
 * \brief This structure is used to hold the algorithm-dependent hash state used
 * when building the hash.
 */
typedef struct vccrypt_hash_context
{
    /**
     * \brief This context is disposable.
     */
    disposable_t hdr;

    /**
     * \brief The options to use for this context.
     */
    vccrypt_hash_options_t* options;

    /**
     * \brief The opaque state structure used to store hash state.
     */
    void* hash_state;

} vccrypt_hash_context_t;

/**
 * \brief Initialize hash options, looking up an appropriate hash algorithm
 * registered in the abstract factory.
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
 * \param algorithm     The hash algorithm to use.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_HASH_OPTIONS_INIT_MISSING_IMPL if the requested
 *             implementation either does not exist or was not registered.
 *      - a non-zero error code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_hash_options_init(
    vccrypt_hash_options_t* options, allocator_options_t* alloc_opts,
    uint32_t algorithm);

/**
 * \brief Initialize a hash algorithm instance with the given options.
 *
 * If initialization is successful, then this hash algorithm instance is owned
 * by the caller and must be disposed by calling dispose() when no longer
 * needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The hash instance to initialize.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_HASH_INIT_INVALID_ARG if an invalid argument is
 *             provided.
 *      - a non-zero error code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_hash_init(
    vccrypt_hash_options_t* options, vccrypt_hash_context_t* context);

/**
 * \brief Digest data for the given hash instance.
 *
 * \param context       The hash instance.
 * \param data          A pointer to raw data to digest.
 * \param size          The size of the data to digest, in bytes.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_HASH_DIGEST_INVALID_ARG if an invalid argument is
 *             provided.
 *      - a non-zero error code.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_hash_digest(
    vccrypt_hash_context_t* context, const uint8_t* data, size_t size);

/**
 * \brief Finalize the hash, copying the output data to the given buffer.
 *
 * \param context       The hash instance.
 * \param hash_buffer   The buffer to receive the hash.  Must be large enough
 *                      for the given hash algorithm.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_HASH_DIGEST_INVALID_ARG if an invalid argument is
 *             provided.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_hash_finalize(
    vccrypt_hash_context_t* context, vccrypt_buffer_t* hash_buffer);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_HASH_HEADER_GUARD
