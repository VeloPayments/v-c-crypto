/**
 * \file hash.h
 *
 * Cryptographic Hash Functions.  The Cryptographic Hash Function interface
 * provides a method by which a value can be mapped to a number that is hard to
 * predict based on input, has high collision resistance, and in which a small
 * change to the input value results in a large and unpredictible change to the
 * output value.
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
#include <vccrypt/interfaces.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/**
 * \defgroup HashAlgorithms Cryptographic Hash Algorithms.
 *
 * Algorithms optionally supported by the hash subsystem.  Note that the
 * appropriate register method must be called during startup before using one of
 * these hash algorithms to initialize a vccrypt_hash_options_t structure.
 * Registration is a link-time optimization that ensures that only cryptographic
 * primitives needed by the application are linked in the application or
 * library.
 *
 * @{
 */
#define VCCRYPT_HASH_ALGORITHM_SHA_2_256 0x00000100
#define VCCRYPT_HASH_ALGORITHM_SHA_2_384 0x00000200
#define VCCRYPT_HASH_ALGORITHM_SHA_2_512 0x00000400
#define VCCRYPT_HASH_ALGORITHM_SHA_2_512_224 0x00000800
#define VCCRYPT_HASH_ALGORITHM_SHA_2_512_256 0x00001000
/**
 * @}
 */

/**
 * \defgroup HashRegistration Registration functions for Hash Algorithms.
 * @{
 */
void vccrypt_hash_register_SHA_2_256();
void vccrypt_hash_register_SHA_2_384();
void vccrypt_hash_register_SHA_2_512();
void vccrypt_hash_register_SHA_2_512_224();
void vccrypt_hash_register_SHA_2_512_256();
/**
 * @}
 */

/**
 * \brief Cryptographic Hash Options.
 *
 * These options are returned by the vccrypt_hash_options_init() method, which
 * can be used to select options for an appropriate message authentication code.
 * Alternately, the vccrypt_suite_hash_options_init() method can be used to
 * select the appropriate message authentication options for a given crypto
 * suite.
 */
typedef struct vccrypt_hash_options
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
     * The hash size in bytes.
     */
    size_t hash_size;

    /**
     * The hash block size in bytes.
     */
    size_t hash_block_size;

    /**
     * Algorithm-specific initialization for hash.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_hash_context_t structure.
     *
     * \returns 0 on success and non-zero on error.
     */
    int (*vccrypt_hash_alg_init)(void* options, void* context);

    /**
     * Algorithm-specific disposal for hash.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_hash_context_t structure.
     */
    void (*vccrypt_hash_alg_dispose)(void* options, void* context);

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
    int (*vccrypt_hash_alg_digest)(
        void* context, const uint8_t* data, size_t size);

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
    int (*vccrypt_hash_alg_finalize)(
        void* context, vccrypt_buffer_t* hash_buffer);

} vccrypt_hash_options_t;

/**
 * Hash context.  This structure is used to hold the algorithm-dependent hash
 * state used when building the hash.
 */
typedef struct vccrypt_hash_context
{
    /**
     * This context is disposable.
     */
    disposable_t hdr;

    /**
     * The options to use for this context.
     */
    vccrypt_hash_options_t* options;

    /**
     * The opaque state structure used to store hash state.
     */
    void* hash_state;

} vccrypt_hash_context_t;

/**
 * Initialize hash options, looking up an appropriate hash algorithm registered
 * in the abstract factory.  The options structure is owned by the caller and
 * must be disposed when no longer needed by calling dispose().
 *
 * Note that the register method associated with the selected algorithm should
 * have been called during application or library initialization.  Otherwise,
 * the selected algorithm may not be linked to this executable.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options to use.
 * \param algorithm     The hash algorithm to use.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_hash_options_init(
    vccrypt_hash_options_t* options, allocator_options_t* alloc_opts,
    uint32_t algorithm);

/**
 * Initialize a hash algorithm instance with the given options.
 *
 * If initialization is successful, then this hash algorithm instance is owned
 * by the caller and must be disposed by calling dispose() when no longer
 * needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The hash instance to initialize.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_hash_init(
    vccrypt_hash_options_t* options, vccrypt_hash_context_t* context);

/**
 * Digest data for the given hash instance.
 *
 * \param context       The hash instance.
 * \param data          A pointer to raw data to digest.
 * \param size          The size of the data to digest, in bytes.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_hash_digest(
    vccrypt_hash_context_t* context, const uint8_t* data, size_t size);

/**
 * Finalize the hash, copying the output data to the given buffer.
 *
 * \param context       The hash instance.
 * \param hash_buffer   The buffer to receive the hash.  Must be large enough
 *                      for the given hash algorithm.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_hash_finalize(
    vccrypt_hash_context_t* context, vccrypt_buffer_t* hash_buffer);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_HASH_HEADER_GUARD
