/**
 * \file mac.h
 *
 * Message Authentication Codes.  The Message Authentication Code interface
 * provides a method by which a private key can be used to generate an
 * authentication code that can be verified by anyone in possession of that key.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_MAC_HEADER_GUARD
#define VCCRYPT_MAC_HEADER_GUARD

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
 * \defgroup MACAlgorithms Message Authentication Code Algorithms.
 *
 * Algorithms optionally supported by the MAC subsystem.  Note that the
 * appropriate register method must be called during startup before using one of
 * these MAC algorithms to initialize a vccrypt_mac_options_t structure.
 * Registration is a link-time optimization that ensures that only cryptographic
 * primitives needed by the application are linked in the application or
 * library.
 *
 * @{
 */
#define VCCRYPT_MAC_ALGORITHM_SHA_2_256_HMAC 0x00000100
#define VCCRYPT_MAC_ALGORITHM_SHA_2_384_HMAC 0x00000200
#define VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC 0x00000400
#define VCCRYPT_MAC_ALGORITHM_SHA_2_512_224_HMAC 0x00000800
#define VCCRYPT_MAC_ALGORITHM_SHA_2_512_256_HMAC 0x00001000
/**
 * @}
 */

/**
 * \defgroup MACRegistration Registration functions for MAC Algorithms.
 * @{
 */
void vccrypt_mac_register_SHA_2_256_HMAC();
void vccrypt_mac_register_SHA_2_384_HMAC();
void vccrypt_mac_register_SHA_2_512_HMAC();
void vccrypt_mac_register_SHA_2_512_224_HMAC();
void vccrypt_mac_register_SHA_2_512_256_HMAC();
/**
 * @}
 */

/**
 * \brief Message Authentication Code Options.
 *
 * These options are returned by the vccrypt_mac_options_init() method, which
 * can be used to select options for an appropriate message authentication code.
 * Alternately, the vccrypt_suite_mac_options_init() method can be used to
 * select the appropriate message authentication options for a given crypto
 * suite.
 */
typedef struct vccrypt_mac_options
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
     * Does this MAC support key expansion?
     */
    bool key_expansion_supported;

    /**
     * The MAC size in bytes.
     */
    size_t mac_size;

    /**
     * The maximum message size, in bytes.
     */
    size_t maximum_message_size;

    /**
     * Algorithm-specific initialization for MAC.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_mac_context_t structure.
     * \param key       The key to use for this instance.
     *
     * \returns 0 on success and non-zero on error.
     */
    int (*vccrypt_mac_alg_init)(
        void* options, void* context, vccrypt_buffer_t* key);

    /**
     * Algorithm-specific disposal for MAC.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_mac_context_t structure.
     */
    void (*vccrypt_mac_alg_dispose)(void* options, void* context);

    /**
     * Digest data for the given MAC instance.
     *
     * \param context       An opaque pointer to the vccrypt_mac_context_t
     *                      structure.
     * \param data          A pointer to raw data to digest.
     * \param size          The size of the data to digest, in bytes.
     *
     * \returns 0 on success and non-zero on failure.
     */
    int (*vccrypt_mac_alg_digest)(
        void* context, const uint8_t* data, size_t size);

    /**
     * Finalize the message authentication code, copying the output data to the
     * given buffer.
     *
     * \param context       An opaque pointer to the vccrypt_mac_context_t
     *                      structure.
     * \param mac_buffer    The buffer to receive the MAC.  Must be large enough
     *                      for the given MAC algorithm.
     *
     * \returns 0 on success and non-zero on failure.
     */
    int (*vccrypt_mac_alg_finalize)(
        void* context, vccrypt_buffer_t* mac_buffer);

} vccrypt_mac_options_t;

/**
 * MAC context.  This structure is used to hold the algorithm-dependent MAC
 * state used when building the MAC.
 */
typedef struct vccrypt_mac_context
{
    /**
     * This context is disposable.
     */
    disposable_t hdr;

    /**
     * The options to use for this context.
     */
    vccrypt_mac_options_t* options;

    /**
     * The opaque state structure used to store MAC state.
     */
    void* mac_state;

} vccrypt_mac_context_t;

/**
 * Initialize MAC options, looking up an appropriate MAC algorithm registered in
 * the abstract factory.  The options structure is owned by the caller and must
 * be disposed when no longer needed by calling dispose().
 *
 * Note that the register method associated with the selected algorithm should
 * have been called during application or library initialization.  Otherwise,
 * the selected algorithm may not be linked to this executable.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options to use.
 * \param algorithm     The MAC algorithm to use.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_mac_options_init(
    vccrypt_mac_options_t* options, allocator_options_t* alloc_opts,
    uint32_t algorithm);

/**
 * Initialize a MAC algorithm instance with the given options and key.
 *
 * Note that the key length must correspond to a length appropriate for the MAC
 * algorithm.  If the key length is not the correct length, an attempt will be
 * made to use the appropriate key expansion strategy if supported by the
 * algorithm.
 *
 * If initialization is successful, then this mac algorithm instance is owned by
 * the caller and must be disposed by calling dispose() when no longer needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The MAC instance to initialize.
 * \param key           The key to use for this algorithm instance.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_mac_init(
    vccrypt_mac_options_t* options, vccrypt_mac_context_t* context,
    vccrypt_buffer_t* key);

/**
 * Digest data for the given MAC instance.
 *
 * \param context       The MAC instance.
 * \param data          A pointer to raw data to digest.
 * \param size          The size of the data to digest, in bytes.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_mac_digest(
    vccrypt_mac_context_t* context, const uint8_t* data, size_t size);

/**
 * Finalize the message authentication code, copying the output data to the
 * given buffer.
 *
 * \param context       The MAC instance.
 * \param mac_buffer    The buffer to receive the MAC.  Must be large enough for
 *                      the given MAC algorithm.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_mac_finalize(
    vccrypt_mac_context_t* context, vccrypt_buffer_t* mac_buffer);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_MAC_HEADER_GUARD
