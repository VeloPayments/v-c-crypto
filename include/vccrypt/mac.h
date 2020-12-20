/**
 * \file mac.h
 *
 * \brief The Message Authentication Code interface provides a method by which a
 * private key can be used to generate an authentication code that can be
 * verified by anyone in possession of that key.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_MAC_HEADER_GUARD
#define VCCRYPT_MAC_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <vccrypt/buffer.h>
#include <vccrypt/function_decl.h>
#include <vccrypt/interfaces.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/**
 * \defgroup MacConstants MAC Algorithm-specific constants.
 *
 * \brief These constants describe parameters for MAC algorithms.
 *
 * @{
 */

/**
 * \brief Key size for HMAC SHA-2 512/256.
 */
#define VCCRYPT_MAC_SHA_512_256_KEY_SIZE 32

/**
 * \brief MAC size for HMAC SHA-2 512/256.
 */
#define VCCRYPT_MAC_SHA_512_256_MAC_SIZE 32

/**
 * \brief Block size for HMAC SHA-2 512/256.
 */
#define VCCRYPT_MAC_SHA_512_256_BLOCK_SIZE 128

/**
 * \brief Key size for HMAC SHA-2 512/384.
 */
#define VCCRYPT_MAC_SHA_512_384_KEY_SIZE 48

/**
 * \brief MAC size for HMAC SHA-2 512/384.
 */
#define VCCRYPT_MAC_SHA_512_384_MAC_SIZE 48

/**
 * \brief Block size for HMAC SHA-2 512/384.
 */
#define VCCRYPT_MAC_SHA_512_384_BLOCK_SIZE 128

/**
 * \brief Key size for HMAC SHA-2 512.
 */
#define VCCRYPT_MAC_SHA_512_KEY_SIZE 64

/**
 * \brief MAC size for HMAC SHA-2 512.
 */
#define VCCRYPT_MAC_SHA_512_MAC_SIZE 64

/**
 * \brief Block size for HMAC SHA-2 512.
 */
#define VCCRYPT_MAC_SHA_512_BLOCK_SIZE 128
/**
 * @}
 */

/**
 * \defgroup MACAlgorithms Message Authentication Code Algorithms.
 *
 * \brief Algorithms optionally supported by the MAC subsystem.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these MAC algorithms to initialize a
 * vccrypt_mac_options_t structure. Registration is a link-time optimization
 * that ensures that only cryptographic primitives needed by the application are
 * linked in the application or library.
 *
 * @{
 */

/**
 * \brief Selector for HMAC SHA-2 256.
 */
#define VCCRYPT_MAC_ALGORITHM_SHA_2_256_HMAC 0x00000100

/**
 * \brief Selector for HMAC SHA-2 512/384.
 */
#define VCCRYPT_MAC_ALGORITHM_SHA_2_384_HMAC 0x00000200

/**
 * \brief Selector for HMAC SHA-2 512.
 */
#define VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC 0x00000400

/**
 * \brief Selector for HMAC SHA-2 512/224.
 */
#define VCCRYPT_MAC_ALGORITHM_SHA_2_512_224_HMAC 0x00000800

/**
 * \brief Selector for HMAC SHA-2 512/256.
 */
#define VCCRYPT_MAC_ALGORITHM_SHA_2_512_256_HMAC 0x00001000
/**
 * @}
 */

/**
 * \defgroup MACRegistration Registration functions for MAC Algorithms.
 *
 * \brief An appropriate function in this group must be called before using the
 * associated MAC functionality.
 *
 * This resolves linking of the dependent methods for a given MAC algorithm. 
 * @{
 */

/**
 * \brief Register the HMAC SHA-2 256 algorithm.
 */
void vccrypt_mac_register_SHA_2_256_HMAC();

/**
 * \brief Register the HMAC SHA-2 512/384 algorithm.
 */
void vccrypt_mac_register_SHA_2_384_HMAC();

/**
 * \brief Register the HMAC SHA-2 512 algorithm.
 */
void vccrypt_mac_register_SHA_2_512_HMAC();

/**
 * \brief Register the HMAC SHA-2 512/224 algorithm.
 */
void vccrypt_mac_register_SHA_2_512_224_HMAC();

/**
 * \brief Register the HMAC SHA-2 512/256 algorithm.
 */
void vccrypt_mac_register_SHA_2_512_256_HMAC();
/**
 * @}
 */

/**
 * \brief Message Authentication Code Options.
 *
 * These options are returned by the vccrypt_mac_options_init() method, which
 * can be used to select options for an appropriate message authentication code.
 * Alternately, the vccrypt_suite_mac_init() method can be used to select an
 * appropriate message authentication instance for a given crypto suite.
 */
typedef struct vccrypt_mac_options
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
     * \brief Does this MAC support key expansion?
     */
    bool key_expansion_supported;

    /**
     * \brief The MAC size in bytes.
     */
    size_t mac_size;

    /**
     * \brief The maximum message size, in bytes.
     */
    size_t maximum_message_size;

    /**
     * \brief Algorithm-specific initialization for MAC.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_mac_context_t structure.
     * \param key       The key to use for this instance.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
     */
    int (*vccrypt_mac_alg_init)(
        void* options, void* context, vccrypt_buffer_t* key);

    /**
     * \brief Algorithm-specific disposal for MAC.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_mac_context_t structure.
     */
    void (*vccrypt_mac_alg_dispose)(void* options, void* context);

    /**
     * \brief Digest data for the given MAC instance.
     *
     * \param context       An opaque pointer to the vccrypt_mac_context_t
     *                      structure.
     * \param data          A pointer to raw data to digest.
     * \param size          The size of the data to digest, in bytes.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_mac_alg_digest)(
        void* context, const uint8_t* data, size_t size);

    /**
     * \brief Finalize the message authentication code, copying the output data
     * to the given buffer.
     *
     * \param context       An opaque pointer to the vccrypt_mac_context_t
     *                      structure.
     * \param mac_buffer    The buffer to receive the MAC.  Must be large enough
     *                      for the given MAC algorithm.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_mac_alg_finalize)(
        void* context, vccrypt_buffer_t* mac_buffer);

    /**
     * \brief Implementation specific options init method.
     *
     * \param options       The options structure to initialize.
     * \param alloc_opts    The allocator options structure for this method.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_mac_alg_options_init)(
        void* options, allocator_options_t* alloc_opts);

    /**
     * \brief Options level context pointer.
     */
    void* options_context;

} vccrypt_mac_options_t;

/**
 * \brief MAC context.
 *
 * This structure is used to hold the algorithm-dependent MAC state used when
 * building the MAC.
 */
typedef struct vccrypt_mac_context
{
    /**
     * \brief This context is disposable.
     */
    disposable_t hdr;

    /**
     * \brief The options to use for this context.
     */
    vccrypt_mac_options_t* options;

    /**
     * \brief The opaque state structure used to store MAC state.
     */
    void* mac_state;

} vccrypt_mac_context_t;

/**
 * \brief Initialize MAC options, looking up an appropriate MAC algorithm
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
 * \param algorithm     The MAC algorithm to use.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_MAC_OPTIONS_INIT_MISSING_IMPL if the implementation
 *             is missing or was not registered. 
 *      - a non-zero return code on error.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_mac_options_init(
    vccrypt_mac_options_t* options, allocator_options_t* alloc_opts,
    uint32_t algorithm);

/**
 * \brief Initialize a MAC algorithm instance with the given options and key.
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
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_MAC_INIT_INVALID_ARG if an invalid argument is
 *             provided to this method.
 *      - a non-zero return code on error.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_mac_init(
    vccrypt_mac_options_t* options, vccrypt_mac_context_t* context,
    vccrypt_buffer_t* key);

/**
 * \brief Digest data for the given MAC instance.
 *
 * \param context       The MAC instance.
 * \param data          A pointer to raw data to digest.
 * \param size          The size of the data to digest, in bytes.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_MAC_DIGEST_INVALID_ARG if an invalid argument is
 *             provided.
 *      - a non-zero return code on error.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_mac_digest(
    vccrypt_mac_context_t* context, const uint8_t* data, size_t size);

/**
 * \brief Finalize the message authentication code, copying the output data to
 * the given buffer.
 *
 * \param context       The MAC instance.
 * \param mac_buffer    The buffer to receive the MAC.  Must be large enough for
 *                      the given MAC algorithm.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_MAC_FINALIZE_INVALID_ARG if an invalid argument is
 *             provided.
 *      - a non-zero return code on error.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_mac_finalize(
    vccrypt_mac_context_t* context, vccrypt_buffer_t* mac_buffer);

/**
 * \brief Get the disposable handle from a mac context.
 *
 * \param context       The mac context from which the disposable handle is
 *                      read.
 *
 * \returns the disposable handle for this mac context.
 */
inline disposable_t* vccrypt_mac_disposable_handle(
    vccrypt_mac_context_t* context)
{
    MODEL_ASSERT(prop_vccrypt_mac_context_valid(context));

    return &(context->hdr);
}

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_MAC_HEADER_GUARD
