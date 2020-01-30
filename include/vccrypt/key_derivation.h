/**
 * \file key_derivation.h
 *
 * \brief Key Derivation Functions (KDFs) are used to produce keys from a
 * password or passphrase by using a pseudorandom function, typically a keyed
 * cryptographic hash such as HMAC.  A common use of KDFs is password
 * verification.
 *
 * \copyright 2019 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_KEY_DERIVATION_HEADER_GUARD
#define VCCRYPT_KEY_DERIVATION_HEADER_GUARD

#include <vccrypt/error_codes.h>
#include <vccrypt/buffer.h>
#include <vccrypt/function_decl.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus


/**
 * \brief Selector for PBKDF2
 */
#define VCCRYPT_KEY_DERIVATION_ALGORITHM_PBKDF2 0x00010000


/**
 * \defgroup KeyDerivationRegistration Registration functions for Key
 *  Derivation Algorithms.
 *
 * \brief An appropriate function from this group must be called before using
 * the associated key derivation functionality.
 *
 * This resolves linking of the dependent methods for a given key derivation
 * algorithm.
 * @{
 */

/**
 * \brief Register the PBKDF2 key derivation algorithm.
 * 
 */
void vccrypt_key_derivation_register_pbkdf2();


/* forward decls */
typedef struct vccrypt_key_derivation_options vccrypt_key_derivation_options_t;
typedef struct vccrypt_key_derivation_context vccrypt_key_derivation_context_t;

/**
 * \brief These options are returned by the
 * vccrypt_key_derivation_options_init() method.
 */
struct vccrypt_key_derivation_options
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
     * \brief The hmac algorithm to use for a PRF
     */
    uint32_t hmac_algorithm;

    /**
     * \brief The length of the digest produced by the hmac algorithm
     */
    size_t hmac_digest_length;

    /**
     * \brief Algorithm-specific initialization for key derivation.
     *
     * \param context   Pointer to the vccrypt_key_derivation_context_t
     *                  structure.
     * \param options   Pointer to this options structure.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
     */
    int (*vccrypt_key_derivation_alg_init)(
        vccrypt_key_derivation_context_t* context,
        vccrypt_key_derivation_options_t* options);

    /**
     * \brief Algorithm-specific disposal for key derivation.
     *
     * \param context   Pointer to the vccrypt_key_derivation_context_t
     *                  structure.
     * \param options   Pointer to this options structure.
     */
    void (*vccrypt_key_derivation_alg_dispose)(
        vccrypt_key_derivation_context_t* context,
        vccrypt_key_derivation_options_t* options);

    /**
     * \brief Derive a cryptographic key
     *
     * The key buffer is owned by the caller and must be disposed when no
     * longer needed by calling dispose().
     *
     * \param derived_key       A crypto buffer to receive the derived key.
     *                          The buffer should be the size of the desired 
     *                          key length.
     * \param context           Pointer to the
     *                          vccrypt_key_derivation_context_t structure.
     * \param pass              A buffer containing a password or passphrase
     * \param salt              A buffer containing a salt value
     * \param rounds            The number of rounds to process.  More rounds
     *                          increases randomness and computational cost.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
     */
    int (*vccrypt_key_derivation_alg_derive_key)(
        vccrypt_buffer_t* derived_key,
        vccrypt_key_derivation_context_t* context,
        const vccrypt_buffer_t* pass, const vccrypt_buffer_t* salt,
        unsigned int rounds);
};

/**
 * \brief This structure ... is not used for anything useful atm but is here
 * as a placeholder.
 */
struct vccrypt_key_derivation_context
{
    /**
     * \brief This context is disposable.
     */
    disposable_t hdr;

    /**
     * \brief The options to use for this context.
     */
    vccrypt_key_derivation_options_t* options;
};

/**
 * \brief Initialize key derivation options, looking up an appropriate key
 * derivation algorithm registered in the abstract factory.
 *
 * The options structure is owned by the caller and must be disposed when no
 * longer needed by calling dispose().
 *
 * Note that the register method associated with the selected algorithm should
 * have been called during application or library initialization.  Otherwise,
 * the selected algorithm may not be linked to this executable.
 *
 * \param options          The options structure to initialize.
 * \param alloc_opts       The allocator options to use.
 * \param kd_algorithm     The key derivation algorithm to use.
 * \param hmac_algorithm   The HMAC algorithm to use for the PRF.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_KEY_DERIVATION_OPTIONS_INIT_MISSING_IMPL if the
 *             provided instance selector is invalid or unregistered.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_key_derivation_options_init(
    vccrypt_key_derivation_options_t* options,
    allocator_options_t* alloc_opts, uint32_t kd_algorithm,
    uint32_t hmac_algorithm);

/**
 * \brief Initialize a key derivation algorithm instance with the given options.
 *
 * If initialization is successful, then this key derivation algorithm
 * instance is owned by the caller and must be disposed by calling dispose()
 * when no longer needed.
 *
 * \param context       The key derivation algorithm instance to initialize.
 * \param options       The options to use for this algorithm instance.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_KEY_DERIVATION_INIT_INVALID_ARG if one of the
 *             provided arguments is invalid.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_key_derivation_init(
    vccrypt_key_derivation_context_t* context,
    vccrypt_key_derivation_options_t* options);


/**
 * \brief Derive a cryptographic key
 *
 * The key buffer is owned by the caller and must be disposed when no
 * longer needed by calling dispose().
 *   
 * \param derived_key       A crypto buffer to receive the derived key.
 *                          The buffer should be the size of the desired 
 *                          key length.
 * \param context           The vccrypt_key_derivation_context_t instance to
 *                          use for this derivation
 * \param pass              A buffer containing a password or passphrase
 * \param salt              A buffer containing a salt value
 * \param rounds            The number of rounds to process.  More rounds
 *                          increases randomness and computational cost.
 *
 * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_key_derivation_derive_key(
    vccrypt_buffer_t* derived_key, vccrypt_key_derivation_context_t* context,
    const vccrypt_buffer_t* pass, const vccrypt_buffer_t* salt,
    unsigned int rounds);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_KEY_DERIVATION_HEADER_GUARD
