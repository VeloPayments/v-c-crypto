/**
 * \file digital_signature.h
 *
 * \brief The Digital Signature primitive provides a non-repudiation mechanism
 * in which any entity in possession of the public key of a signing entity can
 * verify an artifact signed by this signing entity.
 *
 * Signatures require a private key.  The public key is related to the private
 * key in such a way as it can be used to verify something signed by the private
 * key but cannot be used to either recover this private key or sign artifacts
 * itself.
 *
 * This interface requires access to a cryptographic random number generator,
 * but not all implementations of this interface will require a cryptographic
 * random number generator.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_DIGITAL_SIGNATURE_HEADER_GUARD
#define VCCRYPT_DIGITAL_SIGNATURE_HEADER_GUARD

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <vccrypt/buffer.h>
#include <vccrypt/error_codes.h>
#include <vccrypt/function_decl.h>
#include <vccrypt/hash.h>
#include <vccrypt/interfaces.h>
#include <vccrypt/prng.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup DigitalSignatureConstants Algorithm-specific constants.
 *
 * \brief These constants describe parameters for digital signature algorithms.
 *
 * @{
 */

/**
 * \brief Signature size for ed25519.
 */
#define VCCRYPT_DIGITAL_SIGNATURE_ED25519_SIGNATURE_SIZE 64

/**
 * \brief Private key size for ed25519.
 */
#define VCCRYPT_DIGITAL_SIGNATURE_ED25519_PRIVATE_KEY_SIZE 64

/**
 * \brief Public key size for ed25519.
 */
#define VCCRYPT_DIGITAL_SIGNATURE_ED25519_PUBLIC_KEY_SIZE 32
/**
 * @}
 */

/**
 * \defgroup DigitalSignatureAlgorithms Digital Signature Algorithms.
 *
 * \brief Algorithms optionally supported by the digital signature subsystem.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these algorithms to initialize a
 * \ref vccrypt_digital_signature_options_t structure.  Registration is a
 * link-time optimization that ensures that only cryptographic primitives needed
 * by the application are linked in the application or library.
 *
 * @{
 */

/**
 * \brief Selector for ed25519.
 */
#define VCCRYPT_DIGITAL_SIGNATURE_ALGORITHM_ED25519 0x00001000

/**
 * @}
 */

/**
 * \defgroup DigitalSignatureRegistration Registration functions for Digital Signature Algorithms.
 *
 * \brief An appropriate function from this group must be called before using
 * the associated digital signature functionality.
 *
 * This resolves linking of the dependent methods for a given digital signature
 * algorithm.
 * @{
 */

/**
 * \brief Register the ed25519 digital signature algorithm.
 */
void vccrypt_digital_signature_register_ed25519();

/**
 * @}
 */

/**
 * \brief These options are returned by the
 * vccrypt_digital_signature_options_init() method.
 */
typedef struct vccrypt_digital_signature_options
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
     * \brief The PRNG options to use.
     */
    vccrypt_prng_options_t* prng_opts;

    /**
     * \brief The hash algorithm needed for this options instance.
     */
    uint32_t hash_algorithm;

    /**
     * \brief The signature size in bytes.
     */
    size_t signature_size;

    /**
     * \brief The private key size in bytes.
     */
    size_t private_key_size;

    /**
     * \brief The public key size in bytes.
     */
    size_t public_key_size;

    /**
     * \brief Algorithm-specific initialization for digital signatures.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_digital_signature_context_t
     *                  structure.
     *
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
     */
    int (*vccrypt_digital_signature_alg_init)(void* options, void* context);

    /**
     * \brief Algorithm-specific disposal for digital signatures.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_digital_signature_context_t
     *                  structure.
     */
    void (*vccrypt_digital_signature_alg_dispose)(void* options, void* context);

    /**
     * \brief Sign a message, given a private key, a message, and a message
     * length.
     *
     * \param context       An opaque pointer to the
     *                      vccrypt_digital_signature_context_t structure.
     * \param sign_buffer   The buffer to receive the signature.  Must be large
     *                      enough for the given digital signature algorithm.
     * \param priv          The private key to use for the signature.
     * \param message       The input message.
     * \param size          The size of the message in bytes.
     *
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_digital_signature_alg_sign)(
        void* context, vccrypt_buffer_t* sign_buffer,
        const vccrypt_buffer_t* priv,
        const uint8_t* message, size_t size);

    /**
     * \brief Verify a message, given a public key, a message, and a message
     * length.
     *
     * \param context       An opaque pointer to the
     *                      vccrypt_digital_signature_context_t structure.
     * \param signature     The signature to verify.
     * \param pub           The public key to use for signature verification.
     * \param message       The input message.
     * \param size          The size of the message in bytes.
     *
     * \returns VCCRYPT_STATUS_SUCCESS if the message signature is valid, and
     * no-zero on error.
     */
    int (*vccrypt_digital_signature_alg_verify)(
        void* context, const vccrypt_buffer_t* signature,
        const vccrypt_buffer_t* pub,
        const uint8_t* message, size_t message_size);

    /**
     * \brief Create a keypair.
     *
     * The output buffers must be large enough to accept the resultant keys.
     *
     * \param context       An opaque pointer to the
     *                      vccrypt_digital_signature_context_t structure.
     * \param priv          The output buffer to receive the private key.
     * \param pub           The output buffer to receive the public key.
     *
     * \returns VCCRYPT_STATUS_SUCCESS if the message signature is valid, and
     * no-zero on error.
     */
    int (*vccrypt_digital_signature_alg_keypair_create)(
        void* context, vccrypt_buffer_t* priv, vccrypt_buffer_t* pub);

    /**
     * \brief Implementation specific options init method.
     *
     * \param options       The options structure to initialize.
     * \param alloc_opts    The allocator options structure for this method.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_digital_signature_alg_options_init)(
        void* options, allocator_options_t* alloc_opts);

    /**
     * \brief Options level context pointer.
     */
    void* options_context;

} vccrypt_digital_signature_options_t;

/**
 * \brief This structure is used to hold the algorithm-dependent digital
 * signature state used when building the signature.
 */
typedef struct vccrypt_digital_signature_context
{
    /**
     * \brief This context is disposable.
     */
    disposable_t hdr;

    /**
     * \brief The options to use for this context.
     */
    vccrypt_digital_signature_options_t* options;

    /**
     * \brief The hash options to use.
     */
    vccrypt_hash_options_t hash_opts;

    /**
     * \brief The opaque state structure used to store digital signature state.
     */
    void* digital_signature_state;

} vccrypt_digital_signature_context_t;

/**
 * \brief Initialize digital signature options, looking up an appropriate
 * digital signature algorithm registered in the abstract factory.
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
 * \param prng_opts     The PRNG to use for this algorithm.  MUST BE COMPATIBLE
 *                      WITH THIS ALGORITHM.
 * \param algorithm     The digital signature algorithm to use.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_DIGITAL_SIGNATURE_OPTIONS_INIT_MISSING_IMPL if the
 *             provided instance selector is invalid or unregistered.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_digital_signature_options_init(
    vccrypt_digital_signature_options_t* options,
    allocator_options_t* alloc_opts, vccrypt_prng_options_t* prng_opts,
    uint32_t algorithm);

/**
 * \brief Initialize a digital signature instance with the given options.
 *
 * If initialization is successful, then this digital signature algorithm
 * instance is owned by the caller and must be disposed by calling dispose()
 * when no longer needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The digital signature instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_DIGITAL_SIGNATURE_INIT_INVALID_ARG if one of the
 *             provided arguments is invalid.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_digital_signature_init(
    vccrypt_digital_signature_options_t* options,
    vccrypt_digital_signature_context_t* context);

/**
 * \brief Sign a message, given a private key, a message, and a message length.
 *
 * \param context       An opaque pointer to the
 *                      vccrypt_digital_signature_context_t structure.
 * \param sign_buffer   The buffer to receive the signature.  Must be large
 *                      enough for the given digital signature algorithm.
 * \param priv          The private key to use for the signature.
 * \param message       The input message.
 * \param size          The size of the message in bytes.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_digital_signature_sign(
    vccrypt_digital_signature_context_t* context, vccrypt_buffer_t* sign_buffer,
    const vccrypt_buffer_t* priv, const uint8_t* message, size_t message_size);

/**
 * \brief Verify a message, given a public key, a message, and a message length.
 *
 * \param context       An opaque pointer to the
 *                      vccrypt_digital_signature_context_t structure.
 * \param signature     The signature to verify.
 * \param pub           The public key to use for signature verification.
 * \param message       The input message.
 * \param size          The size of the message in bytes.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_digital_signature_verify(
    vccrypt_digital_signature_context_t* context,
    const vccrypt_buffer_t* signature, const vccrypt_buffer_t* pub,
    const uint8_t* message, size_t message_size);

/**
 * \brief Create a keypair.
 *
 * The output buffers must be large enough to accept the resultant keys.
 *
 * \param context       An opaque pointer to the
 *                      vccrypt_digital_signature_context_t structure.
 * \param priv          The output buffer to receive the private key.
 * \param pub           The output buffer to receive the public key.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_digital_signature_keypair_create(
    vccrypt_digital_signature_context_t* context, vccrypt_buffer_t* priv,
    vccrypt_buffer_t* pub);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_DIGITAL_SIGNATURE_HEADER_GUARD
