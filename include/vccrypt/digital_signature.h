/**
 * \file digital_signature.h
 *
 * Digital Signatures.  The Digital Signature primitive provides a
 * non-repudiation mechanism in which any entity in possession of the public key
 * of a signing entity can verify an artifact signed by this signing entity.
 * Signatures require a private key.  The public key is related to the private
 * key in such a way as it can be used to verify something signed by the private
 * key but cannot be used to either recover this private key or sign artifacts
 * itself.
 *
 * This interface requires access to a cryptographic random number generator,
 * but not all implementations of this interface will require a cryptographic
 * random number generator.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_DIGITAL_SIGNATURE_HEADER_GUARD
#define VCCRYPT_DIGITAL_SIGNATURE_HEADER_GUARD

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <vccrypt/buffer.h>
#include <vccrypt/error_codes.h>
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
 * @{
 */
#define VCCRYPT_DIGITAL_SIGNATURE_ED25519_SIGNATURE_SIZE 64
#define VCCRYPT_DIGITAL_SIGNATURE_ED25519_PRIVATE_KEY_SIZE 64
#define VCCRYPT_DIGITAL_SIGNATURE_ED25519_PUBLIC_KEY_SIZE 32
/**
 * @}
 */

/**
 * \defgroup DigitalSignatureAlgorithms Digital Signature Algorithms.
 *
 * Algorithms optionally supported by the digital signature subsystem.
 * Note that the appropriate register method must be called during startup
 * before using one of these algorithms to initialize a
 * vccrypt_digital_signature_options_t structure.  Registration is a link-time
 * optimization that ensures that only cryptographic primitives needed by the
 * application are linked in the application or library.
 *
 * @{
 */
#define VCCRYPT_DIGITAL_SIGNATURE_ALGORITHM_ED25519 0x00001000

/**
 * @}
 */

/**
 * \defgroup DigitalSignatureRegistration Registration functions for Digital
 * Signature Algorithms.
 * @{
 */
void vccrypt_digital_signature_register_ed25519();

/**
 * @}
 */

/**
 * \brief Digital Signature Options.
 *
 * These options are returned by the vccrypt_digital_signature_options_init()
 * method.
 */
typedef struct vccrypt_digital_signature_options
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
     * The PRNG options to use.
     */
    vccrypt_prng_options_t* prng_opts;

    /**
     * The hash algorithm needed for this options instance.
     */
    uint32_t hash_algorithm;

    /**
     * The signature size in bytes.
     */
    size_t signature_size;

    /**
     * The private key size in bytes.
     */
    size_t private_key_size;

    /**
     * The public key size in bytes.
     */
    size_t public_key_size;

    /**
     * Algorithm-specific initialization for digital signatures.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_digital_signature_context_t
     *                  structure.
     *
     * \returns 0 on success and non-zero on error.
     */
    int (*vccrypt_digital_signature_alg_init)(void* options, void* context);

    /**
     * Algorithm-specific disposal for digital signatures.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to vccrypt_digital_signature_context_t
     *                  structure.
     */
    void (*vccrypt_digital_signature_alg_dispose)(void* options, void* context);

    /**
     * Sign a message, given a private key, a message, and a message length.
     *
     * \param context       An opaque pointer to the
     *                      vccrypt_digital_signature_context_t structure.
     * \param sign_buffer   The buffer to receive the signature.  Must be large
     *                      enough for the given digital signature algorithm.
     * \param priv          The private key to use for the signature.
     * \param message       The input message.
     * \param size          The size of the message in bytes.
     *
     * \returns 0 on success and 1 on failure.
     */
    int (*vccrypt_digital_signature_alg_sign)(
        void* context, vccrypt_buffer_t* sign_buffer,
        const vccrypt_buffer_t* priv,
        const uint8_t* message, size_t size);

    /**
     * Verify a message, given a public key, a message, and a message length.
     *
     * \param context       An opaque pointer to the
     *                      vccrypt_digital_signature_context_t structure.
     * \param signature     The signature to verify.
     * \param pub           The public key to use for signature verification.
     * \param message       The input message.
     * \param size          The size of the message in bytes.
     *
     * \returns 0 if the message signature is valid, and no-zero on error.
     */
    int (*vccrypt_digital_signature_alg_verify)(
        void* context, const vccrypt_buffer_t* signature,
        const vccrypt_buffer_t* pub,
        const uint8_t* message, size_t message_size);

    /**
     * Create a keypair.
     *
     * The output buffers must be large enough to accept the resultant keys.
     *
     * \param context       An opaque pointer to the
     *                      vccrypt_digital_signature_context_t structure.
     * \param priv          The output buffer to receive the private key.
     * \param pub           The output buffer to receive the public key.
     */
    int (*vccrypt_digital_signature_alg_keypair_create)(
        void* context, vccrypt_buffer_t* priv, vccrypt_buffer_t* pub);

} vccrypt_digital_signature_options_t;

/**
 * Digital signature context.  This structure is used to hold the
 * algorithm-dependent digital signature state used when building the signature.
 */
typedef struct vccrypt_digital_signature_context
{
    /**
     * This context is disposable.
     */
    disposable_t hdr;

    /**
     * The options to use for this context.
     */
    vccrypt_digital_signature_options_t* options;

    /**
     * The hash options to use.
     */
    vccrypt_hash_options_t hash_opts;

    /**
     * The opaque state structure used to store digital signature state.
     */
    void* digital_signature_state;

} vccrypt_digital_signature_context_t;

/**
 * Initialize digital signature options, looking up an appropriate digital
 * signature algorithm registered in the abstract factory.  The options
 * structure is owned by the caller and must be disposed when no longer needed
 * by calling dispose().
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
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_digital_signature_options_init(
    vccrypt_digital_signature_options_t* options,
    allocator_options_t* alloc_opts, vccrypt_prng_options_t* prng_opts,
    uint32_t algorithm);

/**
 * Initialize a digital signature instance with the given options.
 *
 * If initialization is successful, then this digital signature algorithm
 * instance is owned by the caller and must be disposed by calling dispose()
 * when no longer needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The digital signature instance to initialize.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_digital_signature_init(
    vccrypt_digital_signature_options_t* options,
    vccrypt_digital_signature_context_t* context);

/**
 * Sign a message, given a private key, a message, and a message length.
 *
 * \param context       An opaque pointer to the
 *                      vccrypt_digital_signature_context_t structure.
 * \param sign_buffer   The buffer to receive the signature.  Must be large
 *                      enough for the given digital signature algorithm.
 * \param priv          The private key to use for the signature.
 * \param message       The input message.
 * \param size          The size of the message in bytes.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_digital_signature_sign(
    vccrypt_digital_signature_context_t* context, vccrypt_buffer_t* sign_buffer,
    const vccrypt_buffer_t* priv, const uint8_t* message, size_t message_size);

/**
 * Verify a message, given a public key, a message, and a message length.
 *
 * \param context       An opaque pointer to the
 *                      vccrypt_digital_signature_context_t structure.
 * \param signature     The signature to verify.
 * \param pub           The public key to use for signature verification.
 * \param message       The input message.
 * \param size          The size of the message in bytes.
 *
 * \returns 0 if the message signature is valid, and no-zero on error.
 */
int vccrypt_digital_signature_verify(
    vccrypt_digital_signature_context_t* context,
    const vccrypt_buffer_t* signature, const vccrypt_buffer_t* pub,
    const uint8_t* message, size_t message_size);

/**
 * Create a keypair.
 *
 * The output buffers must be large enough to accept the resultant keys.
 *
 * \param context       An opaque pointer to the
 *                      vccrypt_digital_signature_context_t structure.
 * \param priv          The output buffer to receive the private key.
 * \param pub           The output buffer to receive the public key.
 */
int vccrypt_digital_signature_keypair_create(
    vccrypt_digital_signature_context_t* context, vccrypt_buffer_t* priv,
    vccrypt_buffer_t* pub);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_DIGITAL_SIGNATURE_HEADER_GUARD
