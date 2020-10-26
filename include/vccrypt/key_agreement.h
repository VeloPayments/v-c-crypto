/**
 * \file key_agreement.h
 *
 * \brief The Key Agreement primitive provides a protocol by which two entities
 * can agree upon a shared secret key that is unique to the combination of
 * either the first entity's private key and the second entity's public key, or
 * the first entity's public key and the second entity's private key.
 *
 * For this mechanism to be secure, a secure channel is needed to transmit
 * public keys in order to prevent a man-in-the-middle (MITM) attack.  PKI is
 * one mechanism that provides this, and the blockchain -- as a natural
 * extension to PKI -- is another.
 *
 * This interface requires access to a cryptographic random number generator to
 * create keys.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_KEY_AGREEMENT_HEADER_GUARD
#define VCCRYPT_KEY_AGREEMENT_HEADER_GUARD

#include <vccrypt/error_codes.h>
#include <vccrypt/function_decl.h>
#include <vccrypt/prng.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup KeyAgreementConstants Key Agreement Constants.
 *
 * \brief These constants describe parameters for key agreement algorithms.
 *
 * @{
 */

/**
 * \brief Shared secret size for Curve25519 Plain.
 */
#define VCCRYPT_KEY_AGREEMENT_CURVE25519_PLAIN_SECRET_SIZE 32

/**
 * \brief Private key size for Curve25519 Plain.
 */
#define VCCRYPT_KEY_AGREEMENT_CURVE25519_PLAIN_PRIVATE_KEY_SIZE 32

/**
 * \brief Public key size for Curve25519 Plain.
 */
#define VCCRYPT_KEY_AGREEMENT_CURVE25519_PLAIN_PUBLIC_KEY_SIZE 32

/**
 * \brief Nonce size for Curve25519 Plain.
 */
#define VCCRYPT_KEY_AGREEMENT_CURVE25519_PLAIN_NONCE_SIZE 32

/**
 * \brief Shared secret size for Curve25519-SHA-2-512.
 */
#define VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_SECRET_SIZE 64

/**
 * \brief Private key size for Curve25519-SHA-2-512.
 */
#define VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_PRIVATE_KEY_SIZE 32

/**
 * \brief Public key size for Curve25519-SHA-2-512.
 */
#define VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_PUBLIC_KEY_SIZE 32

/**
 * \brief Nonce size for Curve25519-SHA-2-512.
 */
#define VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_NONCE_SIZE 64

/**
 * \brief Shared secret size for Curve25519-SHA-2-512/256.
 */
#define VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_256_SECRET_SIZE 32

/**
 * \brief Private key size for Curve25519-SHA-2-512/256.
 */
#define VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_256_PRIVATE_KEY_SIZE 32

/**
 * \brief Public key size for Curve25519-SHA-2-512/256.
 */
#define VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_256_PUBLIC_KEY_SIZE 32

/**
 * \brief Nonce size for Curve25519-SHA-2-512/256.
 */
#define VCCRYPT_KEY_AGREEMENT_CURVE25519_SHA512_256_NONCE_SIZE 32

/**
 * @}
 */

/**
 * \defgroup KeyAgreementAlgorithms Key Agreement Algorithms.
 *
 * \brief Algorithms optionally supported by the key agreement subsystem.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these algorithms to initialize a
 * \ref vccrypt_key_agreement_options_t structure. Registration is a link-time
 * optimization that ensures that only cryptographic primitives needed by the
 * application are linked in the application or library.
 *
 * @{
 */

/**
 * \brief Selector for Curve25519 Plain.
 */
#define VCCRYPT_KEY_AGREEMENT_ALGORITHM_CURVE25519_PLAIN 0x00010000

/**
 * \brief Selector for Curve25519-SHA-2-512.
 */
#define VCCRYPT_KEY_AGREEMENT_ALGORITHM_CURVE25519_SHA512 0x00020000

/**
 * \brief Selector for Curve25519-SHA-2-512/256.
 */
#define VCCRYPT_KEY_AGREEMENT_ALGORITHM_CURVE25519_SHA512_256 0x00040000
/**
 * @}
 */

/**
 * \defgroup KeyAgreementRegistration Registration functions for Key Agreement Algorithms.
 *
 * \brief An appropriate function from this group must be called before using
 * the associated key agreement functionality.
 *
 * This resolves linking of the dependent methods for a given key agreement
 * algorithm.
 * @{
 */

/**
 * \brief Register the Curve25519 Plain key agreement algorithm.
 */
void vccrypt_key_agreement_register_curve25519_plain();

/**
 * \brief Register the Curve25519-SHA-2-512 key agreement algorithm.
 */
void vccrypt_key_agreement_register_curve25519_sha512();

/**
 * \brief Register the Curve25519-SHA-2-512/256 key agreement algorithm.
 */
void vccrypt_key_agreement_register_curve25519_sha512_256();

/**
 * @}
 */

/**
 * \brief These options are returned by the vccrypt_key_agreement_options_init()
 * method.
 */
typedef struct vccrypt_key_agreement_options
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
     * \brief The hash algorithm to use.
     */
    uint32_t hash_algorithm;

    /**
     * \brief The hmac algorithm to use for short-term secrets.
     */
    uint32_t hmac_algorithm;

    /**
     * \brief The shared secret size in bytes.
     */
    size_t shared_secret_size;

    /**
     * \brief The private key size in bytes.
     */
    size_t private_key_size;

    /**
     * \brief The public key size in bytes.
     */
    size_t public_key_size;

    /**
     * \brief The minimum nonce size for short-term key creation.
     */
    size_t minimum_nonce_size;

    /**
     * \brief Algorithm-specific initialization for key agreement.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to the vccrypt_key_agreement_context_t
     *                  structure.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
     */
    int (*vccrypt_key_agreement_alg_init)(void* options, void* context);

    /**
     * \brief Algorithm-specific disposal for key agreement.
     *
     * \param options   Opaque pointer to this options structure.
     * \param context   Opaque pointer to the vccrypt_key_agreement_context_t
     *                  structure.
     */
    void (*vccrypt_key_agreement_alg_dispose)(void* options, void* context);

    /**
     * \brief Generate the long-term secret, given a private key and a public
     * key.
     *
     * \param context   Opaque pointer to the vccrypt_key_agreement_context_t
     *                  structure.
     * \param priv      The private key to use for this operation.
     * \param pub       The public key to use for this operation.
     * \param shared    The buffer to receive the long-term secret.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
     */
    int (*vccrypt_key_agreement_alg_long_term_secret_create)(
        void* context, const vccrypt_buffer_t* priv,
        const vccrypt_buffer_t* pub, vccrypt_buffer_t* shared);

    /**
     * \brief Generate the short-term secret, given a private key, a public
     * key, a server nonce, and a client nonce.
     *
     * \param context       Opaque pointer to the
     *                      vccrypt_key_agreement_context_t structure.
     * \param priv          The private key to use for this operation.
     * \param pub           The public key to use for this operation.
     * \param server_nonce  The server nonce to use for this operation.
     * \param client_nonce  The client nonce to use for this operation.
     * \param shared        The buffer to receive the long-term secret.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
     */
    int (*vccrypt_key_agreement_alg_short_term_secret_create)(
        void* context, const vccrypt_buffer_t* priv,
        const vccrypt_buffer_t* pub, const vccrypt_buffer_t* server_nonce,
        const vccrypt_buffer_t* client_nonce, vccrypt_buffer_t* shared);

    /**
     * \brief Generate a keypair.
     *
     * \param context   Opaque pointer to the vccrypt_key_agreement_context_t
     *                  structure.
     * \param priv      The buffer to receive the private key.
     * \param pub       The buffer to receive the public key.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
     */
    int (*vccrypt_key_agreement_alg_keypair_create)(
        void* context, vccrypt_buffer_t* priv, vccrypt_buffer_t* pub);

    /**
     * \brief Implementation specific options init method.
     *
     * \param options       The options structure to initialize.
     * \param alloc_opts    The allocator options structure for this method.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_key_agreement_alg_options_init)(
        void* options, allocator_options_t* alloc_opts);

    /**
     * \brief Options level context pointer.
     */
    void* options_context;

} vccrypt_key_agreement_options_t;

/**
 * \brief This structure is used to hold the algorithm-dependent key agreement
 * state used when building a shared secret.
 */
typedef struct vccrypt_key_agreement_context
{
    /**
     * \brief This context is disposable.
     */
    disposable_t hdr;

    /**
     * \brief The options to use for this context.
     */
    vccrypt_key_agreement_options_t* options;

    /**
     * \brief The opaque state structure to use to store key agreement state.
     */
    void* key_agreement_state;

} vccrypt_key_agreement_context_t;

/**
 * \brief Initialize key agreement options, looking up an appropriate key
 * agreement algorithm registered in the abstract factory.
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
 * \param algorithm     The key agreement algorithm to use.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_KEY_AGREEMENT_OPTIONS_INIT_MISSING_IMPL if the
 *             provided instance selector is invalid or unregistered.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_key_agreement_options_init(
    vccrypt_key_agreement_options_t* options,
    allocator_options_t* alloc_opts, vccrypt_prng_options_t* prng_opts,
    uint32_t algorithm);

/**
 * \brief Initialize a key agreement algorithm instance with the given options.
 *
 * If initialization is successful, then this key agreement algorithm
 * instance is owned by the caller and must be disposed by calling dispose()
 * when no longer needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The key agreement algorithm instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_KEY_AGREEMENT_INIT_INVALID_ARG if one of the
 *             provided arguments is invalid.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_key_agreement_init(
    vccrypt_key_agreement_options_t* options,
    vccrypt_key_agreement_context_t* context);

/**
 * \brief Generate a long-term secret, given a private key and a public key.
 *
 * \param context       The key agreement algorithm instance to use for this
 *                      derivation.
 * \param priv          The private key to use for this operation.
 * \param pub           The public key to use for this operation.
 * \param shared        The buffer to receive the long-term secret.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_key_agreement_long_term_secret_create(
    vccrypt_key_agreement_context_t* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, vccrypt_buffer_t* shared);

/**
 * \brief Generate a short-term secret, given a private key, a public key, a
 * server nonce, and a client nonce.
 *
 * Internally, this method generates the long-term shared secret for these two
 * peers, and uses this secret to generate a short-term secret via the HMAC
 * algorithm selected for this algorithm instance.  The long-term secret is used
 * as the key for the HMAC.  The nonces should never be used again for this
 * keypair.
 *
 * Note that when this is used to generate a short-term secret in a
 * non-client/server capacity, one peer should be selected as the client and the
 * other as the server.  Both peers should order the nonces the same, meaning
 * that if Peer A is designated the "server", then both Peer A and Peer B should
 * use Peer A's nonce value as the server nonce and Peer B's nonce value as the
 * client nonce.
 *
 * \param context       The key agreement algorithm instance to use for this
 *                      derivation.
 * \param priv          The private key to use for this operation.
 * \param pub           The public key to use for this operation.
 * \param server_nonce  The server nonce to use to generate the short-term
 *                      secret.
 * \param client_nonce  The client nonce to use to generate the short-term
 *                      secret.
 * \param shared        The buffer to receive the long-term secret.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_KEY_AGREEMENT_SHORT_TERM_CREATE_INVALID_ARG if one
 *             of the provided arguments is invalid.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_key_agreement_short_term_secret_create(
    vccrypt_key_agreement_context_t* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, const vccrypt_buffer_t* server_nonce,
    const vccrypt_buffer_t* client_nonce, vccrypt_buffer_t* shared);

/**
 * \brief Generate a keypair.
 *
 * \param context       The key agreement algorithm instance to use for this
 *                      keypair generation.
 * \param priv          The buffer to receive the private key.
 * \param pub           The buffer to receive the public key.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_key_agreement_keypair_create(
    vccrypt_key_agreement_context_t* context, vccrypt_buffer_t* priv,
    vccrypt_buffer_t* pub);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_KEY_AGREEMENT_HEADER_GUARD
