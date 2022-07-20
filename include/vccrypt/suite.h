/**
 * \file suite.h
 *
 * \brief The Crypto Suite interface allows related cryptographic primitives to
 * be grouped together.
 *
 * These primitives should be used together to implement a particular set of
 * features for a specific application.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_SUITE_HEADER_GUARD
#define VCCRYPT_SUITE_HEADER_GUARD

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <vccrypt/buffer.h>
#include <vccrypt/digital_signature.h>
#include <vccrypt/function_decl.h>
#include <vccrypt/hash.h>
#include <vccrypt/interfaces.h>
#include <vccrypt/key_agreement.h>
#include <vccrypt/key_derivation.h>
#include <vccrypt/mac.h>
#include <vccrypt/prng.h>
#include <vccrypt/block_cipher.h>
#include <vccrypt/stream_cipher.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup Suites Cryptographic Suites.
 *
 * \brief These are the cryptographic suites supported by this library.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these cryptographic suites.  Registration is a link-time
 * optimization that ensures that only cryptographic primitives needed by the
 * application are linked in the application or library.
 *
 * @{
 */

/**
 * \brief Velo V1 Crypto Suite.
 */
#define VCCRYPT_SUITE_VELO_V1 0x00000001

/**
 * @}
 */

/**
 * \defgroup SuiteRegistration Registration functions for Crypto Suites.
 *
 * \brief An appropriate function in this group must be called before using the
 * associated suite functionality.
 *
 * This resolves linking of the dependent methods for a given cryptographic
 * suite.
 * @{
 */

/**
 * \brief Register the Velo V1 crypto suite.
 */
void vccrypt_suite_register_velo_v1();

/**
 * @}
 */

/* forward decl */
typedef struct vccrypt_suite_options vccrypt_suite_options_t;

/**
 * \brief Cryptographic Suite options.
 *
 * These options are returned by the vccrypt_suite_options_init() method.
 */
struct vccrypt_suite_options
{
    /**
     * \brief This options structure is disposable.
     */
    disposable_t hdr;

    /**
     * \brief The suite id (e.g. VCCRYPT_SUITE_VELO_V1).
     */
    uint32_t suite_id;

    /**
     * \brief The hash algorithm to use for this suite -- see vccrypt/hash.h.
     */
    uint32_t hash_alg;

    /**
     * \brief The signature algorithm to use for this suite -- see
     * vccrypt/digital_signature.h
     */
    uint32_t sign_alg;

    /**
     * \brief The PRNG source to use for this suite -- see vccrypt/prng.h.
     */
    uint32_t prng_src;

    /**
     * \brief The MAC algorithm to use for this suite -- see vccrypt/mac.h.
     */
    uint32_t mac_alg;

    /**
     * \brief The short MAC algorithm to use for this suite -- see
     * vccrypt/mac.h.
     */
    uint32_t mac_short_alg;

    /**
     * \brief The key agreement for authentication algorithm to use for this
     * suite -- see vccrypt/key_agreement.h.
     */
    uint32_t key_auth_alg;

    /**
     * \brief The key agreement for cipher algorithm to use for this suite --
     * see vccrypt/key_agreement.h.
     */
    uint32_t key_cipher_alg;

    /**
     * \brief The key derivation algorithm to use for this suite -- see
     * vccrypt/key_derivation.h.
     */
    uint32_t key_derivation_alg;

    /**
     * \brief The HMAC algorithm to use for the key derivation PRF -- see
     * vccrypt/mac.h
     */
    uint32_t key_derivation_hmac_alg;

    /**
     * \brief The block cipher algorithm to use for this suite -- see
    * vccrypt/block_cipher.h
    */
    uint32_t block_cipher_alg;


    /**
     * \brief The stream cipher algorithm to use for this suite -- see
     * vccrypt/stream_cipher.h
     */
    uint32_t stream_cipher_alg;

    /**
     * \brief The allocator options to use for this suite.
     */
    allocator_options_t* alloc_opts;

    /**
     * \brief The hash options to use for this suite.
     */
    vccrypt_hash_options_t hash_opts;

    /**
     * \brief The digital signature options to use for this suite.
     */
    vccrypt_digital_signature_options_t sign_opts;

    /**
     * \brief The PRNG options to use for this suite.
     */
    vccrypt_prng_options_t prng_opts;

    /**
     * \brief The long MAC options to use for this suite.
     */
    vccrypt_mac_options_t mac_opts;

    /**
     * \brief The short MAC options to use for this suite.
     */
    vccrypt_mac_options_t mac_short_opts;

    /**
     * \brief The key agreement for authentication options to use for this
     * suite.
     */
    vccrypt_key_agreement_options_t key_auth_opts;

    /**
     * \brief The key agreement for cipher options to use for this suite.
     */
    vccrypt_key_agreement_options_t key_cipher_opts;

    /**
     * \brief The key derivation options to use for this suite.
     */
    vccrypt_key_derivation_options_t key_derivation_opts;


    /**
     * \brief The block cipher options to use for this suite.
    */
    vccrypt_block_options_t block_cipher_opts;


    /**
     * \brief The stream cipher options to use for this suite.
     */
    vccrypt_stream_options_t stream_cipher_opts;


    /**
     * \brief Suite-specific initialization for a hash algorithm instance.
     *
     * \param options       Opaque pointer to the suite options.
     * \param context       Hash algorithm context to initialize.
     *
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_suite_hash_alg_init)(
        void* options, vccrypt_hash_context_t* context);

    /**
     * \brief Suite-specific initialization for a digital signature algorithm
     * instance.
     *
     * \param options       Opaque pointer to the suite options.
     * \param context       The digital signature instance to initialize.
     *
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_suite_digital_signature_alg_init)(
        void* options, vccrypt_digital_signature_context_t* context);

    /**
     * \brief Suite-specific initialization for a PRNG source.
     *
     * \param options       Opaque pointer to the suite options.
     * \param context       The PRNG context to initialize.
     *
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_suite_prng_alg_init)(
        void* options, vccrypt_prng_context_t* context);

    /**
     * \brief Suite-specific initialization for a message authentication code
     * algorithm instance.
     *
     * \param options       Opaque pointer to the suite options.
     * \param context       The message authentication code instance to
     *                      initialize.
     * \param key           The key to use for this algorithm.
     *
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_suite_mac_alg_init)(
        void* options, vccrypt_mac_context_t* context,
        const vccrypt_buffer_t* key);

    /**
     * \brief Suite-specific initialization for a short message authentication
     * code algorithm instance.
     *
     * \param options       Opaque pointer to the suite options.
     * \param context       The message authentication code instance to
     *                      initialize.
     * \param key           The key to use for this algorithm.
     *
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_suite_mac_short_alg_init)(
        void* options, vccrypt_mac_context_t* context,
        const vccrypt_buffer_t* key);

    /**
     * \brief Suite-specific initialization for a key agreement algorithm
     * instance to be used for authentication purposes.
     *
     * \param options       Opaque pointer to the suite options.
     * \param context       The key agreement algorithm instance to initialize.
     *
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_suite_key_auth_init)(
        void* options, vccrypt_key_agreement_context_t* context);

    /**
     * \brief Suite-specific initialization for a key agreement algorithm
     * instance to be used for creating shared secrets for symmetric ciphers.
     *
     * \param options       Opaque pointer to the suite options.
     * \param context       The key agreement algorithm instance to initialize.
     *
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_suite_key_cipher_init)(
        void* options, vccrypt_key_agreement_context_t* context);


    /**
     * \brief Suite-specific initialization for a key derivation algorithm
     * instance to be used for deriving keys from passwords.
     *
     * \param context       The key derivation algorithm instance to
     *                      initialize.
     * \param options       Pointer to the suite options.
     *
     * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_suite_key_derivation_alg_init)(
        vccrypt_key_derivation_context_t* context,
        vccrypt_suite_options_t* options);

    /**
     * \brief Suite-specific initialization for block cipher algorithm
     * instance.
     *
     * \param options       Opaque pointer to the suite options.
     * \param context       The block cipher algorithm instance to initialize.
     * \param key           The key to use for this algorithm.
     * \param encrypt       Set to true if this is for encryption, and false for
     *                      decryption.
     *
     * \return VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_suite_block_alg_init)(
        void* options, vccrypt_block_context_t* context,
        const vccrypt_buffer_t* key, bool encrypt);

    /**
     * \brief Suite-specific initialization for stream cipher algorithm
     * instance.
     *
     * \param options       Opaque pointer to the suite options.
     * \param context       The stream cipher algorithm instance to initialize.
     * \param key           The key to use for this algorithm.
     *
     * \return VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_suite_stream_alg_init)(
        void* options, vccrypt_stream_context_t* context,
        const vccrypt_buffer_t* key);

    /**
     * \brief Implementation specific options init method.
     *
     * \param options       The options structure to initialize.
     * \param alloc_opts    The allocator options structure for this method.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_suite_alg_options_init)(
        void* options, allocator_options_t* alloc_opts);

    /**
     * \brief Implementation specific options dispose method.
     *
     * \param disp          The options structure to dispose.
     */
    void (*vccrypt_suite_alg_options_dispose)(void* disp);

    /**
     * \brief Options level context pointer.
     */
    void* options_context;

};

/**
 * \brief Initialize a crypto suite options structure.
 *
 * This method initializes a crypto suite options structure so that it can be
 * used to instantiate cryptographic primitives for a given crypto suite.
 *
 * Note that the crypto suite selected must be registered prior to use in order
 * to instruct the linker to link the correct algorithms to this application.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options to use for this suite.
 * \param suite_id      The suite identifier to use for initialization.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_SUITE_OPTIONS_INIT_MISSING_IMPL when the provided
 *             implementation selector is invalid or the implementation was not
 *             registered.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_options_init(
    vccrypt_suite_options_t* options, allocator_options_t* alloc_opts,
    uint32_t suite_id);

/**
 * \brief Create an appropriate hash algorithm instance for this crypto suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The hash algorithm context to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_hash_init(
    vccrypt_suite_options_t* options, vccrypt_hash_context_t* context);

/**
 * \brief Open an appropriate prng source for this crypto suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The prng instance to initialize with this source.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_prng_init(
    vccrypt_suite_options_t* options, vccrypt_prng_context_t* context);

/**
 * \brief Create an appropriate digital signature algorithm instance for this
 * crypto suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The digital signature instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_digital_signature_init(
    vccrypt_suite_options_t* options,
    vccrypt_digital_signature_context_t* context);

/**
 * \brief Create an appropriate message authentication code algorithm instance
 * for this crypto suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The message authentication code instance to
 *                      initialize.
 * \param key           The key to use for this algorithm.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_mac_init(
    vccrypt_suite_options_t* options, vccrypt_mac_context_t* context,
    const vccrypt_buffer_t* key);

/**
 * \brief Create an appropriate short message authentication code algorithm
 * instance for this crypto suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The message authentication code instance to
 *                      initialize.
 * \param key           The key to use for this algorithm.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_mac_short_init(
    vccrypt_suite_options_t* options, vccrypt_mac_context_t* context,
    const vccrypt_buffer_t* key);

/**
 * \brief Create an appropriate authentication key agreement algorithm instance
 * for this crypto suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The key agreement algorithm instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_auth_key_agreement_init(
    vccrypt_suite_options_t* options, vccrypt_key_agreement_context_t* context);

/**
 * \brief Create an appropriate symmetric cipher key agreement algorithm
 * instance for this crypto suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The key agreement algorithm instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_cipher_key_agreement_init(
    vccrypt_suite_options_t* options, vccrypt_key_agreement_context_t* context);

/**
 * \brief Create a buffer sized appropriately for the output of this crypto
 * suite's hash algorithm.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer to instance initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_hash(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer);

/**
 * \brief Create a buffer sized appropriately for the private key of this crypto
 * suite's digital signature algorithm.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer to instance initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_signature_private_key(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer);

/**
 * \brief Create a buffer sized appropriately for the public key of this crypto
 * suite's digital signature algorithm.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer to instance initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_signature_public_key(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer);

/**
 * \brief Create a buffer sized appropriately for the signature of this crypto
 * suite's digital signature algorithm.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer to instance initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_signature(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer);

/**
 * \brief Create a buffer sized appropriately for the private key of this crypto
 * suite's message authentication code algorithm.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 * \param short_mac     Whether the buffer is for a short or long MAC.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_mac_private_key(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer, bool short_mac);

/**
 * \brief Create a buffer sized appropriately for the message authentication
 * code of this crypto suite's message authentication code algorithm.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 * \param short_mac     Whether the buffer is for a short or long MAC.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_mac_authentication_code(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer, bool short_mac);

/**
 * \brief Create a buffer sized appropriately for the private key of this crypto
 * suite's key agreement algorithm for authentication.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_auth_key_agreement_private_key(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer);

/**
 * \brief Create a buffer sized appropriately for the public key of this crypto
 * suite's key agreement algorithm for authentication.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_auth_key_agreement_public_key(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer);

/**
 * \brief Create a buffer sized appropriately for a nonce value for this crypto
 * suite's key agreement algorithm for authentication.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_auth_key_agreement_nonce(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer);

/**
 * \brief Create a buffer sized appropriately for the shared secret of this
 * crypto suite's key agreement algorithm for authentication.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_auth_key_agreement_shared_secret(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer);

/**
 * \brief Create a buffer sized appropriately for the private key of this crypto
 * suite's key agreement algorithm for ciphers.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_cipher_key_agreement_private_key(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer);

/**
 * \brief Create a buffer sized appropriately for the public key of this crypto
 * suite's key agreement algorithm for ciphers.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer);

/**
 * \brief Create a buffer sized appropriately for a nonce value for this crypto
 * suite's key agreement algorithm for ciphers.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer);

/**
 * \brief Create a buffer sized appropriately for the shared secret of this
 * crypto suite's key agreement algorithm for ciphers.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer);

/**
 * \brief Create a buffer sized appropriately for holding a UUID in raw byte
 * form.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_buffer_init_for_uuid(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer);

/**
 * \brief Create an appropriate key derivation algorithm instance
 * for this crypto suite.
 *
 * \param context       The key derivation instance to initialize.
 * \param options       The options structure for this crypto suite.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_key_derivation_init(
    vccrypt_key_derivation_context_t* context, vccrypt_suite_options_t* options);

/**
 * \brief
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The block cipher instance to initialize.
 * \param key           The key to use for this algorithm.
 * \param encrypt       Set to true if this is for encryption, and false for
 *                      decryption.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_block_init(
    vccrypt_suite_options_t* options, vccrypt_block_context_t* context,
    const vccrypt_buffer_t* key, bool encrypt);

/**
 * \brief
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The stream cipher instance to initialize.
 * \param key           The key to use for this algorithm.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_suite_stream_init(
    vccrypt_suite_options_t* options, vccrypt_stream_context_t* context,
    vccrypt_buffer_t* key);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_SUITE_HEADER_GUARD
