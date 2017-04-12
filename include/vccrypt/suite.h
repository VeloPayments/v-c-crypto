/**
 * \file suite.h
 *
 * Crypto Suite.  The Crypto Suite interface allows related cryptographic
 * primitives to be grouped together.  These primitives should be used together
 * to implement a particular set of features for a specific application.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_SUITE_HEADER_GUARD
#define VCCRYPT_SUITE_HEADER_GUARD

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <vccrypt/buffer.h>
#include <vccrypt/digital_signature.h>
#include <vccrypt/hash.h>
#include <vccrypt/interfaces.h>
#include <vccrypt/mac.h>
#include <vccrypt/prng.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup Suites Cryptographic Suites.
 *
 * These are the cryptographic suites supported by this library.
 *
 * @{
 */
#define VCCRYPT_SUITE_VELO_V1 0x00000001

/**
 * @}
 */

/**
 * \defgroup SuiteRegistration Registration functions for Crypto Suites.
 * @{
 */
void vccrypt_suite_register_velo_v1();

/**
 * @}
 */

/**
 * \brief Cryptographic Suite options.
 *
 * These options are returned by the vccrypt_suite_options_init() method.
 */
typedef struct vccrypt_suite_options
{
    /**
     * This options structure is disposable.
     */
    disposable_t hdr;

    uint32_t hash_alg;
    uint32_t sign_alg;
    uint32_t prng_src;

    allocator_options_t* alloc_opts;
    vccrypt_hash_options_t hash_opts;
    vccrypt_digital_signature_options_t sign_opts;
    vccrypt_prng_options_t prng_opts;

    /**
     * Suite-specific initialization for a hash algorithm instance.
     *
     * \param options       Opaque pointer to the suite options.
     * \param context       Hash algorithm context to initialize.
     *
     * \returns 0 on success and non-zero on failure.
     */
    int (*vccrypt_suite_hash_alg_init)(
        void* options, vccrypt_hash_context_t* context);

    /**
     * Suite-specific initialization for a digital signature algorithm instance.
     *
     * \param options       Opaque pointer to the suite options.
     * \param context       The digital signature instance to initialize.
     *
     * \returns 0 on success and non-zero on failure.
     */
    int (*vccrypt_suite_digital_signature_alg_init)(
        void* options, vccrypt_digital_signature_context_t* context);

    /**
     * Suite-specific initialization for a PRNG source.
     *
     * \param options       Opaque pointer to the suite options.
     * \param context       The PRNG context to initialize.
     *
     * \returns 0 on success and non-zero on failure.
     */
    int (*vccrypt_suite_prng_alg_init)(
        void* options, vccrypt_prng_context_t* context);

} vccrypt_suite_options_t;

/**
 * Initialize a crypto suite options structure.
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
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_options_init(
    vccrypt_suite_options_t* options, allocator_options_t* alloc_opts,
    uint32_t suite_id);

/**
 * Create an appropriate hash algorithm instance for this crypto suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The hash algorithm context to initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_hash_init(
    vccrypt_suite_options_t* options, vccrypt_hash_context_t* context);

/**
 * Open an appropriate prng source for this crypto suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The prng instance to initialize with this source.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_prng_init(
    vccrypt_suite_options_t* options, vccrypt_prng_context_t* context);

/**
 * Create an appropriate digital signature algorithm instance for this crypto
 * suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The digital signature instance to initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_digital_signature_init(
    vccrypt_suite_options_t* options,
    vccrypt_digital_signature_context_t* context);

/**
 * Create a buffer sized appropriately for the output of this crypto suite's
 * hash algorithm.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer to instance initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_buffer_init_for_hash(
    vccrypt_suite_options_t* options,
    vccrypt_buffer_t* buffer);

/**
 * Create a buffer sized appropriately for the private key of this crypto
 * suite's digital signature algorithm.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer to instance initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_buffer_init_for_signature_private_key(
    vccrypt_suite_options_t* options,
    vccrypt_buffer_t* buffer);

/**
 * Create a buffer sized appropriately for the public key of this crypto
 * suite's digital signature algorithm.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer to instance initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_buffer_init_for_signature_public_key(
    vccrypt_suite_options_t* options,
    vccrypt_buffer_t* buffer);

/**
 * Create a buffer sized appropriately for the signature of this crypto
 * suite's digital signature algorithm.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer to instance initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_buffer_init_for_signature(
    vccrypt_suite_options_t* options,
    vccrypt_buffer_t* buffer);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_SUITE_HEADER_GUARD
