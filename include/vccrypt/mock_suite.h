/**
 * \file mock_suite.h
 *
 * \brief The Crypto Suite Mock allows test code written in C++ to mock software
 * interfaces that use the Crypto Suite interface.
 *
 * Test code using this suite must link against the mock vccrypt library.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_MOCK_SUITE_HEADER_GUARD
#define VCCRYPT_MOCK_SUITE_HEADER_GUARD

#include <vccrypt/suite.h>
#include <vccrypt/mock/block_cipher.h>
#include <vccrypt/mock/digital_signature.h>
#include <vccrypt/mock/hash.h>
#include <vccrypt/mock/key_agreement.h>
#include <vccrypt/mock/key_derivation.h>
#include <vccrypt/mock/mac.h>
#include <vccrypt/mock/prng.h>

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
 * \brief Mock Crypto Suite.
 */
#define VCCRYPT_SUITE_MOCK    0x80000000

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
 * \brief Register the mock crypto suite.
 */
void vccrypt_suite_register_mock();

/**
 * @}
 */

/**
 * \brief Initialize a mock crypto suite options structure.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options to use for this suite.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_options_init(
    vccrypt_suite_options_t* suite, allocator_options_t* alloc_opts);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

/* C++ mock methods for testing start here. */
#if       defined(__cplusplus)

#include <functional>

/**
 * \brief Mock the hash algorithm init method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to initialize a hash algorithm
 *                  instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_hash_init(
    vccrypt_suite_options_t* suite,
    std::function<int (vccrypt_hash_options_t*, vccrypt_hash_context_t*)> func);

/**
 * \brief Mock the hash algorithm dispose method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to call when this algorithm is disposed.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_hash_dispose(
    vccrypt_suite_options_t* suite,
    std::function<
        void (vccrypt_hash_options_t*, vccrypt_hash_context_t*)> func);

/**
 * \brief Mock the hash algorithm digest method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to call when the digest method is called.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_hash_digest(
    vccrypt_suite_options_t* suite,
    std::function<int (vccrypt_hash_context_t*, const uint8_t*, size_t)> func);

/**
 * \brief Mock the hash algorithm finalize method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to call when the finalize method is
 *                  called.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_hash_finalize(
    vccrypt_suite_options_t* suite,
    std::function<int (vccrypt_hash_context_t*, vccrypt_buffer_t*)> func);

/**
 * \brief Mock the prng init method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to initialize a prng algorithm
 *                  instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_prng_init(
    vccrypt_suite_options_t* suite,
    std::function<int (vccrypt_prng_options_t*, vccrypt_prng_context_t*)> func);

/**
 * \brief Mock the prng dispose method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to dispose a prng algorithm
 *                  instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_prng_dispose(
    vccrypt_suite_options_t* suite,
    std::function<
        void (vccrypt_prng_options_t*, vccrypt_prng_context_t*)> func);

/**
 * \brief Mock the prng read method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to read from the prng instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_prng_read(
    vccrypt_suite_options_t* suite,
    std::function<int (vccrypt_prng_context_t*, uint8_t*, size_t)> func);

/**
 * \brief Mock the digital signature algorithm init method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to initialize a digital signature
 *                  algorithm instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_digital_signature_init(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_digital_signature_options_t*,
            vccrypt_digital_signature_context_t*)> func);

/**
 * \brief Mock the digital signature algorithm dispose method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to dispose a digital signature
 *                  algorithm instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_digital_signature_dispose(
    vccrypt_suite_options_t* suite,
    std::function<
        void (
            vccrypt_digital_signature_options_t*,
            vccrypt_digital_signature_context_t*)> func);

/**
 * \brief Mock the digital signature algorithm sign method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to call when sign is called.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_digital_signature_sign(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_digital_signature_context_t*, vccrypt_buffer_t*,
            const vccrypt_buffer_t*, const uint8_t*, size_t)> func);

/**
 * \brief Mock the digital signature algorithm verify method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to call when verify is called.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_digital_signature_verify(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_digital_signature_context_t*, const vccrypt_buffer_t*,
            const vccrypt_buffer_t*, const uint8_t*, size_t)> func);

/**
 * \brief Mock the digital signature algorithm keypair create method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to call when keypair_create is called.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_digital_signature_keypair_create(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_digital_signature_context_t*, vccrypt_buffer_t*,
            vccrypt_buffer_t*)> func);

/**
 * \brief Mock the mac algorithm init method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to initialize a mack algorithm
 *                  instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_mac_init(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_mac_options_t*, vccrypt_mac_context_t*,
            vccrypt_buffer_t*)> func);

/**
 * \brief Mock the mac algorithm dispose method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to dispose a mack algorithm
 *                  instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_mac_dispose(
    vccrypt_suite_options_t* suite,
    std::function<
        void (vccrypt_mac_options_t*, vccrypt_mac_context_t*)> func);

/**
 * \brief Mock the mac algorithm digest method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when digest is called.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_mac_digest(
    vccrypt_suite_options_t* suite,
    std::function<
        int (vccrypt_mac_context_t*, const uint8_t* data, size_t size)> func);

/**
 * \brief Mock the mac algorithm finalize method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when finalize is called.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_mac_finalize(
    vccrypt_suite_options_t* suite,
    std::function<
        int (vccrypt_mac_context_t*, vccrypt_buffer_t*)> func);

/**
 * \brief Mock the short mac algorithm init method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to initialize a mack algorithm
 *                  instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_short_mac_init(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_mac_options_t*, vccrypt_mac_context_t*,
            vccrypt_buffer_t*)> func);

/**
 * \brief Mock the short mac algorithm dispose method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to dispose a mack algorithm
 *                  instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_short_mac_dispose(
    vccrypt_suite_options_t* suite,
    std::function<
        void (vccrypt_mac_options_t*, vccrypt_mac_context_t*)> func);

/**
 * \brief Mock the short mac algorithm digest method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when digest is called.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_short_mac_digest(
    vccrypt_suite_options_t* suite,
    std::function<
        int (vccrypt_mac_context_t*, const uint8_t* data, size_t size)> func);

/**
 * \brief Mock the short mac algorithm finalize method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when finalize is called.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_short_mac_finalize(
    vccrypt_suite_options_t* suite,
    std::function<
        int (vccrypt_mac_context_t*, vccrypt_buffer_t*)> func);

/**
 * \brief Mock the auth key agreement algorithm init method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to initialize an auth key agreement
 *                  algorithm instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_auth_key_agreement_init(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_key_agreement_options_t*,
            vccrypt_key_agreement_context_t*)> func);

/**
 * \brief Mock the auth key agreement algorithm dispose method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to dispose an auth key agreement
 *                  algorithm instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_auth_key_agreement_dispose(
    vccrypt_suite_options_t* suite,
    std::function<
        void (
            vccrypt_key_agreement_options_t*,
            vccrypt_key_agreement_context_t*)> func);

/**
 * \brief Mock the auth key agreement algorithm long-term secret method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when calling the long-term secret
 *                  method.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_auth_key_agreement_long_term_secret_create(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_key_agreement_context_t*, const vccrypt_buffer_t*,
            const vccrypt_buffer_t*, vccrypt_buffer_t*)> func);

/**
 * \brief Mock the auth key agreement algorithm short-term secret method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when calling the short-term secret
 *                  method.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_auth_key_agreement_short_term_secret_create(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_key_agreement_context_t*, const vccrypt_buffer_t*,
            const vccrypt_buffer_t*, const vccrypt_buffer_t*,
            const vccrypt_buffer_t*, vccrypt_buffer_t*)> func);

/**
 * \brief Mock the auth key agreement algorithm keypair create function.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when calling the keypair create
 *                  method.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_auth_key_agreement_keypair_create(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_key_agreement_context_t*, vccrypt_buffer_t*,
            vccrypt_buffer_t*)> func);

/**
 * \brief Mock the cipher key agreement algorithm init method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to initialize an cipher key
 *                  agreement algorithm instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_cipher_key_agreement_init(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_key_agreement_options_t*,
            vccrypt_key_agreement_context_t*)> func);

/**
 * \brief Mock the cipher key agreement algorithm dispose method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to dispose an cipher key agreement
 *                  algorithm instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_cipher_key_agreement_dispose(
    vccrypt_suite_options_t* suite,
    std::function<
        void (
            vccrypt_key_agreement_options_t*,
            vccrypt_key_agreement_context_t*)> func);

/**
 * \brief Mock the cipher key agreement algorithm long-term secret method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when calling the long-term secret
 *                  method.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_cipher_key_agreement_long_term_secret_create(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_key_agreement_context_t*, const vccrypt_buffer_t*,
            const vccrypt_buffer_t*, vccrypt_buffer_t*)> func);

/**
 * \brief Mock the cipher key agreement algorithm short-term secret method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when calling the short-term secret
 *                  method.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_cipher_key_agreement_short_term_secret_create(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_key_agreement_context_t*, const vccrypt_buffer_t*,
            const vccrypt_buffer_t*, const vccrypt_buffer_t*,
            const vccrypt_buffer_t*, vccrypt_buffer_t*)> func);

/**
 * \brief Mock the cipher key agreement algorithm keypair create function.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when calling the keypair create
 *                  method.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_cipher_key_agreement_keypair_create(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_key_agreement_context_t*, vccrypt_buffer_t*,
            vccrypt_buffer_t*)> func);

/**
 * \brief Mock the key derivation algorithm init method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to initialize a key derivation
 *                  algorithm instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_key_derivation_init(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_key_derivation_context_t*,
            vccrypt_key_derivation_options_t*)> func);

/**
 * \brief Mock the key derivation algorithm dispose method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to dispose a key derivation
 *                  algorithm instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_key_derivation_dispose(
    vccrypt_suite_options_t* suite,
    std::function<
        void (
            vccrypt_key_derivation_context_t*,
            vccrypt_key_derivation_options_t*)> func);

/**
 * \brief Mock the key derivation algorithm derive key method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when calling the derive key
 *                  function.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_key_derivation_derive_key(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_buffer_t*, vccrypt_key_derivation_context_t*,
            const vccrypt_buffer_t*, const vccrypt_buffer_t*,
            unsigned int)> func);

/**
 * \brief Mock the block cipher algorithm init method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to initialize a block cipher
 *                  algorithm instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_block_init(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_block_options_t*, vccrypt_block_context_t*,
            vccrypt_buffer_t*, bool)> func);

/**
 * \brief Mock the block cipher algorithm dispose method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to dispose a block cipher
 *                  algorithm instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_block_dispose(
    vccrypt_suite_options_t* suite,
    std::function<
        void (
            vccrypt_block_options_t*,
            vccrypt_block_context_t*)> func);

/**
 * \brief Mock the block cipher algorithm encrypt method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when calling the block encrypt
 *                  function.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_block_encrypt(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_block_context_t*, const void*, const void*, void*)> func);

/**
 * \brief Mock the block cipher algorithm decrypt method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when calling the block decrypt
 *                  function.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_block_decrypt(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_block_context_t*, const void*, const void*, void*)> func);

#endif /* defined(__cplusplus) */

#endif  //VCCRYPT_MOCK_SUITE_HEADER_GUARD
