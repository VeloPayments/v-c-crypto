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

#ifndef VCCRYPT_MOCK_KEY_AGREEMENT_HEADER_GUARD
#define VCCRYPT_MOCK_KEY_AGREEMENT_HEADER_GUARD

#include <vccrypt/key_agreement.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

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
 * \brief Selector for mock auth algorithm.
 */
#define VCCRYPT_KEY_AGREEMENT_ALGORITHM_MOCK_AUTH 0x80000000
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
 * \brief Register the mock auth key agreement algroithm.
 */
void vccrypt_key_agreement_register_mock_auth();
/**
 * @}
 */

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

/* C++ mock structs for testing start here. */
#if       defined(__cplusplus)

#include <functional>
#include <memory>

/**
 * \brief The mock structure for key agreement.
 */
struct key_agreement_mock
{

    /** \brief init mock. */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_key_agreement_options_t*,
                vccrypt_key_agreement_context_t*)>>
    key_agreement_init_mock;

    /** \brief dispose mock. */
    std::shared_ptr<
        std::function<
            void (
                vccrypt_key_agreement_options_t*,
                vccrypt_key_agreement_context_t*)>>
    key_agreement_dispose_mock;

    /** \brief long_term_secret_create mock. */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_key_agreement_context_t*, const vccrypt_buffer_t*,
                const vccrypt_buffer_t*, vccrypt_buffer_t*)>>
    key_agreement_long_term_secret_create_mock;

    /** \brief short_term_secret_create mock. */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_key_agreement_context_t*, const vccrypt_buffer_t*,
                const vccrypt_buffer_t*, const vccrypt_buffer_t*,
                const vccrypt_buffer_t*, vccrypt_buffer_t*)>>
    key_agreement_short_term_secret_create_mock;

    /** \brief keypair_create mock. */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_key_agreement_context_t*, vccrypt_buffer_t*,
                vccrypt_buffer_t*)>>
    key_agreement_keypair_create_mock;
};

#endif /* defined(__cplusplus) */

#endif  //VCCRYPT_MOCK_KEY_AGREEMENT_HEADER_GUARD
