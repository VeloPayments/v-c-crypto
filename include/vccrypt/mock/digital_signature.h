/**
 * \file mock/digital_signature.h
 *
 * \brief Mock of the digital signature algorithm.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_MOCK_DIGITAL_SIGNATURE_HEADER_GUARD
#define VCCRYPT_MOCK_DIGITAL_SIGNATURE_HEADER_GUARD

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
#define VCCRYPT_DIGITAL_SIGNATURE_MOCK 0x80000000

/**
 * @}
 */

/**
 * \defgroup DigitalSignatureRegistration Registration functions for Digital
 * Signature Algorithms.
 *
 * \brief An appropriate function from this group must be called before using
 * the associated digital signature functionality.
 *
 * This resolves linking of the dependent methods for a given digital signature
 * algorithm.
 * @{
 */

/**
 * \brief Register the mock digital signature algorithm.
 */
void vccrypt_digital_signature_register_mock();
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
 * \brief The mock structure for digital signature options.
 */
struct digital_signature_mock
{
    /** \brief init mock. */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_digital_signature_options_t*,
                vccrypt_digital_signature_context_t*)>>
    digital_signature_init_mock;

    /** \brief dispose mock. */
    std::shared_ptr<
        std::function<
            void (
                vccrypt_digital_signature_options_t*,
                vccrypt_digital_signature_context_t*)>>
    digital_signature_dispose_mock;

    /** \brief sign mock. */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_digital_signature_context_t*, vccrypt_buffer_t*,
                const vccrypt_buffer_t*, const uint8_t*, size_t)>>
    digital_signature_sign_mock;

    /** \brief verify mock. */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_digital_signature_context_t*, const vccrypt_buffer_t*,
                const vccrypt_buffer_t*, const uint8_t*, size_t)>>
    digital_signature_verify_mock;

    /** \brief keypair_create mock. */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_digital_signature_context_t*, vccrypt_buffer_t*,
                vccrypt_buffer_t*)>>
    digital_signature_keypair_create_mock;
};

#endif /* defined(__cplusplus) */

#endif  //VCCRYPT_MOCK_DIGITAL_SIGNATURE_HEADER_GUARD
