/**
 * \file mock/key_derivation.h
 *
 * \brief Mock for the key derivation interface.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_MOCK_KEY_DERIVATION_HEADER_GUARD
#define VCCRYPT_MOCK_KEY_DERIVATION_HEADER_GUARD

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
 * \defgroup KeyDerivationAlgorithms Key Derivation Algorithms.
 *
 * \brief Algorithms optionally supported by the key derivation subsystem.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these algorithms to initialize a
 * \ref vccrypt_key_derivation_options_t structure. Registration is a link-time
 * optimization that ensures that only cryptographic primitives needed by the
 * application are linked in the application or library.
 *
 * @{
 */

/**
 * \brief Selector for mock.
 */
#define VCCRYPT_KEY_DERIVATION_ALGORITHM_MOCK 0x80000000

/**
 * @}
 */

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
 * \brief Register the mock key derivation algorithm.
 * 
 */
void vccrypt_key_derivation_register_mock();

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
 * \brief The mock structure for key derivation.
 */
struct key_derivation_mock
{

    /** \brief init mock. */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_key_derivation_context_t*,
                vccrypt_key_derivation_options_t*)>>
    key_derivation_init_mock;

    /** \brief dispose mock. */
    std::shared_ptr<
        std::function<
            void (
                vccrypt_key_derivation_context_t*,
                vccrypt_key_derivation_options_t*)>>
    key_derivation_dispose_mock;

    /** \brief derive_key mock. */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_buffer_t*,
                vccrypt_key_derivation_context_t*,
                const vccrypt_buffer_t*,
                const vccrypt_buffer_t*,
                unsigned int)>>
    key_derivation_derive_key_mock;
};

#endif /* defined(__cplusplus) */

#endif  //VCCRYPT_MOCK_KEY_DERIVATION_HEADER_GUARD
