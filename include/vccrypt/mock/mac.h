/**
 * \file mock/mac.h
 *
 * \brief Mock the mac interface.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_MOCK_MAC_HEADER_GUARD
#define VCCRYPT_MOCK_MAC_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <vccrypt/buffer.h>
#include <vccrypt/function_decl.h>
#include <vccrypt/interfaces.h>
#include <vccrypt/mac.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/**
 * \defgroup MACAlgorithms Message Authentication Code Algorithms.
 *
 * \brief Algorithms optionally supported by the MAC subsystem.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these MAC algorithms to initialize a
 * vccrypt_mac_options_t structure. Registration is a link-time optimization
 * that ensures that only cryptographic primitives needed by the application are
 * linked in the application or library.
 *
 * @{
 */

/**
 * \brief Selector for mock.
 */
#define VCCRYPT_MAC_ALGORITHM_MOCK 0x80000000

/**
 * \brief Selector for short mock.
 */
#define VCCRYPT_MAC_ALGORITHM_SHORT_MOCK 0x40000000
/**
 * @}
 */

/**
 * \defgroup MACRegistration Registration functions for MAC Algorithms.
 *
 * \brief An appropriate function in this group must be called before using the
 * associated MAC functionality.
 *
 * This resolves linking of the dependent methods for a given MAC algorithm. 
 * @{
 */

/**
 * \brief Register the mac mock.
 */
void vccrypt_mac_register_mock();

/**
 * \brief Register the short mac mock.
 */
void vccrypt_mac_register_short_mock();

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
 * \brief The mock structure for mac options.
 */
struct mac_mock
{
    /**
     * \brief init mock.
     */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_mac_options_t*, vccrypt_mac_context_t*,
                const vccrypt_buffer_t*)>>
    mac_init_mock;

    /**
     * \brief dispose mock.
     */
    std::shared_ptr<
        std::function<void (vccrypt_mac_options_t*, vccrypt_mac_context_t*)>>
    mac_dispose_mock;

    /**
     * \brief digest mock.
     */
    std::shared_ptr<
        std::function<int (vccrypt_mac_context_t*, const uint8_t*, size_t)>>
    mac_digest_mock;

    /**
     * \brief finalize mock.
     */
    std::shared_ptr<
        std::function<int (vccrypt_mac_context_t*, vccrypt_buffer_t*)>>
    mac_finalize_mock;
};

#endif /* defined(__cplusplus) */

#endif  //VCCRYPT_MOCK_MAC_HEADER_GUARD
