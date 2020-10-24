/**
 * \file prng.h
 *
 * \brief Mock implementation of the prng interface.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_MOCK_PRNG_HEADER_GUARD
#define VCCRYPT_MOCK_PRNG_HEADER_GUARD

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <vccrypt/buffer.h>
#include <vccrypt/error_codes.h>
#include <vccrypt/function_decl.h>
#include <vccrypt/interfaces.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>
#include <vpr/uuid.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup PRNGSources Cryptographic PRNG sources.
 *
 * \brief Sources optionally supported by the CPRNG subsystem.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these algorithms to initialize a
 * \ref vccrypt_prng_options_t structure. Registration is a link-time
 * optimization that ensures that only cryptographic primitives needed by the
 * application are linked in the application or library.
 *
 * @{
 */

/**
 * \brief Selector for the CPRNG provided by the operating system.
 */
#define VCCRYPT_PRNG_SOURCE_MOCK 0x80000000
/**
 * @}
 */

/**
 * \defgroup PRNGSourceRegistration Registration functions for PRNG sources.
 *
 * \brief An appropriate function in this group must be called before using the
 * associated PRNG functionality.
 *
 * This resolves linking of the dependent methods for a given PRNG source.
 * @{
 */

/**
 * \brief Register the mock CPRNG source.
 */
void vccrypt_prng_register_source_mock();
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

struct prng_mock
{
    /** \brief Mock for the prng init method. */
    std::shared_ptr<
        std::function<int (vccrypt_prng_options_t*, vccrypt_prng_context_t*)>>
    prng_init_mock;

    /** \brief Mock for the prng dispose method. */
    std::shared_ptr<
        std::function<void (vccrypt_prng_options_t*, vccrypt_prng_context_t*)>>
    prng_dispose_mock;

    /** \brief Mock for the prng read method. */
    std::shared_ptr<
        std::function<int (vccrypt_prng_context_t*, uint8_t*, size_t)>>
    prng_read_mock;
};

#endif /* defined(__cplusplus) */

#endif  //VCCRYPT_MOCK_PRNG_HEADER_GUARD
