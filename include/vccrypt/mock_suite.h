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
#endif /* defined(__cplusplus) */

#endif  //VCCRYPT_MOCK_SUITE_HEADER_GUARD
