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

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_MOCK_SUITE_HEADER_GUARD
