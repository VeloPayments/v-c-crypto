/**
 * \file vccrypt/version.h
 *
 * \brief Return the version string for the vccrypt library.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#ifndef  VCCRYPT_VERSION_HEADER_GUARD
# define VCCRYPT_VERSION_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef   __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * \brief Return the version string for the vccrypt library.
 *
 * \returns a const version string for this library.
 */
const char* vccrypt_version();

/* make this header C++ friendly. */
#ifdef   __cplusplus
}
#endif /*__cplusplus*/

#endif /*VCCRYPT_VERSION_HEADER_GUARD*/
