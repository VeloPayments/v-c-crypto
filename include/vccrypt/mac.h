/**
 * \file mac.h
 *
 * Message Authentication Codes.  The Message Authentication Code interface
 * provides a method by which a private key can be used to generate an
 * authentication code that can be verified by anyone in possession of that key.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_MAC_HEADER_GUARD
#define VCCRYPT_MAC_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <vpr/disposable.h>

/**
 * \brief message authentication code options.
 *
 * These options are returned by the vccrypt_mac_get_options() method, which can
 * be used to select options for an appropriate message authentication code.
 * Alternately, the vccrypt_suite_get_mac_options() method can be used to select
 * the appropriate message authentication options for a given crypto suite.
 */

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_MAC_HEADER_GUARD
