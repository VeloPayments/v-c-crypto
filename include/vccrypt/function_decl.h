/**
 * \file function_decl.h
 *
 * \brief Function declaration macros for vccrypt.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_FUNCTION_DECL_HEADER_GUARD
#define VCCRYPT_FUNCTION_DECL_HEADER_GUARD

#include <vpr/function_decl.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * We'll re-use the VPR macro here as a separate definition to stick with
 * VCCRYPT naming conventions.
 */
#define VCCRYPT_DECL_MUST_CHECK VPR_DECL_MUST_CHECK

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_FUNCTION_DECL_HEADER_GUARD
