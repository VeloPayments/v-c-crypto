/**
 * \file compare.h
 *
 * \brief Timing attack resistant comparison routines.
 *
 * \copyright 2017-2022 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_COMPARE_HEADER_GUARD
#define VCCRYPT_COMPARE_HEADER_GUARD

#include <stddef.h>
#include <vccrypt/function_decl.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \brief Compare two buffers in a timing-safe way.
 *
 * Note that while this function is named like memcmp and shares the same
 * arguments, its behavior is different due to the timing-safe guarantees.
 * memcmp short circuits on the first difference.  This function gathers all
 * differences into a saturated return value.  Because of this, the ordering of
 * memcmp is broken in this function. This function cannot be used to sort
 * values, but only for giving a true-or-false answer to the question: are these
 * two buffers equal?
 *
 * \param lhs       The left-hand-side buffer to compare.
 * \param rhs       The right-hand-side buffer to compare.
 * \param length    The length in bytes to compare.
 *
 * \returns 0 if these two buffers are equal, and a non-zero values if
 *          differences were encountered.
 */
int VCCRYPT_DECL_MUST_CHECK crypto_memcmp(
    const void* lhs, const void* rhs, size_t length);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_COMPARE_HEADER_GUARD
