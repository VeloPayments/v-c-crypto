/**
 * \file crypto_memcmp.c
 *
 * Timing-attack resistant memory comparison implementation.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vccrypt/compare.h>
#include <vpr/parameters.h>

/**
 * Compare two buffers in a timing-safe way.  Note that while this function is
 * named like memcmp and shares the same arguments, its behavior is different
 * due to the timing-safe guarantees.  memcmp short circuits on the first
 * difference.  This function gathers all differences into a saturated return
 * value.  Because of this, the ordering of memcmp is broken in this function.
 * This function cannot be used to sort values, but only for giving a
 * true-or-false answer to the question: are these two buffers equal?
 *
 * \param lhs       The left-hand-side buffer to compare.
 * \param rhs       The right-hand-side buffer to compare.
 * \param length    The length in bytes to compare.
 *
 * \returns 0 if these two buffers are equal, and a non-zero values if
 *          differences were encountered.
 */
int crypto_memcmp(const void* lhs, const void* rhs, size_t length)
{
    uint8_t* l = (uint8_t*)lhs;
    uint8_t* r = (uint8_t*)rhs;
    uint8_t cmp = 0;

    for (size_t i = 0; i < length; ++i)
    {
        cmp |= l[i] ^ r[i];
    }

    return (int)cmp;
}
