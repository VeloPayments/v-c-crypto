/**
 * \file vccrypt_aes_ctr_incr.c
 *
 * Increment a 128-bit counter value for AES counter mode.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vpr/parameters.h>

#include "stream_cipher_private.h"

/**
 * Increment the 128-bit counter by one.
 *
 * \param ctr       Pointer to the 128-bit counter.
 */
void vccrypt_aes_ctr_incr(
    uint8_t* ctr)
{
    int i = 16;

    do
    {
        /* get to the next index of this 128-bit value. */
        --i;

        /* increment this 8-bit portion of the value */
        ++(ctr[i]);

        /* a 0 means that we've overflowed and need to carry.  Otherwise, we're
         * done. */
        if (ctr[i] != 0)
            return;

    } while (i > 0);
}
