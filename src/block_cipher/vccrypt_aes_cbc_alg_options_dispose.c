/**
 * \file vccrypt_aes_cbc_alg_options_dispose.c
 *
 * Dispose of aes cbc block cipher options.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "block_cipher_private.h"

/**
 * Dispose of the options structure.
 *
 * \param options   the options structure to dispose.
 */
void vccrypt_aes_cbc_alg_options_dispose(
    void* disp)
{
    MODEL_ASSERT(disp != NULL);

    memset(disp, 0, sizeof(vccrypt_block_options_t));
}
