/**
 * \file vccrypt_aes_ctr_alg_options_init.c
 *
 * Do implementation-specific options structure initialization.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vpr/parameters.h>

#include "stream_cipher_private.h"

/**
 * \brief Implementation specific options init method.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options structure for this method.
 *
 * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
 */
int vccrypt_aes_ctr_alg_options_init(
    void* UNUSED(options), allocator_options_t* UNUSED(alloc_opts))
{
    /* do nothing. */

    return VCCRYPT_STATUS_SUCCESS;
}
