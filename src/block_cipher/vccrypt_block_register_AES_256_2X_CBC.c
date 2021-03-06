/**
 * \file vccrypt_block_register_AES_256_2X_CBC.c
 *
 * This file contains the registration methods for the reference implementations
 * of the block cipher interface for the double-round version of
 * AES 256 CBC MODE.
 *
 * \copyright 2018-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/block_cipher.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

#include "block_cipher_private.h"

/* instance data for AES-256-2X-CBC. */
static abstract_factory_registration_t aes_2x_impl;
static vccrypt_block_options_t aes_2x_options;
static aes_cbc_options_data_t aes_2x_options_data;
static bool aes_2x_impl_registered = false;

/**
 * Register the double-round implementation of AES-256-CBC.
 */
void vccrypt_block_register_AES_256_2X_CBC()
{
    MODEL_ASSERT(!aes_2x_impl_registered);

    /* only register once */
    if (aes_2x_impl_registered)
    {
        return;
    }

    /* set up options for aes-256-2x-cbc */
    aes_2x_options_data.round_multiplier =
        VCCRYPT_AES_CBC_ALG_ROUND_MULT_2X;
    aes_2x_options.hdr.dispose = &vccrypt_aes_cbc_alg_options_dispose;
    aes_2x_options.alloc_opts = 0; /* alloc by init */
    aes_2x_options.key_size =
        VCCRYPT_AES_CBC_ALG_AES_256_KEY_SIZE;
    aes_2x_options.IV_size = VCCRYPT_AES_CBC_ALG_IV_SIZE;
    aes_2x_options.maximum_message_size = UINT64_MAX;
    aes_2x_options.vccrypt_block_alg_init = &vccrypt_aes_cbc_alg_init;
    aes_2x_options.vccrypt_block_alg_dispose = &vccrypt_aes_cbc_alg_dispose;
    aes_2x_options.vccrypt_block_alg_encrypt = &vccrypt_aes_cbc_alg_encrypt;
    aes_2x_options.vccrypt_block_alg_decrypt = &vccrypt_aes_cbc_alg_decrypt;
    aes_2x_options.data = &aes_2x_options_data;
    aes_2x_options.vccrypt_block_alg_options_init =
        &vccrypt_aes_cbc_alg_options_init;

    /* set up this registration for the abstract factory. */
    aes_2x_impl.interface =
        VCCRYPT_INTERFACE_BLOCK;
    aes_2x_impl.implementation =
        VCCRYPT_BLOCK_ALGORITHM_AES_256_2X_CBC;
    aes_2x_impl.implementation_features =
        VCCRYPT_BLOCK_ALGORITHM_AES_256_2X_CBC;
    aes_2x_impl.factory = 0;
    aes_2x_impl.context = &aes_2x_options;

    /* register this instance. */
    abstract_factory_register(&aes_2x_impl);

    /* only register once */
    aes_2x_impl_registered = true;
}
