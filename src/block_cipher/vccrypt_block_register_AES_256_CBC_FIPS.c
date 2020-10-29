/**
 * \file vccrypt_block_register_AES_256_CBC_FIPS.c
 *
 * This file contains the registration methods for the reference implementations
 * of the block cipher interface for the FIPS version of AES 256 CBC MODE.
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

/* instance data for AES-256-CBC-FIPS. */
static abstract_factory_registration_t aes_fips_impl;
static vccrypt_block_options_t aes_fips_options;
static aes_cbc_options_data_t aes_fips_options_data;
static bool aes_fips_impl_registered = false;

/**
 * Register the FIPS compatible implementation of AES-256-CBC.
 */
void vccrypt_block_register_AES_256_CBC_FIPS()
{
    MODEL_ASSERT(!aes_fips_impl_registered);

    /* only register once */
    if (aes_fips_impl_registered)
    {
        return;
    }

    /* set up options for aes-256-cbc-fips */
    aes_fips_options_data.round_multiplier =
        VCCRYPT_AES_CBC_ALG_ROUND_MULT_FIPS;
    aes_fips_options.hdr.dispose = &vccrypt_aes_cbc_alg_options_dispose;
    aes_fips_options.alloc_opts = 0; /* alloc by init */
    aes_fips_options.key_size =
        VCCRYPT_AES_CBC_ALG_AES_256_KEY_SIZE;
    aes_fips_options.IV_size = VCCRYPT_AES_CBC_ALG_IV_SIZE;
    aes_fips_options.maximum_message_size = UINT64_MAX;
    aes_fips_options.vccrypt_block_alg_init = &vccrypt_aes_cbc_alg_init;
    aes_fips_options.vccrypt_block_alg_dispose = &vccrypt_aes_cbc_alg_dispose;
    aes_fips_options.vccrypt_block_alg_encrypt = &vccrypt_aes_cbc_alg_encrypt;
    aes_fips_options.vccrypt_block_alg_decrypt = &vccrypt_aes_cbc_alg_decrypt;
    aes_fips_options.data = &aes_fips_options_data;
    aes_fips_options.vccrypt_block_alg_options_init =
        &vccrypt_aes_cbc_alg_options_init;

    /* set up this registration for the abstract factory. */
    aes_fips_impl.interface =
        VCCRYPT_INTERFACE_BLOCK;
    aes_fips_impl.implementation =
        VCCRYPT_BLOCK_ALGORITHM_AES_256_CBC_FIPS;
    aes_fips_impl.implementation_features =
        VCCRYPT_BLOCK_ALGORITHM_AES_256_CBC_FIPS;
    aes_fips_impl.factory = 0;
    aes_fips_impl.context = &aes_fips_options;

    /* register this instance. */
    abstract_factory_register(&aes_fips_impl);

    /* only register once */
    aes_fips_impl_registered = true;
}
