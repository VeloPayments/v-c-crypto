/**
 * \file vccrypt_stream_register_AES_256_2X_CTR.c
 *
 * This file contains the registration methods for the reference implementations
 * of the stream cipher interface for the double-round variant of AES 256 CTR
 * MODE.
 *
 * \copyright 2018-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/stream_cipher.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

#include "stream_cipher_private.h"

/* instance data for AES-256-2X-CTR. */
static abstract_factory_registration_t aes_2x_impl;
static vccrypt_stream_options_t aes_2x_options;
static aes_ctr_options_data_t aes_2x_options_data;
static bool aes_2x_impl_registered = false;

/**
 * Register the double round implementation of AES-256-CTR.
 */
void vccrypt_stream_register_AES_256_2X_CTR()
{
    MODEL_ASSERT(!aes_2x_impl_registered);

    /* only register once */
    if (aes_2x_impl_registered)
    {
        return;
    }

    /* set up options for aes-256-ctr-2x */
    aes_2x_options_data.round_multiplier =
        VCCRYPT_AES_CTR_ALG_ROUND_MULT_2X;
    aes_2x_options.hdr.dispose = &vccrypt_aes_ctr_alg_options_dispose;
    aes_2x_options.alloc_opts = 0; /* alloc by init */
    aes_2x_options.key_size =
        VCCRYPT_AES_CTR_ALG_AES_256_KEY_SIZE;
    aes_2x_options.IV_size = VCCRYPT_AES_CTR_ALG_IV_SIZE;
    aes_2x_options.maximum_message_size = UINT64_MAX;
    aes_2x_options.vccrypt_stream_alg_init = &vccrypt_aes_ctr_alg_init;
    aes_2x_options.vccrypt_stream_alg_start_encryption =
        &vccrypt_aes_ctr_alg_start_encryption;
    aes_2x_options.vccrypt_stream_alg_continue_encryption =
        &vccrypt_aes_ctr_alg_continue_encryption;
    aes_2x_options.vccrypt_stream_alg_start_decryption =
        &vccrypt_aes_ctr_alg_start_decryption;
    aes_2x_options.vccrypt_stream_alg_continue_decryption =
        &vccrypt_aes_ctr_alg_continue_decryption;
    aes_2x_options.vccrypt_stream_alg_encrypt =
        &vccrypt_aes_ctr_alg_encrypt; /* yes... both are the same. */
    aes_2x_options.vccrypt_stream_alg_decrypt =
        &vccrypt_aes_ctr_alg_encrypt; /* yes... both are the same. */
    aes_2x_options.data = &aes_2x_options_data;
    aes_2x_options.vccrypt_stream_alg_options_init =
        &vccrypt_aes_ctr_alg_options_init;

    /* set up this registration for the abstract factory. */
    aes_2x_impl.interface =
        VCCRYPT_INTERFACE_STREAM;
    aes_2x_impl.implementation =
        VCCRYPT_STREAM_ALGORITHM_AES_256_2X_CTR;
    aes_2x_impl.implementation_features =
        VCCRYPT_STREAM_ALGORITHM_AES_256_2X_CTR;
    aes_2x_impl.factory = 0;
    aes_2x_impl.context = &aes_2x_options;

    /* register this instance. */
    abstract_factory_register(&aes_2x_impl);

    /* only register once */
    aes_2x_impl_registered = true;
}
