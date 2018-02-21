/**
 * \file vccrypt_stream_register_AES_256_3X_CTR.c
 *
 * This file contains the registration methods for the reference implementations
 * of the stream cipher interface for the triple-round variant of AES 256 CTR
 * MODE.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/stream_cipher.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

#include "stream_cipher_private.h"

/* instance data for AES-256-3X-CTR. */
static abstract_factory_registration_t aes_3x_impl;
static vccrypt_stream_options_t aes_3x_options;
static aes_ctr_options_data_t aes_3x_options_data;
static bool aes_3x_impl_registered = false;

/**
 * Register the triple round implementation of AES-256-CTR.
 */
void vccrypt_stream_register_AES_256_3X_CTR()
{
    MODEL_ASSERT(!aes_3x_impl_registered);

    /* only register once */
    if (aes_3x_impl_registered)
    {
        return;
    }

    /* set up options for aes-256-ctr-3x */
    aes_3x_options_data.round_multiplier = 3;
    aes_3x_options.hdr.dispose = 0; /* dispose by init */
    aes_3x_options.alloc_opts = 0; /* alloc by init */
    aes_3x_options.key_size = 32;
    aes_3x_options.IV_size = 8;
    aes_3x_options.maximum_message_size = UINT64_MAX;
    aes_3x_options.vccrypt_stream_alg_init = &vccrypt_aes_ctr_alg_init;
    aes_3x_options.vccrypt_stream_alg_start_encryption =
        &vccrypt_aes_ctr_alg_start_encryption;
    aes_3x_options.vccrypt_stream_alg_start_decryption =
        &vccrypt_aes_ctr_alg_start_decryption;
    aes_3x_options.vccrypt_stream_alg_encrypt =
        &vccrypt_aes_ctr_alg_encrypt; /* yes... both are the same. */
    aes_3x_options.vccrypt_stream_alg_decrypt =
        &vccrypt_aes_ctr_alg_encrypt; /* yes... both are the same. */
    aes_3x_options.data = &aes_3x_options_data;

    /* set up this registration for the abstract factory. */
    aes_3x_impl.interface =
        VCCRYPT_INTERFACE_STREAM;
    aes_3x_impl.implementation =
        VCCRYPT_STREAM_ALGORITHM_AES_256_3X_CTR;
    aes_3x_impl.implementation_features =
        VCCRYPT_STREAM_ALGORITHM_AES_256_3X_CTR;
    aes_3x_impl.factory = 0;
    aes_3x_impl.context = &aes_3x_options;

    /* register this instance. */
    abstract_factory_register(&aes_3x_impl);

    /* only register once */
    aes_3x_impl_registered = true;
}
