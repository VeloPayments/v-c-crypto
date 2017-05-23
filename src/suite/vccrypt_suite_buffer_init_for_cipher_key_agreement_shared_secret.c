/**
 * \file vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret.c
 *
 * Initialize a crypto buffer sized appropriately for the suite cipher key
 * agreement shared secret key.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/suite.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * Create a buffer sized appropriately for the shared secret of this crypto
 * suite's key agreement algorithm for ciphers.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
    vccrypt_suite_options_t* options,
    vccrypt_buffer_t* buffer)
{
    MODEL_ASSERT(buffer != NULL);
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(options->alloc_opts != 0);
    MODEL_ASSERT(options->key_cipher_opts.shared_secret_size > 0);

    return vccrypt_buffer_init(
        buffer, options->alloc_opts,
        options->key_cipher_opts.shared_secret_size);
}
