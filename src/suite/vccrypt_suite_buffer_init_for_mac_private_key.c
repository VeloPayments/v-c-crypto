/**
 * \file vccrypt_suite_buffer_init_for_mac_private_key.c
 *
 * Initialize a crypto buffer sized appropriately for the suite mac algorithm
 * private key.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/suite.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * Create a buffer sized appropriately for the private key of this crypto
 * suite's message authentication code algorithm.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_buffer_init_for_mac_private_key(
    vccrypt_suite_options_t* options,
    vccrypt_buffer_t* buffer)
{
    MODEL_ASSERT(buffer != NULL);
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(options->mac_opts != 0);
    MODEL_ASSERT(options->mac_opts.key_size > 0);

    return vccrypt_buffer_init(
        buffer, options->alloc_opts, options->mac_opts.key_size);
}
