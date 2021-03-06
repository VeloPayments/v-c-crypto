/**
 * \file vccrypt_suite_buffer_init_for_mac_private_key.c
 *
 * Initialize a crypto buffer sized appropriately for the suite mac algorithm
 * private key.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/suite.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * \brief Create a buffer sized appropriately for the private key of this crypto
 * suite's message authentication code algorithm.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 * \param short_mac     Whether the buffer is for a short or long MAC.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int vccrypt_suite_buffer_init_for_mac_private_key(
    vccrypt_suite_options_t* options,
    vccrypt_buffer_t* buffer, bool short_mac)
{
    MODEL_ASSERT(buffer != NULL);
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(options->mac_opts.key_size > 0);

    size_t buffer_sz = short_mac
        ? options->mac_short_opts.key_size
        : options->mac_opts.key_size;

    return vccrypt_buffer_init(buffer, options->alloc_opts, buffer_sz);
}
