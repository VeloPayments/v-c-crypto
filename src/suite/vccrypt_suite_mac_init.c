/**
 * \file vccrypt_suite_mac_init.c
 *
 * Initialize the mac algorithm for the given crypto suite.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/suite.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * Create an appropriate message authentication code algorithm instance for this
 * crypto suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The message authentication code instance to
 *                      initialize.
 * \param key           The key to use for this algorithm.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_mac_init(
    vccrypt_suite_options_t* options, vccrypt_mac_context_t* context,
    vccrypt_buffer_t* key)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(key != NULL);
    MODEL_ASSERT(options->vccrypt_suite_mac_alg_init != NULL);

    return options->vccrypt_suite_mac_alg_init(options, context, key);
}
