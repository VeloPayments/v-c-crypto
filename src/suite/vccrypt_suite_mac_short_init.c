/**
 * \file vccrypt_suite_mac_short_init.c
 *
 * Initialize the short mac algorithm for the given crypto suite.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/suite.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * \brief Create an appropriate short message authentication code algorithm
 * instance for this crypto suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The message authentication code instance to
 *                      initialize.
 * \param key           The key to use for this algorithm.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int vccrypt_suite_mac_short_init(
    vccrypt_suite_options_t* options, vccrypt_mac_context_t* context,
    const vccrypt_buffer_t* key)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(key != NULL);
    MODEL_ASSERT(options->vccrypt_suite_mac_short_alg_init != NULL);

    return options->vccrypt_suite_mac_short_alg_init(options, context, key);
}
