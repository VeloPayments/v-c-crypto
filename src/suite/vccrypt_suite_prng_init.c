/**
 * \file vccrypt_suite_prng_init.c
 *
 * Initialize a prng instance for this crypto suite.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/suite.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * Open an appropriate prng source for this crypto suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The prng instance to initialize with this source.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_prng_init(
    vccrypt_suite_options_t* options, vccrypt_prng_context_t* context)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(options->vccrypt_suite_prng_alg_init != NULL);

    return options->vccrypt_suite_prng_alg_init(options, context);
}
