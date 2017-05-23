/**
 * \file vccrypt_suite_cipher_key_agreement_init.c
 *
 * Initialize a key agreement algorithm instance suitable for ciphers
 * from this crypto suite.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/suite.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * Create an appropriate symmetric cipher key agreement algorithm instance for
 * this crypto suite.
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The key agreement algorithm instance to initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_suite_cipher_key_agreement_init(
    vccrypt_suite_options_t* options,
    vccrypt_key_agreement_context_t* context)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(options->vccrypt_suite_key_cipher_init != NULL);

    return options->vccrypt_suite_key_cipher_init(options, context);
}
