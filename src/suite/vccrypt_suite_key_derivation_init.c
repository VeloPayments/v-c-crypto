/**
 * \file vccrypt_suite_key_derivation_init.c
 *
 * Initialize the key derivation algorithm for the given crypto suite.
 *
 * \copyright 2019 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vccrypt/suite.h>

/**
 * \brief Create an appropriate key derivation algorithm instance
 * for this crypto suite.
 *
 * \param context       The key derivation instance to initialize.
 * \param options       The options structure for this crypto suite.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int vccrypt_suite_key_derivation_init(
    vccrypt_key_derivation_context_t* context,
    vccrypt_suite_options_t* options)
{
    MODEL_ASSERT(NULL != context);
    MODEL_ASSERT(NULL != options);
    MODEL_ASSERT(NULL != options->vccrypt_suite_key_derivation_alg_init);

    return options->vccrypt_suite_key_derivation_alg_init(context, options);
}
