/**
 * \file vccrypt_suite_stream_init.c
 *
 * Initialize a stream cipher for this crypto suite.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/suite.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * \brief
 *
 * \param options       The options structure for this crypto suite.
 * \param context       The stream cipher instance to initialize.
 * \param key           The key to use for this algorithm.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int vccrypt_suite_stream_init(
    vccrypt_stream_options_t* options, vccrypt_stream_context_t* context,
    vccrypt_buffer_t* key)
{

    MODEL_ASSERT(NULL != options);
    MODEL_ASSERT(NULL != options->vccrypt_stream_alg_init);
    MODEL_ASSERT(NULL != context);
    MODEL_ASSERT(NULL != key);


    return options->vccrypt_stream_alg_init(options, context, key);
}
