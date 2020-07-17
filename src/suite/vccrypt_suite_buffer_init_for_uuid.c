/**
 * \file vccrypt_suite_buffer_init_for_uuid.c
 *
 * Initialize a crypto buffer sized appropriately for the suite auth key
 * agreement nonce.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/suite.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * \brief Create a buffer sized appropriately for holding a UUID in raw byte
 * form.
 *
 * \param options       The options structure for this crypto suite.
 * \param buffer        The buffer instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero return code on failure.
 */
int
vccrypt_suite_buffer_init_for_uuid(
    vccrypt_suite_options_t* options, vccrypt_buffer_t* buffer)
{
    MODEL_ASSERT(buffer != NULL);
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(options->alloc_opts != 0);

    return vccrypt_buffer_init(buffer, options->alloc_opts, 16);
}
