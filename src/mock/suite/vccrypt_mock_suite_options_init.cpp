/**
 * \file mock/suite/vccrypt_mock_suite_options_init.cpp
 *
 * Initialize a mock crypto suite options structure.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

/**
 * \brief Initialize a mock crypto suite options structure.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options to use for this suite.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_options_init(
    vccrypt_suite_options_t* suite, allocator_options_t* alloc_opts)
{
    return
        vccrypt_suite_options_init(suite, alloc_opts, VCCRYPT_SUITE_MOCK);
}
