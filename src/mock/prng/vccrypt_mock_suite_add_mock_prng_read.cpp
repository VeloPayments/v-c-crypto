/**
 * \file src/mock/prng/vccrypt_mock_suite_add_mock_prng_read.cpp
 *
 * Mock the prng algorithm read method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

using namespace std;

/**
 * \brief Mock the prng read method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to read from the prng instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_prng_read(
    vccrypt_suite_options_t* suite,
    std::function<int (vccrypt_prng_context_t*, uint8_t*, size_t)> func)
{
    prng_mock* mock = (prng_mock*)suite->prng_opts.options_context;

    mock->prng_read_mock.reset(new (decltype (func))(func));

    return VCCRYPT_STATUS_SUCCESS;
}
