/**
 * \file src/mock/hash/vccrypt_mock_suite_add_mock_hash_init.cpp
 *
 * Mock the hash algorithm init method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

using namespace std;

/**
 * \brief Mock the hash algorithm init method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to initialize a hash algorithm
 *                  instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_hash_init(
    vccrypt_suite_options_t* suite,
    std::function<int (vccrypt_hash_options_t*, vccrypt_hash_context_t*)> func)
{
    hash_mock* mock = (hash_mock*)suite->hash_opts.options_context;

    mock->hash_init_mock.reset(new (decltype (func))(func));

    return VCCRYPT_STATUS_SUCCESS;
}
