/**
 * \file vccrypt_mock_suite_add_mock_key_derivation_dispose.cpp
 *
 * Mock the key derivation algorithm dispose method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

using namespace std;

/**
 * \brief Mock the key derivation algorithm dispose method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to dispose a key derivation
 *                  algorithm instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_key_derivation_dispose(
    vccrypt_suite_options_t* suite,
    std::function<
        void (
            vccrypt_key_derivation_context_t*,
            vccrypt_key_derivation_options_t*)> func)
{
    key_derivation_mock* mock =
        (key_derivation_mock*)suite->key_derivation_opts.options_context;

    mock->key_derivation_dispose_mock.reset(new (decltype (func))(func));

    return VCCRYPT_STATUS_SUCCESS;
}
