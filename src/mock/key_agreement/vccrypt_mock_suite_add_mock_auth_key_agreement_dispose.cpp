/**
 * \file vccrypt_mock_suite_add_mock_auth_key_agreement_dispose.cpp
 *
 * Mock the key agreement algorithm dispose method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

using namespace std;

/**
 * \brief Mock the auth key agreement algorithm dispose method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to dispose an auth key agreement
 *                  algorithm instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_auth_key_agreement_dispose(
    vccrypt_suite_options_t* suite,
    std::function<
        void (
            vccrypt_key_agreement_options_t*,
            vccrypt_key_agreement_context_t*)> func)
{
    key_agreement_mock* mock =
        (key_agreement_mock*)suite->key_auth_opts.options_context;

    mock->key_agreement_dispose_mock.reset(new (decltype (func))(func));

    return VCCRYPT_STATUS_SUCCESS;
}
