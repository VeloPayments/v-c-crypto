/**
 * \file
 * vccrypt_mock_suite_add_mock_cipher_key_agreement_keypair_create.cpp
 *
 * Mock the key agreement algorithm keypair create method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

using namespace std;

/**
 * \brief Mock the cipher key agreement algorithm keypair create function.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when calling the keypair create
 *                  method.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_cipher_key_agreement_keypair_create(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_key_agreement_context_t*, vccrypt_buffer_t*,
            vccrypt_buffer_t*)> func)
{
    key_agreement_mock* mock =
        (key_agreement_mock*)suite->key_cipher_opts.options_context;

    mock->key_agreement_keypair_create_mock.reset(new (decltype (func))(func));

    return VCCRYPT_STATUS_SUCCESS;
}
