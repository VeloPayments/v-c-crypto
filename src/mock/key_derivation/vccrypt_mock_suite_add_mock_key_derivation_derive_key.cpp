/**
 * \file vccrypt_mock_suite_add_mock_key_derivation_derive_key.cpp
 *
 * Mock the key derivation algorithm derive key method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

using namespace std;

/**
 * \brief Mock the key derivation algorithm derive key method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when calling the derive key
 *                  function.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_key_derivation_derive_key(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_buffer_t*, vccrypt_key_derivation_context_t*,
            const vccrypt_buffer_t*, const vccrypt_buffer_t*,
            unsigned int)> func)
{
    key_derivation_mock* mock =
        (key_derivation_mock*)suite->key_derivation_opts.options_context;

    mock->key_derivation_derive_key_mock.reset(new (decltype (func))(func));

    return VCCRYPT_STATUS_SUCCESS;
}
