/**
 * \file
 * mock/digital_signature/vccrypt_mock_suite_add_mock_digital_signature_init.cpp
 *
 * Mock the digital signature algorithm init method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

using namespace std;

/**
 * \brief Mock the digital signature algorithm init method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to initialize a digital signature
 *                  algorithm instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_digital_signature_init(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_digital_signature_options_t*,
            vccrypt_digital_signature_context_t*)> func)
{
    digital_signature_mock* mock =
        (digital_signature_mock*)suite->sign_opts.options_context;

    mock->digital_signature_init_mock.reset(new (decltype (func))(func));

    return VCCRYPT_STATUS_SUCCESS;
}
