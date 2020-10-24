/**
 * \file src/mock/mac/vccrypt_mock_suite_add_mock_mac_dispose.cpp
 *
 * Mock the mac algorithm dispose method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

using namespace std;

/**
 * \brief Mock the mac algorithm dispose method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to dispose a mack algorithm
 *                  instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_mac_dispose(
    vccrypt_suite_options_t* suite,
    std::function<
        void (vccrypt_mac_options_t*, vccrypt_mac_context_t*)> func)
{
    mac_mock* mock = (mac_mock*)suite->mac_opts.options_context;

    mock->mac_dispose_mock.reset(new (decltype (func))(func));

    return VCCRYPT_STATUS_SUCCESS;
}
