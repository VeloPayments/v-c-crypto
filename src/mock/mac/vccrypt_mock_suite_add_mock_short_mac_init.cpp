/**
 * \file src/mock/mac/vccrypt_mock_suite_add_mock_short_mac_init.cpp
 *
 * Mock the short mac algorithm init method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

using namespace std;

/**
 * \brief Mock the short mac algorithm init method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use to initialize a mack algorithm
 *                  instance.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_short_mac_init(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_mac_options_t*, vccrypt_mac_context_t*,
            vccrypt_buffer_t*)> func)
{
    mac_mock* mock = (mac_mock*)suite->mac_short_opts.options_context;

    mock->mac_init_mock.reset(new (decltype (func))(func));

    return VCCRYPT_STATUS_SUCCESS;
}
