/**
 * \file src/mock/mac/vccrypt_mock_suite_add_mock_mac_finalize.cpp
 *
 * Mock the mac algorithm finalize method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

using namespace std;

/**
 * \brief Mock the mac algorithm finalize method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when finalize is called.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_mac_finalize(
    vccrypt_suite_options_t* suite,
    std::function<
        int (vccrypt_mac_context_t*, vccrypt_buffer_t*)> func)
{
    mac_mock* mock = (mac_mock*)suite->mac_opts.options_context;

    mock->mac_finalize_mock.reset(new (decltype (func))(func));

    return VCCRYPT_STATUS_SUCCESS;
}
