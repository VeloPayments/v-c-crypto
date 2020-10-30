/**
 * \file vccrypt_mock_suite_add_mock_stream_start_decryption.cpp
 *
 * Mock the stream cipher algorithm start decryption method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

using namespace std;

/**
 * \brief Mock the stream cipher algorithm start decryption method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to call when the start decryption method
 *                  is called.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_stream_start_decryption(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_stream_context_t*, const void*, size_t*)> func)
{
    stream_mock* mock = (stream_mock*)suite->stream_cipher_opts.options_context;

    mock->stream_start_decryption_mock.reset(new (decltype (func))(func));

    return VCCRYPT_STATUS_SUCCESS;
}
