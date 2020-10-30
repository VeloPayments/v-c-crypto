/**
 * \file vccrypt_mock_suite_add_mock_stream_decrypt.cpp
 *
 * Mock the stream cipher algorithm decrypt method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

using namespace std;

/**
 * \brief Mock the stream cipher algorithm decrypt method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to call when the decrypt method is called.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_stream_decrypt(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_stream_context_t*, const void*, size_t, void*,
            size_t*)> func)
{
    stream_mock* mock = (stream_mock*)suite->stream_cipher_opts.options_context;

    mock->stream_decrypt_mock.reset(new (decltype (func))(func));

    return VCCRYPT_STATUS_SUCCESS;
}
