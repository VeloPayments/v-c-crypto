/**
 * \file src/mock/block_cipher/vccrypt_mock_suite_add_mock_block_decrypt.cpp
 *
 * Mock the block cipher algorithm decrypt method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/mock_suite.h>

using namespace std;

/**
 * \brief Mock the block cipher algorithm decrypt method.
 *
 * \param suite     The suite to which this mock function should be attached.
 * \param func      The mock function to use when calling the block decrypt
 *                  function.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success
 *      - a non-zero error code on failure.
 */
int vccrypt_mock_suite_add_mock_block_decrypt(
    vccrypt_suite_options_t* suite,
    std::function<
        int (
            vccrypt_block_context_t*, const void*, const void*, void*)> func)
{
    block_mock* mock = (block_mock*)suite->block_cipher_opts.options_context;

    mock->block_decrypt_mock.reset(new (decltype (func))(func));

    return VCCRYPT_STATUS_SUCCESS;
}
