/**
 * \file test_vccrypt_buffer_init_for_hex_serialization.cpp
 *
 * Unit tests for vccrypt_buffer_init_for_hex_serialization.
 *
 * \copyright 2017-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <vccrypt/buffer.h>

#include "../mock_allocator.h"

TEST_SUITE(vccrypt_buffer_init_for_hex_serialization);

/**
 * Test that a buffer can be created and destroyed.
 */
TEST(simpletest)
{
    const size_t BUFFER_SIZE = 4;
    const size_t HEX_BUFFER_SIZE = 8;
    uint8_t backBuffer[8] = { 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF };
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    //set up our allocator mock
    mock_allocator_options_init(&alloc_opts, false);
    mock_allocator_allocate_retval(&alloc_opts, backBuffer);

    //the buffer creation should succeed
    TEST_ASSERT(
        0
            == vccrypt_buffer_init_for_hex_serialization(
                    &buffer, &alloc_opts, BUFFER_SIZE));
    //the buffer alloc opts should be set
    TEST_EXPECT(&alloc_opts == buffer.alloc_opts);
    //the size should be 4
    TEST_EXPECT(HEX_BUFFER_SIZE == buffer.size);
    //the data points to our buffer
    TEST_EXPECT((void*)backBuffer == buffer.data);

    //the allocate method should have been called with the right size
    TEST_EXPECT(mock_allocator_allocate_called(&alloc_opts, HEX_BUFFER_SIZE));

    //the buffer should have been cleared
    for (size_t i = 0; i < HEX_BUFFER_SIZE; ++i)
    {
        TEST_EXPECT(0 == backBuffer[i]);
        backBuffer[i] = 0xFF;
    }

    //dispose of the structure
    dispose((disposable_t*)&buffer);

    //the release method should have been called
    TEST_EXPECT(mock_allocator_release_called(&alloc_opts, backBuffer));

    //the buffer should have been cleared
    for (size_t i = 0; i < HEX_BUFFER_SIZE; ++i)
    {
        TEST_EXPECT(0 == backBuffer[i]);
    }

    //clean up mock
    dispose((disposable_t*)&alloc_opts);
}

/**
 * Test that an error status is returned if allocation fails.
 */
TEST(allocation_failure)
{
    const size_t BUFFER_SIZE = 4;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    //set up our allocator mock
    mock_allocator_options_init(&alloc_opts, false);
    mock_allocator_allocate_retval(&alloc_opts, nullptr);

    //the buffer creation should fail
    TEST_ASSERT(
        0
            != vccrypt_buffer_init_for_hex_serialization(
                    &buffer, &alloc_opts, BUFFER_SIZE));

    //dispose of our mock allocator
    dispose((disposable_t*)&alloc_opts);
}
