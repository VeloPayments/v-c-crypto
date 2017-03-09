/**
 * \file test_vccrypt_buffer_init.cpp
 *
 * Unit tests for vccrypt_buffer_init.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vccrypt/buffer.h>

#include "../mock_allocator.h"

/**
 * Test that a buffer can be created and destroyed.
 */
TEST(vccrypt_buffer_init, simpletest)
{
    const size_t BUFFER_SIZE = 4;
    uint8_t backBuffer[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    //set up our allocator mock
    mock_allocator_options_init(&alloc_opts, false);
    mock_allocator_allocate_retval(&alloc_opts, backBuffer);

    //the buffer creation should succeed
    ASSERT_EQ(0, vccrypt_buffer_init(&buffer, &alloc_opts, BUFFER_SIZE));
    //the buffer alloc opts should be set
    EXPECT_EQ(&alloc_opts, buffer.alloc_opts);
    //the size should be 4
    EXPECT_EQ(BUFFER_SIZE, buffer.size);
    //the data points to our buffer
    EXPECT_EQ((void*)backBuffer, buffer.data);

    //the allocate method should have been called with the right size
    EXPECT_TRUE(mock_allocator_allocate_called(&alloc_opts, BUFFER_SIZE));

    //the buffer should have been cleared
    for (size_t i = 0; i < BUFFER_SIZE; ++i)
    {
        EXPECT_EQ(0, backBuffer[i]);
        backBuffer[i] = 0xFF;
    }

    //dispose of the structure
    dispose((disposable_t*)&buffer);

    //the release method should have been called
    EXPECT_TRUE(mock_allocator_release_called(&alloc_opts, backBuffer));

    //the buffer should have been cleared
    for (size_t i = 0; i < BUFFER_SIZE; ++i)
        EXPECT_EQ(0, backBuffer[i]);

    //dispose of our mock allocator
    dispose((disposable_t*)&alloc_opts);
}

/**
 * Test that an error status is returned if allocation fails.
 */
TEST(vccrypt_buffer_init, allocation_failure)
{
    const size_t BUFFER_SIZE = 4;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    //set up our allocator mock
    mock_allocator_options_init(&alloc_opts, false);
    mock_allocator_allocate_retval(&alloc_opts, nullptr);

    //the buffer creation should fail
    ASSERT_NE(0, vccrypt_buffer_init(&buffer, &alloc_opts, BUFFER_SIZE));

    //dispose of our mock allocator
    dispose((disposable_t*)&alloc_opts);
}
