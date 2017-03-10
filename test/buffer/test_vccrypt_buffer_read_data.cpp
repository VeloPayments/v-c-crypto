/**
 * \file test_vccrypt_buffer_read_data.cpp
 *
 * Unit tests for vccrypt_buffer_read_data.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vpr/allocator/malloc_allocator.h>
#include <vccrypt/buffer.h>

class vccrypt_buffer_read_data_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        malloc_allocator_options_init(&alloc_opts);
    }

    void TearDown() override
    {
        dispose((disposable_t*)&alloc_opts);
    }

    allocator_options_t alloc_opts;
};

/**
 * Test that we can read a C array into a buffer.
 */
TEST_F(vccrypt_buffer_read_data_test, simple_test)
{
    size_t BUFFER_SIZE = 16;
    vccrypt_buffer_t source, dest;

    //create source buffer
    ASSERT_EQ(0, vccrypt_buffer_init(&source, &alloc_opts, BUFFER_SIZE));

    //set data in source buffer
    memset(source.data, 0xF7, BUFFER_SIZE);

    //create destination buffer
    ASSERT_EQ(0, vccrypt_buffer_init(&dest, &alloc_opts, BUFFER_SIZE));

    //set data in destination
    memset(dest.data, 0x1A, BUFFER_SIZE);

    //the two buffers do not match
    ASSERT_NE(0, memcmp(dest.data, source.data, BUFFER_SIZE));

    //copy the source data to the dest buffer, treating the source buffer as a C
    //array.
    ASSERT_EQ(0, vccrypt_buffer_read_data(&dest, source.data, BUFFER_SIZE));

    //the two buffers should now match
    EXPECT_EQ(0, memcmp(dest.data, source.data, BUFFER_SIZE));

    //dispose buffers
    dispose((disposable_t*)&source);
    dispose((disposable_t*)&dest);
}

/**
 * Test that attempting to copy more data than in the destination buffer results
 * in an error.
 */
TEST_F(vccrypt_buffer_read_data_test, size_mismatch)
{
    size_t BUFFER_SIZE = 16;
    vccrypt_buffer_t source, dest;

    //create source buffer
    ASSERT_EQ(0, vccrypt_buffer_init(&source, &alloc_opts, BUFFER_SIZE + 1));

    //create destination buffer
    ASSERT_EQ(0, vccrypt_buffer_init(&dest, &alloc_opts, BUFFER_SIZE));

    //the data read should fail.
    EXPECT_NE(0, vccrypt_buffer_read_data(&dest, source.data, BUFFER_SIZE + 1));

    //dispose buffers
    dispose((disposable_t*)&source);
    dispose((disposable_t*)&dest);
}
