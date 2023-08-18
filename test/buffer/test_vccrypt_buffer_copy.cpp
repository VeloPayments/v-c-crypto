/**
 * \file test_vccrypt_buffer_copy.cpp
 *
 * Unit tests for vccrypt_buffer_copy.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <vpr/allocator/malloc_allocator.h>
#include <vccrypt/buffer.h>

/* DISABLED GTEST */
#if 0

class vccrypt_buffer_copy_test : public ::testing::Test {
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
 * Test that a buffer can be copied.
 */
TEST_F(vccrypt_buffer_copy_test, simple_test)
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

    //copy the source data to the dest buffer
    ASSERT_EQ(0, vccrypt_buffer_copy(&dest, &source));

    //the two buffers should now match
    EXPECT_EQ(0, memcmp(dest.data, source.data, BUFFER_SIZE));

    //dispose buffers
    dispose((disposable_t*)&source);
    dispose((disposable_t*)&dest);
}

/**
 * Test that buffers of different sizes cannot be copied.
 */
TEST_F(vccrypt_buffer_copy_test, size_mismatch)
{
    size_t BUFFER_SIZE = 16;
    vccrypt_buffer_t source, dest;

    //create source buffer
    ASSERT_EQ(0, vccrypt_buffer_init(&source, &alloc_opts, BUFFER_SIZE));

    //create destination buffer
    ASSERT_EQ(0, vccrypt_buffer_init(&dest, &alloc_opts, BUFFER_SIZE + 1));

    //the copy should fail (dest.size != source.size)
    EXPECT_NE(0, vccrypt_buffer_copy(&dest, &source));

    //dispose buffers
    dispose((disposable_t*)&source);
    dispose((disposable_t*)&dest);
}
#endif
