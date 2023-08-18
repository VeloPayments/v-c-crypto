/**
 * \file test_vccrypt_buffer_write_hex.cpp
 *
 * Unit tests for vccrypt_buffer_write_hex.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <vpr/allocator/malloc_allocator.h>
#include <vccrypt/buffer.h>

/* DISABLED GTEST */
#if 0

class vccrypt_buffer_write_hex_test : public ::testing::Test {
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
 * Test that we can write hex values to an output buffer.
 */
TEST_F(vccrypt_buffer_write_hex_test, simple_test)
{
    size_t BUFFER_SIZE = 32;
    vccrypt_buffer_t source, dest;

    //create source buffer
    ASSERT_EQ(0, vccrypt_buffer_init(&source, &alloc_opts, BUFFER_SIZE));

    //set data in source buffer
    uint8_t* source_bytes = (uint8_t*)source.data;
    for (size_t i = 0; i < 16; ++i)
    {
        source_bytes[i] = (uint8_t)i;
        source_bytes[i + 16] = (uint8_t)(i + 16);
    }

    //create destination buffer
    ASSERT_EQ(0,
        vccrypt_buffer_init_for_hex_serialization(
            &dest, &alloc_opts, BUFFER_SIZE));

    //write hex digits to the destination buffer
    EXPECT_EQ(0, vccrypt_buffer_write_hex(&dest, &source));

    //verify the hex values
    EXPECT_EQ(0,
        memcmp(dest.data, "000102030405060708090A0B0C0D0E0F"
                          "101112131415161718191A1B1C1D1E1F",
            dest.size));

    //dispose buffers
    dispose((disposable_t*)&source);
    dispose((disposable_t*)&dest);
}

/**
 * Test that the write fails if the destination buffer is too small.
 */
TEST_F(vccrypt_buffer_write_hex_test, size_error)
{
    size_t BUFFER_SIZE = 32;
    vccrypt_buffer_t source, dest;

    //create source buffer
    ASSERT_EQ(0, vccrypt_buffer_init(&source, &alloc_opts, BUFFER_SIZE));

    //create destination buffer
    ASSERT_EQ(0, vccrypt_buffer_init(&dest, &alloc_opts, BUFFER_SIZE));

    //write hex digits to the destination buffer should fail
    EXPECT_NE(0, vccrypt_buffer_write_hex(&dest, &source));

    //dispose buffers
    dispose((disposable_t*)&source);
    dispose((disposable_t*)&dest);
}
#endif
