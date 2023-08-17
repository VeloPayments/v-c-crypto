/**
 * \file test_vccrypt_buffer_read_hex.cpp
 *
 * Unit tests for vccrypt_buffer_read_hex.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <vpr/allocator/malloc_allocator.h>
#include <vccrypt/buffer.h>

/* DISABLED GTEST */
#if 0

class vccrypt_buffer_read_hex_test : public ::testing::Test {
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
 * Test that we can read hex values from an input buffer.
 */
TEST_F(vccrypt_buffer_read_hex_test, simple_test)
{
    size_t BUFFER_SIZE = 32;
    vccrypt_buffer_t source, dest;

    //create source buffer
    ASSERT_EQ(0,
        vccrypt_buffer_init_for_hex_serialization(
            &source, &alloc_opts, BUFFER_SIZE));

    //set data in source buffer
    memcpy(source.data, "000102030405060708090A0B0C0D0E0F"
                        "101112131415161718191A1B1C1D1E1F",
        64);

    //create destination buffer
    ASSERT_EQ(0, vccrypt_buffer_init(&dest, &alloc_opts, BUFFER_SIZE));

    //read hex digits from the input buffer, and write bytes to the output
    //buffer.
    ASSERT_EQ(0, vccrypt_buffer_read_hex(&dest, &source));

    //verify the byte values
    uint8_t* dest_bytes = (uint8_t*)dest.data;
    for (size_t i = 0; i < 16; ++i)
    {
        EXPECT_EQ((uint8_t)i, dest_bytes[i]);
        EXPECT_EQ((uint8_t)i + 16, dest_bytes[i + 16]);
    }

    //dispose buffers
    dispose((disposable_t*)&source);
    dispose((disposable_t*)&dest);
}

/**
 * Test that an error is returned when hex data is read into a destination
 * buffer too small to hold the data.
 */
TEST_F(vccrypt_buffer_read_hex_test, size_mismtach)
{
    size_t BUFFER_SIZE = 32;
    vccrypt_buffer_t source, dest;

    //create source buffer
    ASSERT_EQ(0,
        vccrypt_buffer_init_for_hex_serialization(
            &source, &alloc_opts, BUFFER_SIZE));

    //set the buffer to valid hex data
    memset(source.data, '0', BUFFER_SIZE * 2);

    //create destination buffer that is too small
    ASSERT_EQ(0, vccrypt_buffer_init(&dest, &alloc_opts, BUFFER_SIZE - 1));

    //an attempt to read hex digits from the source buffer will fail.
    EXPECT_NE(0, vccrypt_buffer_read_hex(&dest, &source));

    //dispose buffers
    dispose((disposable_t*)&source);
    dispose((disposable_t*)&dest);
}
#endif
