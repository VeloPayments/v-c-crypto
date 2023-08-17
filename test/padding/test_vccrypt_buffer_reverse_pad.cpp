/**
 * \file test/padding/test_vccrypt_buffer_reverse_pad.cpp
 *
 * Unit tests for vccrypt_buffer_reverse_pad.
 *
 * \copyright 2020 Velo-Payments, Inc.  All rights reserved.
 */

#include <vccrypt/padding.h>
#include <vpr/allocator/malloc_allocator.h>

/* DISABLED GTEST */
#if 0

/**
 * Test that passing an invalid value to vccrypt_buffer_reverse_pad results in
 * VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT.
 */
TEST(vccrypt_buffer_reverse_pad, parameter_checks)
{
    vccrypt_buffer_t buffer;
    allocator_options_t alloc_opts;

    /* create  the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initialize the buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&buffer, &alloc_opts, 3));

    /* calling vccrypt_buffer_pad with an invalid argument causes an error. */
    ASSERT_EQ(
        VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT,
        vccrypt_buffer_reverse_pad(nullptr, &alloc_opts));
    ASSERT_EQ(
        VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT,
        vccrypt_buffer_reverse_pad(&buffer, nullptr));

    /* cleanup. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * A zero size buffer is an invalid padding.
 */
TEST(vccrypt_buffer_reverse_pad, zero_size_buffer)
{
    vccrypt_buffer_t buffer;
    allocator_options_t alloc_opts;

    /* create  the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initialize the buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&buffer, &alloc_opts, 0));

    /* This buffer is rejected. */
    ASSERT_EQ(
        VCCRYPT_ERROR_BUFFER_PADDING_SCHEME_INVALID,
        vccrypt_buffer_reverse_pad(&buffer, &alloc_opts));

    /* cleanup. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * A one byte buffer is an invalid padding.
 */
TEST(vccrypt_buffer_reverse_pad, one_byte_buffer)
{
    vccrypt_buffer_t buffer;
    allocator_options_t alloc_opts;

    /* create  the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initialize the buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&buffer, &alloc_opts, 1));

    /* This buffer is rejected. */
    ASSERT_EQ(
        VCCRYPT_ERROR_BUFFER_PADDING_SCHEME_INVALID,
        vccrypt_buffer_reverse_pad(&buffer, &alloc_opts));

    /* cleanup. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * If the last byte is 0, then the padding scheme is invalid.
 */
TEST(vccrypt_buffer_reverse_pad, last_byte_zero)
{
    vccrypt_buffer_t buffer;
    allocator_options_t alloc_opts;

    /* create  the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initialize the buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&buffer, &alloc_opts, 16));

    /* clear the buffer. */
    memset(buffer.data, 0, buffer.size);

    /* This buffer is rejected. */
    ASSERT_EQ(
        VCCRYPT_ERROR_BUFFER_PADDING_SCHEME_INVALID,
        vccrypt_buffer_reverse_pad(&buffer, &alloc_opts));

    /* cleanup. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * If the last byte is greater than the buffer size, then the padding scheme is
 * invalid.
 */
TEST(vccrypt_buffer_reverse_pad, last_byte_greater_than_buffer_size)
{
    vccrypt_buffer_t buffer;
    allocator_options_t alloc_opts;

    /* create  the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initialize the buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&buffer, &alloc_opts, 16));

    /* clear the buffer. */
    memset(buffer.data, 0, buffer.size);

    /* get a byte pointer to this buffer. */
    uint8_t* buf = (uint8_t*)buffer.data;

    /* set the last byte to the size of the buffer + 1. */
    buf[15] = 16 + 1;

    /* This buffer is rejected. */
    ASSERT_EQ(
        VCCRYPT_ERROR_BUFFER_PADDING_SCHEME_INVALID,
        vccrypt_buffer_reverse_pad(&buffer, &alloc_opts));

    /* cleanup. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * If the last byte is equal to the buffer size, then the padding scheme is
 * invalid.
 */
TEST(vccrypt_buffer_reverse_pad, last_byte_equal_to_buffer_size)
{
    vccrypt_buffer_t buffer;
    allocator_options_t alloc_opts;

    /* create  the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initialize the buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&buffer, &alloc_opts, 16));

    /* clear the buffer. */
    memset(buffer.data, 0, buffer.size);

    /* get a byte pointer to this buffer. */
    uint8_t* buf = (uint8_t*)buffer.data;

    /* set the last byte to the size of the buffer. */
    buf[15] = 16;

    /* This buffer is rejected. */
    ASSERT_EQ(
        VCCRYPT_ERROR_BUFFER_PADDING_SCHEME_INVALID,
        vccrypt_buffer_reverse_pad(&buffer, &alloc_opts));

    /* cleanup. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * If the padding bytes don't equal the last padding byte, the padding scheme is
 * invalid.
 */
TEST(vccrypt_buffer_reverse_pad, padding_byte_equality)
{
    vccrypt_buffer_t buffer;
    allocator_options_t alloc_opts;

    /* create  the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initialize the buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&buffer, &alloc_opts, 20));

    /* clear the buffer. */
    memset(buffer.data, 0, buffer.size);

    /* get a byte pointer to this buffer. */
    uint8_t* buf = (uint8_t*)buffer.data;

    /* set the last byte to the size of the buffer. */
    buf[19] = 0x04;
    buf[18] = 0x04;
    buf[17] = 0x04;
    buf[16] = 0x05; /* WRONG */

    /* This buffer is rejected. */
    ASSERT_EQ(
        VCCRYPT_ERROR_BUFFER_PADDING_SCHEME_INVALID,
        vccrypt_buffer_reverse_pad(&buffer, &alloc_opts));

    /* cleanup. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * A valid padded buffer can be unpadded.
 */
TEST(vccrypt_buffer_reverse_pad, happy_path)
{
    vccrypt_buffer_t buffer;
    allocator_options_t alloc_opts;
    const uint8_t EXPECTED_BYTES[] = { 0x01, 0x02, 0x03, 0x04 };

    /* create  the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initialize the buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&buffer, &alloc_opts, 8));

    /* "pad" the buffer. */
    memset(buffer.data, 0x04, buffer.size);

    /* copy the expected bytes into the buffer. */
    memcpy(buffer.data, EXPECTED_BYTES, sizeof(EXPECTED_BYTES));

    /* This buffer is successfully unpadded. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_reverse_pad(&buffer, &alloc_opts));

    /* the updated buffer has a valid data pointer. */
    ASSERT_NE(nullptr, buffer.data);

    /* the new buffer size is the size of the expected bytes array. */
    ASSERT_EQ(sizeof(EXPECTED_BYTES), buffer.size);

    /* the buffer was copied over correctly. */
    EXPECT_EQ(0, memcmp(buffer.data, EXPECTED_BYTES, buffer.size));

    /* cleanup. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
#endif
