/**
 * \file test/padding/test_vccrypt_buffer_pad.cpp
 *
 * Unit tests for vccrypt_buffer_pad.
 *
 * \copyright 2020 Velo-Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vccrypt/padding.h>
#include <vpr/allocator/malloc_allocator.h>

/**
 * Test that passing an invalid value to vccrypt_buffer_pad results in
 * VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT.
 */
TEST(vccrypt_buffer_pad, parameter_checks)
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
        vccrypt_buffer_pad(nullptr, &alloc_opts, 16));
    ASSERT_EQ(
        VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT,
        vccrypt_buffer_pad(&buffer, nullptr, 16));
    ASSERT_EQ(
        VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT,
        vccrypt_buffer_pad(&buffer, &alloc_opts, 256));
    ASSERT_EQ(
        VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT,
        vccrypt_buffer_pad(&buffer, &alloc_opts, 0));

    /* cleanup. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * For any blocksize between 1 and 255 inclusive, for any value equal to or less
 * than the blocksize, the padding is correct.
 */
TEST(vccrypt_buffer_pad, happy_path)
{
    vccrypt_buffer_t buffer;
    allocator_options_t alloc_opts;

    /* create  the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    for (size_t blocksize = 1; blocksize < 256; ++blocksize)
    {
        for (size_t i = 0; i <= blocksize; ++i)
        {
            /* create a buffer of the correct size. */
            ASSERT_EQ(
                VCCRYPT_STATUS_SUCCESS,
                vccrypt_buffer_init(&buffer, &alloc_opts, i));

            /* set the buffer value. */
            memset(buffer.data, 0, buffer.size);

            /* PRECONDITION: the buffer size is equal to i. */
            ASSERT_EQ(i, buffer.size);

            /* padding the buffer should succeed. */
            ASSERT_EQ(
                VCCRYPT_STATUS_SUCCESS,
                vccrypt_buffer_pad(&buffer, &alloc_opts, blocksize));

            /* the buffer pointer is not null. */
            ASSERT_NE(nullptr, buffer.data);
            /* the resulting buffer size should be greater than i. */
            ASSERT_GT(buffer.size, i);
            /* the buffer size should be a multiple of blocksize. */
            ASSERT_EQ(0LU, buffer.size % blocksize);

            /* in the case that i < blocksize... */
            if (i < blocksize)
            {
                /* compute the padding size. */
                size_t padding_size = blocksize - (i % blocksize);

                /* the buffer size should be equal to blocksize. */
                ASSERT_EQ(buffer.size, blocksize);
                ASSERT_GE(buffer.size, padding_size);

                /* compute the padding byte. */
                uint8_t padding_byte = (uint8_t)padding_size;

                /* get a byte pointer for the buffer. */
                const uint8_t* buf = (const uint8_t*)buffer.data;

                /* each byte from the end of the buffer for blocksize bytes
                 * should be equal to padding_byte. */
                for (size_t j = buffer.size - 1;
                     j > buffer.size - padding_size - 1; --j)
                {
                    EXPECT_EQ(padding_byte, buf[j]);
                }
            }
            /* i == blocksize. */
            else
            {
                /* the buffer size should be greater than blocksize. */
                ASSERT_GT(buffer.size, blocksize);

                /* compute the block size byte. */
                ASSERT_LT(blocksize, 256);
                uint8_t block_size_byte = (uint8_t)blocksize;

                /* get a byte pointer for the buffer. */
                const uint8_t* buf = (const uint8_t*)buffer.data;

                /* each byte from the end of the buffer for blocksize bytes
                 * should be equal to block_size_byte. */
                for (size_t j = buffer.size - 1;
                     j > buffer.size - blocksize - 1; --j)
                {
                    EXPECT_EQ(block_size_byte, buf[j]);
                }
            }

            /* clean up buffer. */
            dispose((disposable_t*)&buffer);
        }
    }

    /* cleanup. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * If the buffer size is greater than the block size and not a multiple of it,
 * the padding works as expected.
 */
TEST(vccrypt_buffer_pad, greater_than_blocksize_padding)
{
    vccrypt_buffer_t buffer;
    allocator_options_t alloc_opts;
    const size_t BLOCK_SIZE = 16;
    const size_t BUFFER_SIZE = 35;
    const size_t EXPECTED_PADDED_BUFFER_SIZE = 48;

    /* create  the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* create a buffer of the correct size. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&buffer, &alloc_opts, BUFFER_SIZE));

    /* set the buffer value. */
    memset(buffer.data, 0, buffer.size);

    /* PRECONDITION: the buffer size is equal to BUFFER_SIZE. */
    ASSERT_EQ(BUFFER_SIZE, buffer.size);

    /* padding the buffer should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_pad(&buffer, &alloc_opts, BLOCK_SIZE));

    /* the buffer pointer is not null. */
    ASSERT_NE(nullptr, buffer.data);
    /* the resulting buffer size should be greater than BUFFER_SIZE. */
    ASSERT_GT(buffer.size, BUFFER_SIZE);
    /* the buffer size should be a multiple of blocksize. */
    ASSERT_EQ(0LU, buffer.size % BLOCK_SIZE);
    /* the buffer size should be equal to EXPECTED_PADDED_BUFFER_SIZE. */
    ASSERT_EQ(EXPECTED_PADDED_BUFFER_SIZE, buffer.size);

    /* compute the padding byte. */
    size_t padding_size = BLOCK_SIZE - (BUFFER_SIZE % BLOCK_SIZE);
    uint8_t padding_byte = (uint8_t)(BLOCK_SIZE - (BUFFER_SIZE % BLOCK_SIZE));

    /* get a byte pointer to this buffer. */
    const uint8_t* buf = (const uint8_t*)buffer.data;

    /* ensure that each padding byte is set correctly. */
    for (size_t i = buffer.size - 1; i > buffer.size - padding_size - 1; --i)
    {
        EXPECT_EQ(padding_byte, buf[i]);
    }

    /* cleanup. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
