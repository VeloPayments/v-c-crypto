/**
 * \file test_vccrypt_buffer_move.cpp
 *
 * Unit tests for vccrypt_buffer_move.
 *
 * \copyright 2020-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <string.h>
#include <vccrypt/buffer.h>

#include "../mock_allocator.h"

TEST_SUITE(vccrypt_buffer_move);

/**
 * Test that a buffer can be initialized and moved.
 */
TEST(basics)
{
    const size_t BUFFER_SIZE = 4;
    uint8_t backBuffer[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    allocator_options_t alloc_opts;
    vccrypt_buffer_t newbuffer, oldbuffer;

    /* set up the allocator mock. */
    mock_allocator_options_init(&alloc_opts, false);
    mock_allocator_allocate_retval(&alloc_opts, backBuffer);

    /* PRECONDITIONS - clear both new and old buffer. */
    memset(&newbuffer, 0, sizeof(newbuffer));
    memset(&oldbuffer, 0, sizeof(oldbuffer));

    /* initializing the old buffer should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(&oldbuffer, &alloc_opts, BUFFER_SIZE));

    /* move the old buffer to the new buffer. */
    vccrypt_buffer_move(&newbuffer, &oldbuffer);

    /* the new buffer's allocator, data, and size are set. */
    TEST_ASSERT(&alloc_opts == newbuffer.alloc_opts);
    TEST_ASSERT((void*)backBuffer == newbuffer.data);
    TEST_ASSERT(BUFFER_SIZE == newbuffer.size);

    /* the old buffer's pointer is set to NULL. */
    TEST_ASSERT(nullptr == oldbuffer.data);
    TEST_ASSERT(0U == oldbuffer.size);

    /* clean up the new buffer. */
    dispose((disposable_t*)&newbuffer);
    /* clean up the mock allocator. */
    dispose((disposable_t*)&alloc_opts);
}
