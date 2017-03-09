/**
 * \file buffer/vccrypt_buffer_init_for_hex_serialization.c
 *
 * Initialize a buffer for hex serialization.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/buffer.h>
#include <vpr/parameters.h>

/**
 * Initialize a buffer sized to serialize data in hexadecimal.
 *
 * Note: the buffer is owned by the caller and must be disposed by calling the
 * dispose() method when no longer needed.
 *
 * \param buffer    the buffer to initialize.
 * \param alloc     the allocator options to use for this buffer.
 * \param size      the size of the buffer in bytes; the real size will be the
 *                  hexadecimal equivalent (size * 2).
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_buffer_init_for_hex_serialization(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc, size_t size)
{
    return vccrypt_buffer_init(buffer, alloc, size * 2);
}
