/**
 * \file buffer/vccrypt_buffer_init_for_base64_serialization.c
 *
 * Initialize a buffer for Base64 serialization.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/buffer.h>
#include <vpr/parameters.h>

/**
 * Initialize a buffer sized to serialize data in Base64.
 *
 * Note: the buffer is owned by the caller and must be disposed by calling the
 * dispose() method when no longer needed.
 *
 * \param buffer    the buffer to initialize.
 * \param alloc     the allocator options to use for this buffer.
 * \param size      the size of the buffer in bytes; the real size will be the
 *                  padded Base64 equivalent.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_buffer_init_for_base64_serialization(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc, size_t size)
{
    size_t base64_size = ((size * 4) / 3);

    //pad the buffer
    if (base64_size % 4 != 0)
        base64_size += 4 - base64_size % 4;

    return vccrypt_buffer_init(buffer, alloc, base64_size);
}
