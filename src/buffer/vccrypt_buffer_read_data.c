/**
 * \file buffer/vccrypt_buffer_read_data.c
 *
 * Read data from a C array into a buffer.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/buffer.h>
#include <vpr/parameters.h>

/**
 * Read data from a C buffer.
 *
 * Note: C buffer size cannot exceed buffer size.
 *
 * \param dest      the destination buffer.
 * \param source    the source C buffer.
 * \param size      the number of bytes to read.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_buffer_read_data(
    vccrypt_buffer_t* dest, const void* source, size_t size)
{
    MODEL_ASSERT(dest != NULL);
    MODEL_ASSERT(dest->data != NULL);
    MODEL_ASSERT(source != NULL);
    MODEL_ASSERT(size > 0);
    MODEL_ASSERT(size <= dest->size);

    /* we can't exceed the destination buffer size. */
    if (size > dest->size)
        return 1;

    /* copy the data. */
    memcpy(dest->data, source, size);

    /* success */
    return 0;
}
