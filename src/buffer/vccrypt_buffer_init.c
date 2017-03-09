/**
 * \file buffer/vccrypt_buffer_init.c
 *
 * Initialize a buffer for general use.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/buffer.h>
#include <vpr/parameters.h>

//external reference to a unified buffer disposal method
extern void vccrypt_buffer_dispose(void*);

/**
 * Initialize a buffer with the given size.
 *
 * Note: the buffer is owned by the caller and must be disposed by calling the
 * dispose() method when no longer needed.
 *
 * \param buffer    the buffer to initialize.
 * \param alloc     the allocator options to use for this buffer.
 * \param size      the size of the buffer in bytes.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_buffer_init(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc, size_t size)
{
    /* model checks */
    MODEL_ASSERT(buffer != NULL);
    MODEL_ASSERT(alloc != NULL);
    MODEL_ASSERT(size > 0);

    /* initialize the structure */
    buffer->hdr.dispose = &vccrypt_buffer_dispose;
    buffer->alloc_opts = alloc;
    buffer->size = size;
    buffer->data = allocate(alloc, size);

    /* allocation failed. */
    if (buffer->data == NULL)
    {
        return 1;
    }

    /* clear out this structure */
    memset(buffer->data, 0, buffer->size);

    /* success */
    return 0;
}
