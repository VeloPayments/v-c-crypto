/**
 * \file buffer/vccrypt_buffer_dispose.c
 *
 * Dispose a buffer.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/buffer.h>
#include <vpr/parameters.h>

/**
 * Dispose of a buffer structure.
 *
 * \param buffer    opaque pointer to the key buffer.
 */
void vccrypt_buffer_dispose(void* ptr)
{
    vccrypt_buffer_t* buffer = (vccrypt_buffer_t*)ptr;

    MODEL_ASSERT(buffer != NULL);
    MODEL_ASSERT(buffer->alloc_opts != NULL);
    MODEL_ASSERT(buffer->size > 0);
    MODEL_ASSERT(buffer->data != NULL);

    /* verify that the buffer data pointer is valid. */
    if (NULL != buffer->data)
    {
        /* clear out buffer data. */
        memset(buffer->data, 0, buffer->size);

        /* release buffer data */
        release(buffer->alloc_opts, buffer->data);
    }
}
