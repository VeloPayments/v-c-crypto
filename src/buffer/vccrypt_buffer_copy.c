/**
 * \file buffer/vccrypt_buffer_copy.c
 *
 * Copy one buffer to another.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/buffer.h>
#include <vpr/parameters.h>

/**
 * \brief Copy data from one buffer to another.
 *
 * Note: buffers must be the same size.
 *
 * \param dest      the destination buffer.
 * \param source    the source buffer.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_COPY_MISMATCHED_BUFFER_SIZES if the buffer
 *             sizes are mismatched and therefore this copy would overwrite one
 *             buffer.
 *      - a non-zero error code on failure.
 */
int vccrypt_buffer_copy(vccrypt_buffer_t* dest, const vccrypt_buffer_t* source)
{
    MODEL_ASSERT(dest != NULL);
    MODEL_ASSERT(dest->data != NULL);
    MODEL_ASSERT(source != NULL);
    MODEL_ASSERT(source->data != NULL);
    MODEL_ASSERT(dest->size == source->size);
    MODEL_ASSERT(dest->size > 0);

    /* only copy buffers of equal size. */
    if (dest->size != source->size)
    {
        return VCCRYPT_ERROR_BUFFER_COPY_MISMATCHED_BUFFER_SIZES;
    }

    /* copy data to the buffer. */
    memcpy(dest->data, source->data, dest->size);

    /* success */
    return VCCRYPT_STATUS_SUCCESS;
}
