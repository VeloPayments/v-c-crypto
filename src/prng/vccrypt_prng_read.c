/**
 * \file vccrypt_prng_read.c
 *
 * Read random bytes from a PRNG source.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/prng.h>
#include <vpr/parameters.h>

/**
 * \brief Read cryptographically random bytes into the given buffer.
 *
 * Internally, the PRNG source may need to reseed, which may cause the current
 * thread to block until the reseeding process is complete.
 *
 * \param context       The prng instance to initialize.
 * \param buffer        The buffer into which the bytes should be read.
 * \param length        The number of random bytes to write to the buffer.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_PRNG_READ_WOULD_OVERWRITE if this read would
 *             overwrite the provided \ref vccrypt_buffer_t instance.
 *      - a non-zero error code indicating failure.
 */
int vccrypt_prng_read(
    vccrypt_prng_context_t* context, vccrypt_buffer_t* buffer, size_t length)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(buffer != NULL);
    MODEL_ASSERT(buffer->data != NULL);
    MODEL_ASSERT(buffer->size >= length);

    /* don't overwrite the buffer */
    if (length > buffer->size)
    {
        return VCCRYPT_ERROR_PRNG_READ_WOULD_OVERWRITE;
    }

    return vccrypt_prng_read_c(context, buffer->data, length);
}
