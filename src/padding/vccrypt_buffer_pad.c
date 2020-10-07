/**
 * \file padding/vccrypt_buffer_pad.c
 *
 * Pad a plaintext buffer using the PKCS#7 padding scheme.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/padding.h>

/**
 * \brief Pad a plaintext buffer to a given blocksize.
 *
 * \param buffer        The buffer to pad.
 * \param alloc_opts    The allocator options to use for this padding operation.
 * \param blocksize     The block size in bytes of which this buffer should be a
 *                      multiple.
 *
 * \note This padding operation should be done exactly once. This padding
 * operation MUST be used in conjunction with an encrypt-then-MAC scheme to
 * prevent padding oracle attacks.
 *
 * On success, this function replaces the data in the buffer with a buffer
 * containing a padded plaintext equivalent.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_INIT_OUT_OF_MEMORY if an out-of-memory
 *             condition occurs while performing this padding operation.
 *      - \ref VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT if the blocksize is
 *              invalid (e.g. >= 256) or if one of the other parameters is null.
 *      - a non-zero error code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_buffer_pad(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    size_t blocksize)
{
    int retval;
    vccrypt_buffer_t padding_buffer;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(blocksize > 0 && blocksize < 256);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts
     || blocksize == 0 || blocksize >= 256)
    {
        return VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT;
    }

    /* compute the required padding. */
    size_t padding = blocksize - (buffer->size % blocksize);
    if (padding == 0)
    {
        padding = blocksize;
    }

    /* compute the padding byte. */
    uint8_t padding_byte = (uint8_t)padding;

    /* create a padding buffer. */
    retval =
        vccrypt_buffer_init(
            &padding_buffer, alloc_opts, buffer->size + padding);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        return retval;
    }

    /* clear the padding buffer with the padding byte. */
    memset(padding_buffer.data, padding_byte, padding_buffer.size);

    /* copy the buffer data to the padding buffer. */
    memcpy(padding_buffer.data, buffer->data, buffer->size);

    /* dispose the old buffer. */
    dispose((disposable_t*)buffer);

    /* move the padding buffer into this buffer. */
    vccrypt_buffer_move(buffer, &padding_buffer);

    /* success. */
    return VCCRYPT_STATUS_SUCCESS;
}
