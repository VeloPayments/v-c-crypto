/**
 * \file padding/vccrypt_buffer_reverse_pad.c
 *
 * Remove the padding in a PKCS#7 padded plaintext buffer.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/padding.h>

/**
 * \brief Reverse the padding operation of padded plaintext.
 *
 * \param buffer        The buffer to reverse.
 * \param alloc_opts    The allocator options to use for this padding operation.
 *
 * \note This padding operation should be done exactly once. This padding
 * operation MUST be used in conjunction with an encrypt-then-MAC scheme to
 * prevent padding oracle attacks.
 *
 * On success, this function replaces the data in the buffer with a buffer
 * containing a reverse padded plaintext value.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT if either of the parameters
 *              is null.
 *      - \ref VCCRYPT_ERROR_BUFFER_INIT_OUT_OF_MEMORY if an out-of-memory
 *             condition occurs while performing this padding operation.
 *      - \ref VCCRYPT_ERROR_BUFFER_PADDING_SCHEME_INVALID if the padded
 *              plaintext does not match padding rules.
 *      - a non-zero error code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_buffer_reverse_pad(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts)
{
    int retval;
    vccrypt_buffer_t unpadded_buffer;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts)
    {
        return VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT;
    }

    /* If the buffer size is <= 1, then it is invalid. */
    if (buffer->size <= 1)
    {
        return VCCRYPT_ERROR_BUFFER_PADDING_SCHEME_INVALID;
    }

    /* Grab the last byte. */
    const uint8_t* buf = (const uint8_t*)buffer->data;
    uint8_t last_padding_byte = buf[buffer->size - 1];

    /* If the last padding byte is 0, then this padding scheme is invalid. */
    if (0U == last_padding_byte)
    {
        return VCCRYPT_ERROR_BUFFER_PADDING_SCHEME_INVALID;
    }

    /* compute the number of padding bytes based on this last byte. */
    size_t padding_size = (size_t)last_padding_byte;

    /* if the padding size is greater than or equal to the buffer size, the
     * buffer is invalid. */
    if (padding_size >= buffer->size)
    {
        return VCCRYPT_ERROR_BUFFER_PADDING_SCHEME_INVALID;
    }

    /* Grab the last N bytes. If they don't all equal N, the padding scheme is
     * invalid. */
    for (size_t i = buffer->size - 1; i >= buffer->size - padding_size - 1; --i)
    {
        if (buf[i] != last_padding_byte)
        {
            return VCCRYPT_ERROR_BUFFER_PADDING_SCHEME_INVALID;
        }
    }

    /* the unpadded size is size - N. */
    size_t unpadded_size = buffer->size - padding_size;

    /* Create a smaller buffer and copy unpadded data. */
    retval = vccrypt_buffer_init(&unpadded_buffer, alloc_opts, unpadded_size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        return retval;
    }
    memcpy(unpadded_buffer.data, buffer->data, unpadded_size);

    /* dispose the original buffer and move the new buffer into it. */
    dispose((disposable_t*)buffer);
    vccrypt_buffer_move(buffer, &unpadded_buffer);

    /* success. */
    return VCCRYPT_STATUS_SUCCESS;
}
