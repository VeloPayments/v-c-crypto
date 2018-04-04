/**
 * \file buffer/vccrypt_buffer_read_hex.c
 *
 * Read the hexadecimal representation of a buffer into a byte buffer.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/buffer.h>
#include <vpr/parameters.h>

/* forward decls */
static uint8_t from_hex(uint8_t hex);

/**
 * \brief Read buffer data from hex.
 *
 * Note: buffers must be sized appropriately.
 *
 * \param dest      the destination byte buffer.
 * \param source    the source hex buffer.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_READ_WOULD_OVERWRITE if this read operation
 *             would overwrite the destination buffer.
 *      - a non-zero error code on failure.
 */
int vccrypt_buffer_read_hex(
    vccrypt_buffer_t* dest, const vccrypt_buffer_t* source)
{
    MODEL_ASSERT(dest != NULL);
    MODEL_ASSERT(dest->data != NULL);
    MODEL_ASSERT(source != NULL);
    MODEL_ASSERT(source->data != NULL);
    MODEL_ASSERT(dest->size > 0);
    MODEL_ASSERT(source->size > 0);
    MODEL_ASSERT(source->size % 2 == 0);
    MODEL_ASSERT(dest->size >= source->size / 2);

    /* we can't exceed the destination buffer size */
    if (dest->size < source->size / 2)
    {
        return VCCRYPT_ERROR_BUFFER_READ_WOULD_OVERWRITE;
    }

    /* convert data pointers to byte buffers. */
    uint8_t* out = (uint8_t*)dest->data;
    const uint8_t* in = (uint8_t*)source->data;

    /* iterate through each byte of the input buffer. */
    for (size_t i = 0; i < source->size; i += 2)
    {
        *out++ = (from_hex(in[i]) << 4) | from_hex(in[i + 1]);
    }

    /* success */
    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Given a hex digit, return the nibble value associated with this value.
 *
 * \param hex        the hex digit value.
 *
 * \returns the saturated nibble representation of this digit.
 */
static uint8_t from_hex(uint8_t hex)
{
    MODEL_ASSERT(
        (hex >= '0' && hex <= '9') ||
        (hex >= 'A' && hex <= 'F') ||
        (hex >= 'a' && hex <= 'f'));

    switch (hex)
    {
        case '0':
            return 0x00;
        case '1':
            return 0x01;
        case '2':
            return 0x02;
        case '3':
            return 0x03;
        case '4':
            return 0x04;
        case '5':
            return 0x05;
        case '6':
            return 0x06;
        case '7':
            return 0x07;
        case '8':
            return 0x08;
        case '9':
            return 0x09;
        case 'A':
        case 'a':
            return 0x0A;
        case 'B':
        case 'b':
            return 0x0B;
        case 'C':
        case 'c':
            return 0x0C;
        case 'D':
        case 'd':
            return 0x0D;
        case 'E':
        case 'e':
            return 0x0E;
        default:
            return 0x0F;
    }
}
