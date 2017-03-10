/**
 * \file buffer/vccrypt_buffer_write_hex.c
 *
 * Write the hexadecimal representation of a buffer to the destination buffer.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/buffer.h>
#include <vpr/parameters.h>

/* forward decls */
uint8_t hex_digit(uint8_t nibble);

/**
 * Write buffer data to hex.
 *
 * Note: buffers must be sized appropriately.
 *
 * \param dest      the destination hex buffer.
 * \param source    the source byte buffer.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_buffer_write_hex(
    vccrypt_buffer_t* dest, const vccrypt_buffer_t* source)
{
    MODEL_ASSERT(dest != NULL);
    MODEL_ASSERT(dest->data != NULL);
    MODEL_ASSERT(source != NULL);
    MODEL_ASSERT(source->data != NULL);
    MODEL_ASSERT(dest->size > 0);
    MODEL_ASSERT(source->size > 0);
    MODEL_ASSERT(dest->size >= source->size * 2);

    /* we can't exceed the destination buffer size */
    if (dest->size < source->size * 2)
        return 1;

    /* convert data pointers to byte buffers. */
    uint8_t* out = (uint8_t*)dest->data;
    const uint8_t* in = (uint8_t*)source->data;

    /* iterate through each byte of the input buffer. */
    for (size_t i = 0; i < source->size; ++i)
    {
        /* write the high bit as a hex digit. */
        *out++ = hex_digit((in[i] >> 4) & 0x0F);
        /* write the low bit as a hex digit. */
        *out++ = hex_digit(in[i] & 0x0F);
    }

    /* success */
    return 0;
}

/**
 * Given a nibble value between 0x00 and 0x0F inclusive, return the hexadecimal
 * digit associated with this value.
 *
 * \param nibble    the nibble value.
 *
 * \returns the saturated hexadecimal digit.
 */
uint8_t hex_digit(uint8_t nibble)
{
    MODEL_ASSERT(nibble >= 0 && nibble <= 0x0F);

    switch (nibble)
    {
        case 0:
            return '0';
        case 1:
            return '1';
        case 2:
            return '2';
        case 3:
            return '3';
        case 4:
            return '4';
        case 5:
            return '5';
        case 6:
            return '6';
        case 7:
            return '7';
        case 8:
            return '8';
        case 9:
            return '9';
        case 10:
            return 'A';
        case 11:
            return 'B';
        case 12:
            return 'C';
        case 13:
            return 'D';
        case 14:
            return 'E';
        default:
            return 'F';
    }
}
