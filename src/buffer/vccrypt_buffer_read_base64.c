/**
 * \file buffer/vccrypt_buffer_read_base64.c
 *
 * Read the Base64 representation of a buffer and write the binary form to an
 * output buffer.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/buffer.h>
#include <vpr/parameters.h>

/* forward decls */
static int from_base64(uint8_t byte);

/**
 * \brief Read buffer data from Base64.
 *
 * Note: buffers must be sized appropriately.
 *
 * \param dest          the destination byte buffer.
 * \param source        the source base64 buffer.
 * \param decoded_bytes the number of bytes decoded.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_READ_WOULD_OVERWRITE if this read operation
 *             would overwrite the destination buffer.
 *      - a non-zero error code on failure.
 */
int vccrypt_buffer_read_base64(
    vccrypt_buffer_t* dest, const vccrypt_buffer_t* source,
    size_t* decoded_bytes)
{
    uint8_t buffer[4];

    MODEL_ASSERT(decoded_bytes != NULL);
    MODEL_ASSERT(dest != NULL);
    MODEL_ASSERT(dest->data != NULL);
    MODEL_ASSERT(source != NULL);
    MODEL_ASSERT(source->data != NULL);
    MODEL_ASSERT(source->size > 0);
    MODEL_ASSERT(dest->size > 0);

    //don't overrun the buffer
    size_t max_output_size = source->size * 3 / 4;
    MODEL_ASSERT(dest->size >= max_output_size);
    if (dest->size < max_output_size)
    {
        return VCCRYPT_ERROR_BUFFER_READ_WOULD_OVERWRITE;
    }

    //convert source data
    size_t digits = 0;
    *decoded_bytes = 0;
    uint8_t* input = (uint8_t*)source->data;
    uint8_t* output = (uint8_t*)dest->data;
    for (size_t i = 0; i < source->size; ++i)
    {
        int nib = from_base64(input[i]);
        if (nib >= 0)
        {
            buffer[digits++] = nib;
        }

        //four digits can be converted to three bytes
        if (digits == 4)
        {
            *output++ = (buffer[0]) << 2 | (buffer[1] & 0x30) >> 4;
            *output++ = (buffer[1] & 0x0F) << 4 | (buffer[2] & 0x3C) >> 2;
            *output++ = (buffer[2] & 0x03) << 6 | (buffer[3] & 0x3F);

            *decoded_bytes += 3;
            digits = 0;
        }
    }

    //handle partials
    switch (digits)
    {
        case 3:
            *(output + 1) = (buffer[1] & 0x0F) << 4 | (buffer[2] & 0x3C) >> 2;
            *decoded_bytes += 1;
            /* fall-through */

        case 2:
            *output = (buffer[0]) << 2 | (buffer[1] & 0x30) >> 4;
            *decoded_bytes += 1;
            break;

        default:
            break;
    }

    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Decode a Base64 character, returning -1 if the character is invalid.
 *
 * \param byte      the character to decode.
 *
 * \returns a value between 0 and 63 on success, and a negative number on
 * failure.
 */
static int from_base64(uint8_t byte)
{
    switch ((char)byte)
    {
        case 'A':
            return 0;
        case 'B':
            return 1;
        case 'C':
            return 2;
        case 'D':
            return 3;
        case 'E':
            return 4;
        case 'F':
            return 5;
        case 'G':
            return 6;
        case 'H':
            return 7;
        case 'I':
            return 8;
        case 'J':
            return 9;
        case 'K':
            return 10;
        case 'L':
            return 11;
        case 'M':
            return 12;
        case 'N':
            return 13;
        case 'O':
            return 14;
        case 'P':
            return 15;
        case 'Q':
            return 16;
        case 'R':
            return 17;
        case 'S':
            return 18;
        case 'T':
            return 19;
        case 'U':
            return 20;
        case 'V':
            return 21;
        case 'W':
            return 22;
        case 'X':
            return 23;
        case 'Y':
            return 24;
        case 'Z':
            return 25;
        case 'a':
            return 26;
        case 'b':
            return 27;
        case 'c':
            return 28;
        case 'd':
            return 29;
        case 'e':
            return 30;
        case 'f':
            return 31;
        case 'g':
            return 32;
        case 'h':
            return 33;
        case 'i':
            return 34;
        case 'j':
            return 35;
        case 'k':
            return 36;
        case 'l':
            return 37;
        case 'm':
            return 38;
        case 'n':
            return 39;
        case 'o':
            return 40;
        case 'p':
            return 41;
        case 'q':
            return 42;
        case 'r':
            return 43;
        case 's':
            return 44;
        case 't':
            return 45;
        case 'u':
            return 46;
        case 'v':
            return 47;
        case 'w':
            return 48;
        case 'x':
            return 49;
        case 'y':
            return 50;
        case 'z':
            return 51;
        case '0':
            return 52;
        case '1':
            return 53;
        case '2':
            return 54;
        case '3':
            return 55;
        case '4':
            return 56;
        case '5':
            return 57;
        case '6':
            return 58;
        case '7':
            return 59;
        case '8':
            return 60;
        case '9':
            return 61;
        case '+':
            return 62;
        case '/':
            return 63;
        default:
            return -1;
    }
}
