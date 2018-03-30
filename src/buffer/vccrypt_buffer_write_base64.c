/**
 * \file buffer/vccrypt_buffer_write_base64.c
 *
 * Write the Base64 representation of a buffer to the destination buffer.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/buffer.h>
#include <vpr/parameters.h>

/* forward decls */
static uint32_t base64_enc(uint32_t word, size_t bytes);
static uint8_t to_base64(uint8_t input);

/**
 * Write buffer data to Base64.
 *
 * Note: buffers must be sized appropriately.
 *
 * \param dest      the destination base64 buffer.
 * \param source    the source byte buffer.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_buffer_write_base64(
    vccrypt_buffer_t* dest, const vccrypt_buffer_t* source)
{
    MODEL_ASSERT(dest != NULL);
    MODEL_ASSERT(dest->data != NULL);
    MODEL_ASSERT(source != NULL);
    MODEL_ASSERT(source->data != NULL);
    MODEL_ASSERT(dest->size > 0);
    MODEL_ASSERT(source->size > 0);

    //compute output size
    size_t unpadded_size = (source->size * 4) / 3;
    size_t output_size = unpadded_size;
    if (output_size % 4 != 0)
        output_size += 4 - output_size % 4;

    //verify that the destination buffer size is large enough
    MODEL_ASSERT(dest->size >= output_size);
    if (dest->size < output_size)
    {
        return VCCRYPT_ERROR_BUFFER_WRITE_WOULD_OVERWRITE;
    }

    //iterate over the input data, writing to the output buffer
    uint8_t* in = (uint8_t*)source->data;
    uint32_t* out = (uint32_t*)dest->data;
    uint32_t input = in[0];
    size_t bytes = 1;
    for (size_t i = 1; i < source->size; ++i)
    {
        input <<= 8;
        input |= in[i];
        ++bytes;

        //if we've read three bytes...
        if (bytes > 2)
        {
            *out++ = base64_enc(input, 4);
            input = bytes = 0;
        }
    }

    //handle padding
    if (bytes)
    {
        input <<= (3 - bytes) * 8;
        *out++ = base64_enc(input, bytes + 1);
    }

    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Encode up to a 24-bit word worth of bytes as Base64, adding padding as
 * needed.
 *
 * \param word      The word to convert
 * \param bytes     The number of bytes in this word.
 *
 * \returns the Base64 word, padded if necessary.
 */
static uint32_t base64_enc(uint32_t word, size_t bytes)
{
    uint32_t out = 0;

    for (int i = 0; i < 4; ++i)
    {
        out >>= 8;

        if (bytes)
        {
            --bytes;
            out |= to_base64((word & 0x00FC0000) >> 18) << 24;
        }
        else
        {
            out |= '=' << 24;
        }

        word <<= 6;
    }

    return out;
}

/**
 * Given a 6-bit input, find the Base64 encoding of the input and return this as
 * a byte.
 *
 * \param input     The 6-bit input to convert.
 *
 * \returns the Base64 encoded output byte, saturated to 0x3F's representation.
 */
static uint8_t to_base64(uint8_t input)
{
    switch (input)
    {
        case 0:
            return 'A';
        case 1:
            return 'B';
        case 2:
            return 'C';
        case 3:
            return 'D';
        case 4:
            return 'E';
        case 5:
            return 'F';
        case 6:
            return 'G';
        case 7:
            return 'H';
        case 8:
            return 'I';
        case 9:
            return 'J';
        case 10:
            return 'K';
        case 11:
            return 'L';
        case 12:
            return 'M';
        case 13:
            return 'N';
        case 14:
            return 'O';
        case 15:
            return 'P';
        case 16:
            return 'Q';
        case 17:
            return 'R';
        case 18:
            return 'S';
        case 19:
            return 'T';
        case 20:
            return 'U';
        case 21:
            return 'V';
        case 22:
            return 'W';
        case 23:
            return 'X';
        case 24:
            return 'Y';
        case 25:
            return 'Z';
        case 26:
            return 'a';
        case 27:
            return 'b';
        case 28:
            return 'c';
        case 29:
            return 'd';
        case 30:
            return 'e';
        case 31:
            return 'f';
        case 32:
            return 'g';
        case 33:
            return 'h';
        case 34:
            return 'i';
        case 35:
            return 'j';
        case 36:
            return 'k';
        case 37:
            return 'l';
        case 38:
            return 'm';
        case 39:
            return 'n';
        case 40:
            return 'o';
        case 41:
            return 'p';
        case 42:
            return 'q';
        case 43:
            return 'r';
        case 44:
            return 's';
        case 45:
            return 't';
        case 46:
            return 'u';
        case 47:
            return 'v';
        case 48:
            return 'w';
        case 49:
            return 'x';
        case 50:
            return 'y';
        case 51:
            return 'z';
        case 52:
            return '0';
        case 53:
            return '1';
        case 54:
            return '2';
        case 55:
            return '3';
        case 56:
            return '4';
        case 57:
            return '5';
        case 58:
            return '6';
        case 59:
            return '7';
        case 60:
            return '8';
        case 61:
            return '9';
        case 62:
            return '+';
        case 63:
        default:
            return '/';
    }
}
