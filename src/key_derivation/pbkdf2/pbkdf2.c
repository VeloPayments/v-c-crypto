/*  $OpenBSD: pkcs5_pbkdf2.c,v 1.10 2017/04/18 04:06:21 deraadt Exp $   */

/**
 * Copyright (c) 2008 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

/* Note: modified to be compatible with Velo Payments */


#include <cbmc/model_assert.h>
#include <stdint.h>
#include <string.h>
#include <vpr/allocator.h>
#include <vpr/parameters.h>
#include <vccrypt/error_codes.h>

#include "pbkdf2.h"

#define MINIMUM(a, b) (((a) < (b)) ? (a) : (b))

/**
 * Password-Based Key Derivation Function 2 (PKCS #5 v2.0).
 * Code based on IEEE Std 802.11-2007, Annex H.4.2.
 *
 * \brief Applies a pseudorandom function to an input password or passphrase,
 * along with a salt value, to produce a derived key.
 *
 * \param derived_key         The output derived key
 * \param derived_key_len     The desired length of the derived key
 * \param options             The options to use
 * \param prf                 A pseudo random function, e.g. keyed HMAC
 * \param pass                The password or passphrase
 * \param pass_len            The length of the password or passphrase
 * \param salt                A salt value, typically random data
 * \param salt_len            The length of the salt
 * \param rounds              The number of rounds to process.  More rounds
 *                            increases randomness and computational cost.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS if successful.
 */
int pkcs5_pbkdf2(
    uint8_t* derived_key, size_t derived_key_len,
    vccrypt_key_derivation_options_t* options, pbkdf2_prf_t prf,
    const char* pass, size_t pass_len,
    const uint8_t* salt, size_t salt_len, unsigned int rounds)
{
    int retval = VCCRYPT_STATUS_SUCCESS;

    uint8_t* asalt;
    uint8_t output_buffer[options->hmac_digest_length];
    uint8_t digest1[options->hmac_digest_length],
        digest2[options->hmac_digest_length];

    // sanity checks
    if (rounds < 1 || derived_key_len == 0)
    {
        return VCCRYPT_ERROR_PBKDF2_INVALID_ARG;
    }

    if (salt_len == 0 || salt_len > SIZE_MAX - 4)
    {
        return VCCRYPT_ERROR_PBKDF2_INVALID_ARG;
    }

    // create a buffer to hold the salt and an additional 4 bytes
    // the additional bytes are to append the iteration number
    asalt = allocate(options->alloc_opts, salt_len + 4);
    if (NULL == asalt)
    {
        return VCCRYPT_ERROR_PBKDF2_INIT_OUT_OF_MEMORY;
    }
    memcpy(asalt, salt, salt_len);

    // derive the key in chunks of HLEN bytes (the length of the PRF's digest).
    for (unsigned int count = 1; derived_key_len > 0; count++)
    {
        // append the loop counter in big endian format to the salt
        asalt[salt_len + 0] = (count >> 24) & 0xff;
        asalt[salt_len + 1] = (count >> 16) & 0xff;
        asalt[salt_len + 2] = (count >> 8) & 0xff;
        asalt[salt_len + 3] = count & 0xff;

        // the first round uses the user supplied salt
        memset(digest1, 0, sizeof(digest1));
        retval = prf(digest1, sizeof(digest1), options, asalt, salt_len + 4,
            (uint8_t*)pass, pass_len);
        if (0 != retval)
        {
            goto cleanup;
        }

        // copy the round 1 results to the output buffer
        memcpy(output_buffer, digest1, sizeof(output_buffer));

        // subsequent rounds use the output of the previous round as the input
        for (unsigned int i = 1; i < rounds; i++)
        {
            memset(digest2, 0, sizeof(digest2));
            retval = prf(digest2, sizeof(digest2), options,
                digest1, sizeof(digest1), (uint8_t*)pass, pass_len);
            if (0 != retval)
            {
                goto cleanup;
            }

            // copy the output of this round into the input buffer for
            // the next round
            memcpy(digest1, digest2, sizeof(digest1));

            // xor the result into the output buffer
            for (unsigned int j = 0; j < sizeof(output_buffer); j++)
            {
                output_buffer[j] ^= digest1[j];
            }
        }

        // copy the bytes from the output buffer into our key
        size_t r = MINIMUM(derived_key_len, options->hmac_digest_length);
        memcpy(derived_key, output_buffer, r);

        // prepare for the next group of bytes
        derived_key += r;
        derived_key_len -= r;
    }

cleanup:

    // erase contents of salt and free memory
    memset(asalt, 0, salt_len + 4);
    release(options->alloc_opts, asalt);

    // erase contents of working arrays
    memset(digest1, 0, sizeof(digest1));
    memset(digest2, 0, sizeof(digest2));

    return retval;
}
