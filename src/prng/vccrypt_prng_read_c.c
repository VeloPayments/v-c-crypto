/**
 * \file vccrypt_prng_read.c
 *
 * Read random bytes from a PRNG source into a C buffer.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/prng.h>
#include <vpr/parameters.h>

/**
 * Read cryptographically random bytes into the given c buffer.  Internally, the
 * PRNG source may need to reseed, which may cause the current thread to block
 * until the reseeding process is complete.
 *
 * \param context       The prng instance to initialize.
 * \param buffer        The buffer into which the bytes should be read.
 * \param length        The number of random bytes to write to the buffer.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_prng_read_c(
    vccrypt_prng_context_t* context, uint8_t* buffer, size_t length)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->options != NULL);
    MODEL_ASSERT(context->options->vccrypt_prng_alg_read != NULL);
    MODEL_ASSERT(buffer != NULL);

    return context->options->vccrypt_prng_alg_read(
        context, buffer, length);
}
