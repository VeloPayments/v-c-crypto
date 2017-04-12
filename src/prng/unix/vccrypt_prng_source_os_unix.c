/**
 * \file vccrypt_prng_source_os_unix.c
 *
 * Use the Unix entropy source as a PRNG.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/os.h>
#include <vccrypt/prng.h>
#include <vpr/allocator.h>
#include <vpr/parameters.h>

#if defined(VCCRYPT_OS_UNIX)

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * Initialize the Unix Entropy device as a PRNG source.
 *
 * \param options           Opaque pointer to this options structure.
 * \param context           Opaque pointer to the vccrypt_prng_context_t
 *                          structure to initialize.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_prng_os_init(void* options, void* context)
{
    vccrypt_prng_options_t* opts = (vccrypt_prng_options_t*)options;
    vccrypt_prng_context_t* ctx = (vccrypt_prng_context_t*)context;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(opts->alloc_opts != NULL);
    MODEL_ASSERT(ctx != NULL);

    /* attempt to allocate space for the entropy device handle. */
    int* handle = (int*)allocate(opts->alloc_opts, sizeof(int));
    if (handle == NULL)
    {
        return 1;
    }

    /* attempt to open the entropy device for the OS. */
    *handle = open("/dev/urandom", O_RDONLY);
    if (*handle < 0)
    {
        release(opts->alloc_opts, handle);
        return 2;
    }

    /* initialize this context */
    ctx->prng_state = handle;

    /* success */
    return 0;
}

/**
 * Disposal of the Unix Entropy device.
 *
 * \param options           Opaque pointer to this options structure.
 * \param context           Opaque pointer to the vccrypt_prng_context_t
 *                          structure to dispose.
 */
void vccrypt_prng_os_dispose(void* options, void* context)
{
    vccrypt_prng_options_t* opts = (vccrypt_prng_options_t*)options;
    vccrypt_prng_context_t* ctx = (vccrypt_prng_context_t*)context;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(opts->alloc_opts != NULL);
    MODEL_ASSERT(ctx != NULL);
    MODEL_ASSERT(ctx->prng_state != NULL);

    /* close the Unix device. */
    int* handle = (int*)ctx->prng_state;
    close(*handle);

    /* clean up memory */
    release(opts->alloc_opts, ctx->prng_state);
    ctx->prng_state = 0;
}

/**
 * Get cryptographically random bytes and place these into the given buffer.
 *
 * \param context           Opaque pointer to the instance context.
 * \param buffer            Pointer to the buffer to which the random bytes
 *                          will be written.
 * \param length            The number of bytes to write to the buffer.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_prng_os_read(void* context, uint8_t* buffer, size_t length)
{
    vccrypt_prng_context_t* ctx = (vccrypt_prng_context_t*)context;

    MODEL_ASSERT(ctx != NULL);
    MODEL_ASSERT(ctx->prng_state != NULL);

    //read the requested number of bytes from the stream
    int* handle = (int*)ctx->prng_state;
    int ret = read(*handle, buffer, length);
    if (ret < 0 || (size_t)ret != length)
    {
        memset(buffer, 0, length);
        return 1;
    }

    /* success */
    return 0;
}

#endif /* defined(VCCRYPT_OS_UNIX) */
