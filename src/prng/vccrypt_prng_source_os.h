/**
 * \file vccrypt_prng_source_os.c
 *
 * Use the Unix entropy source as a PRNG.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_PRNG_SOURCE_OS_PRIVATE_HEADER_GUARD
#define VCCRYPT_PRNG_SOURCE_OS_PRIVATE_HEADER_GUARD

#include <vccrypt/prng.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * Initialize the OS PRNG source.
 *
 * \param options           Opaque pointer to this options structure.
 * \param context           Opaque pointer to the vccrypt_prng_context_t
 *                          structure to initialize.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_prng_os_init(void* options, void* context);

/**
 * Disposal of the OS PRNG source.
 *
 * \param options           Opaque pointer to this options structure.
 * \param context           Opaque pointer to the vccrypt_prng_context_t
 *                          structure to dispose.
 */
void vccrypt_prng_os_dispose(void* options, void* context);

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
int vccrypt_prng_os_read(void* context, uint8_t* buffer, size_t length);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_PRNG_SOURCE_OS_PRIVATE_HEADER_GUARD
