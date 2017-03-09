/**
 * \file buffer.h
 *
 * Crypto buffer.  This implementation provides a disposable method that
 * automatically clears the buffer in memory.  Included in this implementation
 * are methods that ease serialization of the buffer to other formats.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_BUFFER_HEADER_GUARD
#define VCCRYPT_BUFFER_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/**
 * \brief buffer structure.
 *
 * This structure contains details needed to implement a crypto buffer.
 */
typedef struct vccrypt_buffer
{
    /* this is disposable. */
    disposable_t hdr;

    /* the allocator options to use for this buffer. */
    allocator_options_t* alloc_opts;

    /* the size of the buffer. */
    size_t size;

    /* the raw buffer data. */
    void* data;

} vccrypt_buffer_t;

/**
 * Initialize a buffer with the given size.
 *
 * Note: the buffer is owned by the caller and must be disposed by calling the
 * dispose() method when no longer needed.
 *
 * \param buffer    the buffer to initialize.
 * \param alloc     the allocator options to use for this buffer.
 * \param size      the size of the buffer in bytes.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_buffer_init(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc, size_t size);

/**
 * Initialize a buffer sized to serialize data in hexadecimal.
 *
 * Note: the buffer is owned by the caller and must be disposed by calling the
 * dispose() method when no longer needed.
 *
 * \param buffer    the buffer to initialize.
 * \param alloc     the allocator options to use for this buffer.
 * \param size      the size of the buffer in bytes; the real size will be the
 *                  hexadecimal equivalent (size * 2).
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_buffer_init_for_hex_serialization(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc, size_t size);

/**
 * Initialize a buffer sized to serialize data in Base64.
 *
 * Note: the buffer is owned by the caller and must be disposed by calling the
 * dispose() method when no longer needed.
 *
 * \param buffer    the buffer to initialize.
 * \param alloc     the allocator options to use for this buffer.
 * \param size      the size of the buffer in bytes; the real size will be the
 *                  padded Base64 equivalent (size * 4 / 3 + (3 - size % 3)).
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_buffer_init_for_base64_serialization(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc, size_t size);

/**
 * Copy data from one buffer to another.
 *
 * Note: buffers must be the same size.
 *
 * \param dest      the destination buffer.
 * \param source    the source buffer.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_buffer_copy(vccrypt_buffer_t* dest, const vccrypt_buffer_t* source);

/**
 * Read data from a C buffer.
 *
 * Note: C buffer size cannot exceed buffer size.
 *
 * \param dest      the destination buffer.
 * \param source    the source C buffer.
 * \param size      the number of bytes to read.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_buffer_read_data(
    vccrypt_buffer_t* dest, const void* source, size_t size);

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
    vccrypt_buffer_t* dest, const vccrypt_buffer_t* source);

/**
 * Read buffer data from hex.
 *
 * Note: buffers must be sized appropriately.
 *
 * \param dest      the destination byte buffer.
 * \param source    the source hex buffer.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_buffer_read_hex(
    vccrypt_buffer_t* dest, const vccrypt_buffer_t* source);

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
    vccrypt_buffer_t* dest, const vccrypt_buffer_t* source);

/**
 * Read buffer data from Base64.
 *
 * Note: buffers must be sized appropriately.
 *
 * \param dest      the destination byte buffer.
 * \param source    the source base64 buffer.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_buffer_read_base64(
    vccrypt_buffer_t* dest, const vccrypt_buffer_t* source);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_BUFFER_HEADER_GUARD
