/**
 * \file buffer.h
 *
 * \brief This is a "smart" buffer that has some bound checks and provides a
 * disposable method that automatically clears the buffer in memory.
 *
 * Included in this implementation are methods that ease serialization of the
 * buffer to other formats.
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
#include <vccrypt/error_codes.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/**
 * \brief This structure contains details needed to implement a crypto buffer.
 */
typedef struct vccrypt_buffer
{
    /**
     * \brief This buffer is disposable.
     */
    disposable_t hdr;

    /**
     * \brief The allocator options to use for this buffer.
     */
    allocator_options_t* alloc_opts;

    /**
     * \brief The size of the buffer.
     */
    size_t size;

    /**
     * \brief The raw buffer data.
     */
    void* data;

} vccrypt_buffer_t;

/**
 * \brief Initialize a buffer with the given size.
 *
 * Note: the buffer is owned by the caller and must be disposed by calling the
 * dispose() method when no longer needed.
 *
 * \param buffer    the buffer to initialize.
 * \param alloc     the allocator options to use for this buffer.
 * \param size      the size of the buffer in bytes.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_INIT_OUT_OF_MEMORY if this method runs out
 *             of memory while initializing this buffer.
 *      - a non-zero error code on failure.
 */
int vccrypt_buffer_init(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc, size_t size);

/**
 * \brief Initialize a buffer sized to serialize data in hexadecimal.
 *
 * Note: the buffer is owned by the caller and must be disposed by calling the
 * dispose() method when no longer needed.
 *
 * \param buffer    the buffer to initialize.
 * \param alloc     the allocator options to use for this buffer.
 * \param size      the size of the buffer in bytes; the real size will be the
 *                  hexadecimal equivalent (size * 2).
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_INIT_OUT_OF_MEMORY if this method runs out
 *             of memory while initializing this buffer.
 *      - a non-zero error code on failure.
 */
int vccrypt_buffer_init_for_hex_serialization(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc, size_t size);

/**
 * \brief Initialize a buffer sized to serialize data in Base64.
 *
 * Note: the buffer is owned by the caller and must be disposed by calling the
 * dispose() method when no longer needed.
 *
 * \param buffer    the buffer to initialize.
 * \param alloc     the allocator options to use for this buffer.
 * \param size      the size of the buffer in bytes; the real size will be the
 *                  padded Base64 equivalent.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_INIT_OUT_OF_MEMORY if this method runs out
 *             of memory while initializing this buffer.
 *      - a non-zero error code on failure.
 */
int vccrypt_buffer_init_for_base64_serialization(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc, size_t size);

/**
 * \brief Copy data from one buffer to another.
 *
 * Note: buffers must be the same size.
 *
 * \param dest      the destination buffer.
 * \param source    the source buffer.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_COPY_MISMATCHED_BUFFER_SIZES if the buffer
 *             sizes are mismatched and therefore this copy would overwrite one
 *             buffer.
 *      - a non-zero error code on failure.
 */
int vccrypt_buffer_copy(vccrypt_buffer_t* dest, const vccrypt_buffer_t* source);

/**
 * \brief Read data from a C buffer.
 *
 * Note: C buffer size cannot exceed buffer size.
 *
 * \param dest      the destination buffer.
 * \param source    the source C buffer.
 * \param size      the number of bytes to read.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_READ_WOULD_OVERWRITE if this read operation
 *             would overwrite the buffer.
 *      - a non-zero error code on failure.
 */
int vccrypt_buffer_read_data(
    vccrypt_buffer_t* dest, const void* source, size_t size);

/**
 * \brief Write buffer data to hex.
 *
 * Note: buffers must be sized appropriately.
 *
 * \param dest      the destination hex buffer.
 * \param source    the source byte buffer.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_WRITE_WOULD_OVERWRITE if this write
 *             operation would overwrite the destination buffer.
 *      - a non-zero error code on failure.
 */
int vccrypt_buffer_write_hex(
    vccrypt_buffer_t* dest, const vccrypt_buffer_t* source);

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
    vccrypt_buffer_t* dest, const vccrypt_buffer_t* source);

/**
 * \brief Write buffer data to Base64.
 *
 * Note: buffers must be sized appropriately.
 *
 * \param dest      the destination base64 buffer.
 * \param source    the source byte buffer.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_WRITE_WOULD_OVERWRITE if this write
 *             operation would overwrite the destination buffer.
 *      - a non-zero error code on failure.
 */
int vccrypt_buffer_write_base64(
    vccrypt_buffer_t* dest, const vccrypt_buffer_t* source);

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
    size_t* decoded_bytes);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_BUFFER_HEADER_GUARD
