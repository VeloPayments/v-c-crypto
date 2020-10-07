/**
 * \file padding.h
 *
 * \brief Provide PKCS#7 padding support through a generic function.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef  VCCRYPT_PADDING_HEADER_GUARD
#define  VCCRYPT_PADDING_HEADER_GUARD

#include <vccrypt/buffer.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \brief Pad a plaintext buffer to a given blocksize.
 *
 * \param buffer        The buffer to pad.
 * \param alloc_opts    The allocator options to use for this padding operation.
 * \param blocksize     The block size in bytes of which this buffer should be a
 *                      multiple.
 *
 * \note This padding operation should be done exactly once. This padding
 * operation MUST be used in conjunction with an encrypt-then-MAC scheme to
 * prevent padding oracle attacks.
 *
 * On success, this function replaces the data in the buffer with a buffer
 * containing a padded plaintext equivalent.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_INIT_OUT_OF_MEMORY if an out-of-memory
 *             condition occurs while performing this padding operation.
 *      - \ref VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT if the blocksize is
 *              invalid (e.g. >= 256) or if one of the other parameters is null.
 *      - a non-zero error code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_buffer_pad(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    size_t blocksize);

/**
 * \brief Reverse the padding operation of padded plaintext.
 *
 * \param buffer        The buffer to reverse.
 * \param alloc_opts    The allocator options to use for this padding operation.
 *
 * \note This padding operation should be done exactly once. This padding
 * operation MUST be used in conjunction with an encrypt-then-MAC scheme to
 * prevent padding oracle attacks.
 *
 * On success, this function replaces the data in the buffer with a buffer
 * containing a reverse padded plaintext value.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT if either of the parameters
 *              is null.
 *      - \ref VCCRYPT_ERROR_BUFFER_INIT_OUT_OF_MEMORY if an out-of-memory
 *             condition occurs while performing this padding operation.
 *      - \ref VCCRYPT_ERROR_BUFFER_PADDING_SCHEME_INVALID if the padded
 *              plaintext does not match padding rules.
 *      - a non-zero error code on failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_buffer_reverse_pad(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /*VCCRYPT_PADDING_HEADER_GUARD*/
