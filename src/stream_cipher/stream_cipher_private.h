/**
 * \file stream_cipher_private.h
 *
 * Private implementation-specific data.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_STREAM_CIPHER_PRIVATE_HEADER_GUARD
#define VCCRYPT_STREAM_CIPHER_PRIVATE_HEADER_GUARD

#include <vccrypt/stream_cipher.h>

#include "aes/aes.h"

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VCCRYPT_AES_CTR_ALG_IV_SIZE 8

#define VCCRYPT_AES_CTR_ALG_ROUND_MULT_FIPS 1
#define VCCRYPT_AES_CTR_ALG_ROUND_MULT_2X 2
#define VCCRYPT_AES_CTR_ALG_ROUND_MULT_3X 3
#define VCCRYPT_AES_CTR_ALG_ROUND_MULT_4X 4

#define VCCRYPT_AES_CTR_ALG_AES_256_KEY_SIZE 32

/**
 * AES CTR Mode specific options data.
 */
typedef struct aes_ctr_options_data
{
    int round_multiplier;
} aes_ctr_options_data_t;

/**
 * AES CTR Mode specific context data.
 */
typedef struct aes_ctr_context_data
{
    AES_KEY key;
    uint8_t ctr[16];
    uint8_t stream[16];
    size_t count;
} aes_ctr_context_data_t;

/**
 * Increment the 128-bit counter by one.
 *
 * \param ctr       Pointer to the 128-bit counter.
 */
void vccrypt_aes_ctr_incr(
    uint8_t* ctr);

/**
 * Algorithm-specific initialization for stream cipher.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_stream_context_t structure.
 * \param key       The key to use for this instance.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_aes_ctr_alg_init(
    void* options, void* context, vccrypt_buffer_t* key);

/**
 * Algorithm-specific start for the stream cipher encryption.  Initializes
 * output buffer with IV.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_stream_context_t structure.
 * \param iv        The IV to use for this instance.  MUST ONLY BE USED ONCE
 *                  PER KEY, EVER.
 * \param ivSize    The size of the IV in bytes.
 * \param output    The output buffer to initialize. Must be at least
 *                  IV_bytes in size.
 * \param offset    Pointer to the current offset of the buffer.  Will be
 *                  set to IV_bytes.  The value in this offset is ignored.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_aes_ctr_alg_start_encryption(
    void* options, void* context, const void* iv, size_t ivSize,
    void* output, size_t* offset);

/**
 * Algorithm-specific start for the stream cipher decryption.  Reads IV from
 * input buffer.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_stream_context_t structure.
 * \param input     The input buffer to read the IV from. Must be at least
 *                  IV_bytes in size.
 * \param offset    Pointer to the current offset of the buffer.  Will be
 *                  set to IV_bytes.  The value in this offset is ignored.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_aes_ctr_alg_start_decryption(
    void* options, void* context, const void* input, size_t* offset);

/**
 * Encrypt data using the stream cipher.
 *
 * \param options       Opaque pointer to this options structure.
 * \param context       An opaque pointer to the vccrypt_stream_context_t
 *                      structure.
 * \param input         A pointer to the plaintext input to encrypt.
 * \param size          The size of the plaintext input, in bytes.
 * \param output        The output buffer where data is written.  There must
 *                      be at least *offset + size bytes available in this
 *                      buffer.
 * \param offset        A pointer to the current offset in the buffer.  Will
 *                      be incremented by size.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_aes_ctr_alg_encrypt(
    void* options, void* context, const void* input, size_t size,
    void* output, size_t* offset);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VCCRYPT_STREAM_CIPHER_PRIVATE_HEADER_GUARD*/
