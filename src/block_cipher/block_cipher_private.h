/**
 * \file block_cipher_private.h
 *
 * Private implementation-specific data.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_BLOCK_CIPHER_PRIVATE_HEADER_GUARD
#define VCCRYPT_BLOCK_CIPHER_PRIVATE_HEADER_GUARD

#include <vccrypt/block_cipher.h>

#include "../stream_cipher/aes/aes.h"

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VCCRYPT_AES_CBC_ALG_IV_SIZE 16

#define VCCRYPT_AES_CBC_ALG_ROUND_MULT_FIPS 1
#define VCCRYPT_AES_CBC_ALG_ROUND_MULT_2X 2
#define VCCRYPT_AES_CBC_ALG_ROUND_MULT_3X 3
#define VCCRYPT_AES_CBC_ALG_ROUND_MULT_4X 4

#define VCCRYPT_AES_CBC_ALG_AES_256_KEY_SIZE 32

/**
 * AES CBC Mode specific options data.
 */
typedef struct aes_cbc_options_data
{
    int round_multiplier;
} aes_cbc_options_data_t;

/**
 * AES CBC Mode specific context data.
 */
typedef struct aes_cbc_context_data
{
    AES_KEY key;
} aes_cbc_context_data_t;

/**
 * Algorithm-specific initialization for block cipher.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_block_context_t structure.
 * \param key       The key to use for this instance.
 * \param encrypt   Set to true if this is for encryption, and false for
 *                  decryption.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_aes_cbc_alg_init(
    void* options, void* context, vccrypt_buffer_t* key, bool encrypt);

/**
 * Encrypt a single block of data using the block cipher.
 *
 * \param options       Opaque pointer to this options structure.
 * \param context       An opaque pointer to the vccrypt_block_context_t
 *                      structure.
 * \param iv            The initialization vector to use for this block.
 *                      Must be cryptographically random for the first
 *                      block.  Subsequent blocks should use the previous
 *                      output block for the iv (hence, cipher block
 *                      chaining).  Must be the block size in length.
 * \param input         A pointer to the plaintext input to encrypt.  Must
 *                      be the block size in length.
 * \param output        The output buffer where data is written.  The output
 *                      buffer must be at least the block size in length.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_aes_cbc_alg_encrypt(
    void* options, void* context, const void* iv, const void* input,
    void* output);

/**
 * Decrypt a single block of data using the block cipher.
 *
 * \param options       Opaque pointer to this options structure.
 * \param context       An opaque pointer to the vccrypt_block_context_t
 *                      structure.
 * \param iv            The initialization vector to use for this block.
 *                      The first block should be the first block of input.
 *                      Subsequent blocks should be the previous block of
 *                      ciphertext. (hence, cipher block chaining).  Must be
 *                      the block size in length.
 * \param input         A pointer to the plaintext input to encrypt.  The
 *                      first input block should be the second block of
 *                      input.  Must be the block size in length.
 * \param output        The output buffer where data is written.  The output
 *                      buffer must be at least the block size in length.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_aes_cbc_alg_decrypt(
    void* options, void* context, const void* iv, const void* input,
    void* output);

#endif /*VCCRYPT_BLOCK_CIPHER_PRIVATE_HEADER_GUARD*/
