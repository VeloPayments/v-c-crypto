/**
 * \file hmac.h
 *
 * Hashed Message Authentication Codes.  The Hashed Message Authentication Code
 * internal method turns a hash into a keyed hashed message authentication code.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_PRIVATE_MAC_HMAC_HEADER_GUARD
#define VCCRYPT_PRIVATE_MAC_HMAC_HEADER_GUARD

#include <vccrypt/hash.h>
#include <vccrypt/mac.h>
#include <vpr/disposable.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * The vccrypt_hmac_state_t data structure holds the current hmac state.
 */
typedef struct vccrypt_hmac_state
{
    disposable_t hdr;
    vccrypt_hash_options_t* hash_options;
    vccrypt_hash_context_t hash;
    vccrypt_buffer_t key;
} vccrypt_hmac_state_t;

/**
 * Initialize an hmac_state_t using the given hash options and key.
 *
 * \param state             The vccrypt_hmac_state_t structure to initialize.
 * \param hash_options      The vccrypt_hash_options_t hash options to use for
 *                          this hmac.
 * \param key               The key to use to initialize this state structure.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccrypt_hmac_init(
    vccrypt_hmac_state_t* state, vccrypt_hash_options_t* hash_options,
    const vccrypt_buffer_t* key);

/**
 * Digest data for the given hmac instance.
 *
 * \param state         The hmac state to receive data.
 * \param data          A pointer to raw data to digest.
 * \param size          The size of the data to digest, in bytes.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_hmac_digest(
    vccrypt_hmac_state_t* state, const uint8_t* data, size_t size);

/**
 * Finalize the hmac, copying the output data to the given buffer.
 *
 * \param state         The hmac state to finalize.
 * \param hmac_buffer   The buffer to receive the hmac.  Must be large enough
 *                      for the given hmac algorithm.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_hmac_finalize(
    vccrypt_hmac_state_t* state, vccrypt_buffer_t* hmac_buffer);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_PRIVATE_MAC_HMAC_HEADER_GUARD
