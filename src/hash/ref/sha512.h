/**
 * \file hash/ref/sha512.c
 *
 * Reference implementation of SHA-512 as provided by LibreSSL.
 *
 * \copyright 2004 The OpenSSL Project (released under OpenSSL license),
 * with modifications copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef HASH_REF_SHA512_HEADER_GUARD
#define HASH_REF_SHA512_HEADER_GUARD

#include <stdint.h>

/**
 * Context data structure for SHA-512 and SHA-384.
 */
typedef struct SHA512state
{
    uint64_t h[8];
    uint64_t Nl, Nh;
    union
    {
        uint64_t d[16];
        uint8_t p[128];
    } u;
    unsigned int num, md_len;
} SHA512_CTX;

#define SHA384_DIGEST_LENGTH 48

/**
 * Initialize a SHA context for SHA-384 operation.
 *
 * \param c     The SHA context to initialize.
 */
void SHA384_Init(SHA512_CTX* c);

/**
 * Add the given data to a SHA-384 context.
 *
 * \param c     The SHA-384 context to update.
 * \param data  A pointer to the data to digest.
 * \param len   The length of the data to digest.
 */
void SHA384_Update(SHA512_CTX* c, const void* data, size_t len);

/**
 * Finalize a SHA-384 context and generate the final hash.
 *
 * \param c     The SHA-384 context to finalize.
 * \param md    A pointer to a buffer to hold the SHA-384 hash.  Must be at
 *              least 48 bytes in length.
 *
 * \returns 0 on success and non-zero on failure.
 */
int SHA384_Final(SHA512_CTX* c, uint8_t* md);

#define SHA512_DIGEST_LENGTH 64

/**
 * Initialize a SHA context for SHA-512 operation.
 *
 * \param c     The SHA context to initialize.
 */
void SHA512_Init(SHA512_CTX* c);

/**
 * Add the given data to a SHA-512 context.
 *
 * \param c     The SHA-512 context to update.
 * \param data  A pointer to the data to digest.
 * \param len   The length of the data to digest.
 */
void SHA512_Update(SHA512_CTX* c, const void* _data, size_t len);

/**
 * Finalize a SHA-512 context and generate the final hash.
 *
 * \param c     The SHA-512 context to finalize.
 * \param md    A pointer to a buffer to hold the SHA-512 hash.  Must be at
 *              least 64 bytes in length.
 *
 * \returns 0 on success and non-zero on failure.
 */
int SHA512_Final(SHA512_CTX* c, uint8_t* md);

#define SHA512_256_DIGEST_LENGTH 32

/**
 * Initialize a SHA context for SHA-512/256 operation.
 *
 * \param c     The SHA context to initialize.
 */
void SHA512_256_Init(SHA512_CTX* c);

/**
 * Add the given data to a SHA-512/256 context.
 *
 * \param c     The SHA-512/256 context to update.
 * \param data  A pointer to the data to digest.
 * \param len   The length of the data to digest.
 */
void SHA512_256_Update(SHA512_CTX* c, const void* _data, size_t len);

/**
 * Finalize a SHA-512/256 context and generate the final hash.
 *
 * \param c     The SHA-512/256 context to finalize.
 * \param md    A pointer to a buffer to hold the SHA-512/256 hash.  Must be at
 *              least 32 bytes in length.
 *
 * \returns 0 on success and non-zero on failure.
 */
int SHA512_256_Final(SHA512_CTX* c, uint8_t* md);

#endif  //HASH_REF_SHA512_HEADER_GUARD
