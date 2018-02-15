#ifndef AES_PRIVATE_HEADER_GUARD
#define AES_PRIVATE_HEADER_GUARD

#include <stdint.h>

#define AES_MAXNR 56

#define GETU32(pt) ( \
    ((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] << 8) ^ ((uint32_t)(pt)[3]))

#define PUTU32(ct, st) \
    { \
        (ct)[0] = (uint8_t)((st) >> 24); \
        (ct)[1] = (uint8_t)((st) >> 16); \
        (ct)[2] = (uint8_t)((st) >> 8); \
        (ct)[3] = (uint8_t)(st); \
    }

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

typedef struct aes_key
{
    uint32_t rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
} AES_KEY;

/**
 * Expand the cipher key into the encryption key schedule.
 */
int AES_set_encrypt_key(
    const unsigned char* userKey, const int bits, const int roundMult,
    AES_KEY* key);

/**
 * Expand the cipher key into the decryption key schedule.
 */
int AES_set_decrypt_key(
    const unsigned char* userKey, const int bits, const int roundMult,
    AES_KEY* key);

/*
 * Encrypt a single block
 * in and out can overlap
 */
void AES_encrypt(const unsigned char* in, unsigned char* out, const AES_KEY* key);

/*
 * Decrypt a single block
 * in and out can overlap
 */
void AES_decrypt(const unsigned char* in, unsigned char* out, const AES_KEY* key);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*AES_PRIVATE_HEADER_GUARD*/
