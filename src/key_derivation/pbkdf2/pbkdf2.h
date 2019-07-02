#ifndef PBKDF2_PRIVATE_HEADER_GUARD
#define PBKDF2_PRIVATE_HEADER_GUARD

#include <vpr/allocator.h>
#include <vccrypt/key_derivation.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * \brief A pseudorandom function
 *
 * The pseudorandom function (PRF) accepts as input a text value and a key,
 * which are used to produce a fixed length digest value.
 *
 * \param digest        An array to hold the output data
 * \param digest_len    The length of the digest produced by the PRF
 * \param options       Pointer to the options to use
 * \param text          The input data, e.g. a password
 * \param text_len      The length of the input data
 * \param key           The key
 * \param key_len       The length of the key
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code indicating failure.
*/
typedef int (*pbkdf2_prf_t)(uint8_t* digest, size_t digest_len,
    vccrypt_key_derivation_options_t* options,
    const uint8_t* text, size_t text_len,
    const uint8_t* key, size_t key_len);


/**
 * \brief Applies a pseudorandom function to an input password or passphrase,
 * along with a salt value, to produce a derived key.
 *
 * \param derived_key         The output derived key
 * \param derived_key_len     The desired length of the derived key
 * \param options             The options to use
 * \param prf                 A pseudo random function, e.g. keyed HMAC
 * \param pass                The password or passphrase
 * \param pass_len            The length of the password or passphrase
 * \param salt                A salt value, typically random data
 * \param salt_len            The length of the salt
 * \param rounds              The number of rounds to process.  More rounds
 *                            increases randomness and computational cost.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS if successful.
 */
int pkcs5_pbkdf2(
    uint8_t* derived_key, size_t derived_key_len,
    vccrypt_key_derivation_options_t* options, pbkdf2_prf_t prf,
    const char* pass, size_t pass_len,
    const uint8_t* salt, size_t salt_len, unsigned int rounds);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*PBKDF2_PRIVATE_HEADER_GUARD*/
