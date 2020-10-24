/**
 * \file error_codes.h
 *
 * \brief Error codes for vccrypt.
 *
 * \copyright 2018-2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_ERROR_CODES_HEADER_GUARD
#define VCCRYPT_ERROR_CODES_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup StatusCodes Status and error codes for the Velo Crypto Library.
 *
 * \brief These status and error codes are returned by Velo Crypto Library
 * functions.
 *
 * @{
 */

/**
 * \brief The \ref VCCRYPT_STATUS_SUCCESS code represents the successful
 * completion of a Velo Crypto Library method.
 */
#define VCCRYPT_STATUS_SUCCESS 0x0000

/**
 * \brief An attempt was made to call vccrypt_stream_options_init() with an
 * algorithm selector that either does not exist, or was not registered.
 */
#define VCCRYPT_ERROR_STREAM_OPTIONS_INIT_MISSING_IMPL 0x2100

/**
 * \brief An invalid argument was provided to vccrypt_stream_init().
 */
#define VCCRYPT_ERROR_STREAM_INIT_INVALID_ARG 0x2105

/**
 * \brief The vccrypt_stream_init() method ran out of memory when attempting to
 * initialize this stream cipher instance.
 */
#define VCCRYPT_ERROR_STREAM_INIT_OUT_OF_MEMORY 0x2106

/**
 * \brief The provided encryption key did not work with the selected stream
 * cipher algorithm in vccrypt_stream_init().
 */
#define VCCRYPT_ERROR_STREAM_INIT_BAD_ENCRYPTION_KEY 0x2107

/**
 * \brief An invalid argument was provided when calling
 * \ref vccrypt_stream_start_encryption().
 */
#define VCCRYPT_ERROR_STREAM_START_ENCRYPTION_INVALID_ARG 0x210B

/**
 * \brief An attempt was made to call vccrypt_prng_options_init() with a
 * CPRNG source selector that either does not exist, or was not registered.
 */
#define VCCRYPT_ERROR_PRNG_OPTIONS_INIT_MISSING_IMPL 0x210F

/**
 * \brief The vccrypt_prng_init() method ran out of memory when attempting to
 * initialize this CPRNG instance.
 */
#define VCCRYPT_ERROR_PRNG_INIT_OUT_OF_MEMORY 0x2113

/**
 * \brief The vccrypt_prng_init() method failed to open a device handle needed
 * to initialize this CPRNG instance.
 */
#define VCCRYPT_ERROR_PRNG_INIT_DEVICE_OPEN_FAILURE 0x2114

/**
 * \brief The vccrypt_prng_read() method failed to read data from the CPRNG.
 */
#define VCCRYPT_ERROR_PRNG_READ_FAILURE 0x2118

/**
 * \brief The vccrypt_prng_read() method stopped the read because it would have
 * overwritten the provided user \ref vccrypt_buffer_t buffer instance.
 */
#define VCCRYPT_ERROR_PRNG_READ_WOULD_OVERWRITE 0x2119

/**
 * \brief An attempt was made to call vccrypt_suite_options_init() with a
 * suite selector that either does not exist, or was not registered.
 */
#define VCCRYPT_ERROR_SUITE_OPTIONS_INIT_MISSING_IMPL 0x211D

/**
 * \brief An attempt was made to call vccrypt_digital_signature_init() with an
 * invalid argument.
 */
#define VCCRYPT_ERROR_DIGITAL_SIGNATURE_INIT_INVALID_ARG 0x2121

/**
 * \brief An attempt was made to call vccrypt_digital_signature_options_init()
 * with a digital signature algorithm selector that either does not exist, or
 * was not registered.
 */
#define VCCRYPT_ERROR_DIGITAL_SIGNATURE_OPTIONS_INIT_MISSING_IMPL 0x2125

/**
 * \brief An attempt was made to call
 * vccrypt_key_agreement_short_term_secret_create() with an invalid argument.
 */
#define VCCRYPT_ERROR_KEY_AGREEMENT_SHORT_TERM_CREATE_INVALID_ARG 0x2129

/**
 * \brief An attempt was made to call vccrypt_key_agreement_options_init()
 * with a key agreement algorithm selector that either does not exist, or was
 * not registered.
 */
#define VCCRYPT_ERROR_KEY_AGREEMENT_OPTIONS_INIT_MISSING_IMPL 0x212D

/**
 * \brief An attempt was made to call vccrypt_key_agreement_init() with an
 * invalid argument.
 */
#define VCCRYPT_ERROR_KEY_AGREEMENT_INIT_INVALID_ARG 0x2131

/**
 * \brief An attempt was made to call vccrypt_hash_options_init() with a hash
 * algorithm selector that either does not exist, or was not registered.
 */
#define VCCRYPT_ERROR_HASH_OPTIONS_INIT_MISSING_IMPL 0x2135

/**
 * \brief An attempt was made to call vccrypt_hash_init() with an invalid
 * argument.
 */
#define VCCRYPT_ERROR_HASH_INIT_INVALID_ARG 0x2139

/**
 * \brief The vccrypt_hash_init() method ran out of memory when attempting to
 * initialize this \ref vccrypt_hash_context_t instance.
 */
#define VCCRYPT_ERROR_HASH_INIT_OUT_OF_MEMORY 0x213A

/**
 * \brief An attempt was made to call vccrypt_hash_digest() with an invalid
 * argument.
 */
#define VCCRYPT_ERROR_HASH_DIGEST_INVALID_ARG 0x213D

/**
 * \brief An attempt was made to call vccrypt_hash_finalize() with an invalid
 * argument.
 */
#define VCCRYPT_ERROR_HASH_FINALIZE_INVALID_ARG 0x2141

/**
 * \brief An attempt was made to call vccrypt_block_options_init() with an
 * invalid block cipher algorithm selector, or one that has not been registered.
 */
#define VCCRYPT_ERROR_BLOCK_OPTIONS_INIT_MISSING_IMPL 0x2145

/**
 * \brief An attempt was made to call vccrypt_block_init() with a invalid
 * argument.
 */
#define VCCRYPT_ERROR_BLOCK_INIT_INVALID_ARG 0x2149

/**
 * \brief An attempt was made to call vccrypt_block_init() with a bad allocator.
 */
#define VCCRYPT_ERROR_BLOCK_INIT_BAD_ALLOCATOR 0x214A

/**
 * \brief An attempt was made to call vccrypt_block_init() with a bad encryption
 * key.
 */
#define VCCRYPT_ERROR_BLOCK_INIT_BAD_ENCRYPTION_KEY 0x214B

/**
 * \brief An attempt was made to call vccrypt_block_init() with a bad decryption
 * key.
 */
#define VCCRYPT_ERROR_BLOCK_INIT_BAD_DECRYPTION_KEY 0x214C

/**
 * \brief vccrypt_buffer_init() ran out of memory when attempting to initialize
 * a \ref vccrypt_buffer_t instance.
 */
#define VCCRYPT_ERROR_BUFFER_INIT_OUT_OF_MEMORY 0x2150

/**
 * \brief The requested read operation would overwrite a buffer.
 */
#define VCCRYPT_ERROR_BUFFER_READ_WOULD_OVERWRITE 0x2154

/**
 * \brief The requested write operation would overwrite a buffer.
 */
#define VCCRYPT_ERROR_BUFFER_WRITE_WOULD_OVERWRITE 0x2158

/**
 * \brief An argument was invalid.
 */
#define VCCRYPT_ERROR_BUFFER_INVALID_ARGUMENT 0x2159

/**
 * \brief The requested vccrypt_buffer_copy() operation has mismatched buffer
 * sizes.
 */
#define VCCRYPT_ERROR_BUFFER_COPY_MISMATCHED_BUFFER_SIZES 0x215C

/**
 * \brief The padding scheme for this buffer is invalid.
 */
#define VCCRYPT_ERROR_BUFFER_PADDING_SCHEME_INVALID 0x215D

/**
 * \brief An attempt was made to call vccrypt_mac_options_init() with an invalid
 * MAC algorithm selector, or one that has not been registered.
 */
#define VCCRYPT_ERROR_MAC_OPTIONS_INIT_MISSING_IMPL 0x2160

/**
 * \brief vccrypt_mac_init() ran out of memory when initializing a
 * \ref vccrypt_mac_context_t instance.
 */
#define VCCRYPT_ERROR_MAC_INIT_OUT_OF_MEMORY 0x2164

/**
 * \brief An invalid argument was passed to vccrypt_mac_init().
 */
#define VCCRYPT_ERROR_MAC_INIT_INVALID_ARG 0x2165

/**
 * \brief An invalid key for the selected MAC algorithm was passed to
 * vccrypt_mac_init().
 */
#define VCCRYPT_ERROR_MAC_INIT_INVALID_KEY_MAC 0x2166

/**
 * \brief An invalid argument was passed to vccrypt_mac_digest().
 */
#define VCCRYPT_ERROR_MAC_DIGEST_INVALID_ARG 0x2168

/**
 * \brief An invalid argument was passed to vccrypt_mac_finalize().
 */
#define VCCRYPT_ERROR_MAC_FINALIZE_INVALID_ARG 0x216C

/**
 * \brief An invalid argument was passed to pkcs5_pbkdf2().
 */
#define VCCRYPT_ERROR_PBKDF2_INVALID_ARG 0x2170

/**
 * \brief pkdf2() ran out of memory when initializing dynamic memory to contain
 * the salt data.
 */
#define VCCRYPT_ERROR_PBKDF2_INIT_OUT_OF_MEMORY 0x2174

/**
 * \brief An attempt was made to call vccrypt_key_derivation_options_init()
 * with a key derivation algorithm selector that either does not exist, or was
 * not registered.
 */
#define VCCRYPT_ERROR_KEY_DERIVATION_OPTIONS_INIT_MISSING_IMPL 0x2178

/**
 * \brief An attempt was made to call vccrypt_key_derivation_options_init()
 * with an HMAC algorithm selector that either does not exist, or was not
 * registered.
 */
#define VCCRYPT_ERROR_KEY_DERIVATION_OPTIONS_INIT_MISSING_HMAC_IMPL 0x217A

/**
 * \brief An attempt was made to call vccrypt_key_derivation_init() with an
 * invalid argument.
 */
#define VCCRYPT_ERROR_KEY_DERIVATION_INIT_INVALID_ARG 0x217C

/**
 * \brief An attempt was made to call vccrypt_key_derivation_derive_key()
 * with a invalid argument.
 */
#define VCCRYPT_ERROR_KEY_DERIVATION_DERIVE_KEY_INVALID_ARG 0x2180

/**
 * \brief A mock without a mocked function was called.
 */
#define VCCRYPT_ERROR_MOCK_NOT_ADDED 0x2190

/**
 * @}
 */

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_ERROR_CODES_HEADER_GUARD
