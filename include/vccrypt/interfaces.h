/**
 * \file interfaces.h
 *
 * \brief Cryptographic primitive interfaces for the vccrypt library.
 *
 * Each interface has a unique 32-bit value that is used for abstract factory
 * registration.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_INTERFACES_HEADER_GUARD
#define VCCRYPT_INTERFACES_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup Interfaces Cryptographic interfaces.
 *
 * \brief These cryptographic interfaces are used for registration.
 *
 * @{
 */

/**
 * \brief The base interface ID, representing the range for all interfaces in
 * this module.
 */
#define VCCRYPT_INTERFACE_BASE 0x43000000

/** 
 * \brief The Cryptographic Hash interface -- see vccrypt/hash.h
 */
#define VCCRYPT_INTERFACE_HASH 0x43000010

/** \brief The Counter Mode Stream Cipher interface -- see
 * vccrypt/stream_cipher.h 
 */
#define VCCRYPT_INTERFACE_STREAM 0x43000020

/**
 * \brief The Cipher Block Chaining Mode Block Cipher interface -- see
 * vccrypt/block_cipher.h
 */
#define VCCRYPT_INTERFACE_BLOCK 0x43000030

/**
 * \brief The Message Authentication Code interface -- see vccrypt/mac.h
 */
#define VCCRYPT_INTERFACE_MAC 0x43000040

/**
 * \brief The Key Agreement interface -- see vccrypt/key_agreement.h
 */
#define VCCRYPT_INTERFACE_KEY 0x43000050

/**
 * \brief The Digital Signature interface -- see vccrypt/digital_signature.h
 */
#define VCCRYPT_INTERFACE_SIGNATURE 0x43000060

/**
 * \brief The Cryptographic PRNG interface -- see vccrypt/prng.h
 */
#define VCCRYPT_INTERFACE_PRNG 0x43000070

/**
 * \brief The Crypto Suite interface -- see vccrypt/suite.h
 */
#define VCCRYPT_INTERFACE_SUITE 0x43000080
/**
 * @}
 */

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_INTERFACES_HEADER_GUARD
