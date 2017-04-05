/**
 * \file interfaces.h
 *
 * Cryptographic primitive interfaces.  Each interface has a unique 32-bit value
 * that is used for abstract factory registration.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_INTERFACES_HEADER_GUARD
#define VCCRYPT_INTERFACES_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/** The base interface ID is 0x43000000 */
#define VCCRYPT_INTERFACE_BASE 0x43000000
/** Cryptographic Hash -- see vccrypt/hash.h */
#define VCCRYPT_INTERFACE_HASH 0x43000010
/** Message Authentication Code -- see vccrypt/mac.h */
#define VCCRYPT_INTERFACE_MAC 0x43000020
/** Digital Signature -- see vccrypt/digital_signature.h */
#define VCCRYPT_INTERFACE_SIGNATURE 0x43000030
/** Cryptographic PRNG -- see vccrypt/prng.h */
#define VCCRYPT_INTERFACE_PRNG 0x43000040

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_INTERFACES_HEADER_GUARD
