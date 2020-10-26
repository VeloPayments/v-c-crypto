/**
 * \file key_agreement/key_agreement_common.h
 *
 * \brief Common utilitiy functions shared by key_agreement implementations.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef PRIVATE_KEY_AGREEMENT_COMMON_HEADER_GUARD
#define PRIVATE_KEY_AGREEMENT_COMMON_HEADER_GUARD

#include <vccrypt/key_agreement.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \brief Generate a short-term secret, given a private key, a public key, a
 * server nonce, and a client nonce.
 *
 * This method is shared between implementations, since it makes use of the
 * long-term key generation.
 *
 * \param context       The key agreement algorithm instance to use for this
 *                      derivation.
 * \param priv          The private key to use for this operation.
 * \param pub           The public key to use for this operation.
 * \param server_nonce  The server nonce to use to generate the short-term
 *                      secret.
 * \param client_nonce  The client nonce to use to generate the short-term
 *                      secret.
 * \param shared        The buffer to receive the long-term secret.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_KEY_AGREEMENT_SHORT_TERM_CREATE_INVALID_ARG if one
 *             of the provided arguments is invalid.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_key_agreement_short_term_secret_create_common(
    vccrypt_key_agreement_context_t* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, const vccrypt_buffer_t* server_nonce,
    const vccrypt_buffer_t* client_nonce, vccrypt_buffer_t* shared);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //PRIVATE_KEY_AGREEMENT_COMMON_HEADER_GUARD
