/**
 * \file vccrypt_digital_signature_verify.c
 *
 * Verify a message using a digital signature scheme.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/digital_signature.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * Verify a message, given a public key, a message, and a message length.
 *
 * \param context       An opaque pointer to the
 *                      vccrypt_digital_signature_context_t structure.
 * \param signature     The signature to verify.
 * \param pub           The public key to use for signature verification.
 * \param message       The input message.
 * \param size          The size of the message in bytes.
 *
 * \returns 0 if the message signature is valid, and no-zero on error.
 */
int vccrypt_digital_signature_verify(
    vccrypt_digital_signature_context_t* context,
    const vccrypt_buffer_t* signature, const vccrypt_buffer_t* pub,
    const uint8_t* message, size_t message_size)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->options != NULL);
    MODEL_ASSERT(
        context->options->vccrypt_digital_signature_alg_verify != NULL);
    MODEL_ASSERT(signature != NULL);
    MODEL_ASSERT(signature->size == context->options->signature_size);
    MODEL_ASSERT(pub != NULL);
    MODEL_ASSERT(pub->size == context->options->public_key_size);
    MODEL_ASSERT(message != NULL);

    return context->options->vccrypt_digital_signature_alg_verify(
        context, signature, pub, message, message_size);
}
