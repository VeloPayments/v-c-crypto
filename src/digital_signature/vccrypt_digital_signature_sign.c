/**
 * \file vccrypt_digital_signature_sign.c
 *
 * Sign a message using a digital signature scheme.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/digital_signature.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * Sign a message, given a private key, a message, and a message length.
 *
 * \param context       An opaque pointer to the
 *                      vccrypt_digital_signature_context_t structure.
 * \param sign_buffer   The buffer to receive the signature.  Must be large
 *                      enough for the given digital signature algorithm.
 * \param priv          The private key to use for the signature.
 * \param message       The input message.
 * \param size          The size of the message in bytes.
 *
 * \returns 0 on success and 1 on failure.
 */
int vccrypt_digital_signature_sign(
    vccrypt_digital_signature_context_t* context, vccrypt_buffer_t* sign_buffer,
    const vccrypt_buffer_t* priv, const uint8_t* message, size_t message_size)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->options != NULL);
    MODEL_ASSERT(context->options->vccrypt_digital_signature_alg_sign != NULL);
    MODEL_ASSERT(sign_buffer != NULL);
    MODEL_ASSERT(sign_buffer->size >= context->options->signature_size);
    MODEL_ASSERT(priv != NULL);
    MODEL_ASSERT(priv->size == context->options->private_key_size);
    MODEL_ASSERT(message != NULL);

    return context->options->vccrypt_digital_signature_alg_sign(
        context, sign_buffer, priv, message, message_size);
}
