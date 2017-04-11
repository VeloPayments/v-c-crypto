/**
 * \file vccrypt_digital_signature_keypair_create.c
 *
 * Create a keypair for digital signatures.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/digital_signature.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * Create a keypair.
 *
 * The output buffers must be large enough to accept the resultant keys.
 *
 * \param context       An opaque pointer to the
 *                      vccrypt_digital_signature_context_t structure.
 * \param priv          The output buffer to receive the private key.
 * \param pub           The output buffer to receive the public key.
 */
int vccrypt_digital_signature_keypair_create(
    vccrypt_digital_signature_context_t* context, vccrypt_buffer_t* priv,
    vccrypt_buffer_t* pub)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->options != NULL);
    MODEL_ASSERT(
        context->options->vccrypt_digital_signature_alg_keypair_create != NULL);
    MODEL_ASSERT(priv != NULL);
    MODEL_ASSERT(priv->data != NULL);
    MODEL_ASSERT(priv->size == context->options->private_key_size);
    MODEL_ASSERT(pub != NULL);
    MODEL_ASSERT(pub->data != NULL);
    MODEL_ASSERT(pub->size == context->options->public_key_size);

    return context->options->vccrypt_digital_signature_alg_keypair_create(
        context, priv, pub);
}
