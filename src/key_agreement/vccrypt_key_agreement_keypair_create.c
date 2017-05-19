/**
 * \file vccrypt_key_agreement_keypair_create.c
 *
 * Create a keypair using the provided keypair algorithm.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/key_agreement.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * Generate a keypair.
 *
 * \param context       The key agreement algorithm instance to use for this
 *                      keypair generation.
 * \param priv          The buffer to receive the private key.
 * \param pub           The buffer to receive the public key.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_key_agreement_keypair_create(
    vccrypt_key_agreement_context_t* context, vccrypt_buffer_t* priv,
    vccrypt_buffer_t* pub)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->options != NULL);
    MODEL_ASSERT(
        context->options->vccrypt_key_agreement_alg_keypair_create != NULL);
    MODEL_ASSERT(priv != NULL);
    MODEL_ASSERT(priv->size == context->options->private_key_size);
    MODEL_ASSERT(pub != NULL);
    MODEL_ASSERT(pub->size == context->options->public_key_size);

    return context->options->vccrypt_key_agreement_alg_keypair_create(
        context, priv, pub);
}
