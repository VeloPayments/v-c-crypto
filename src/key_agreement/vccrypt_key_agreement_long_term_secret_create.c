/**
 * \file vccrypt_key_agreement_long_term_secret_create.c
 *
 * Create the long-term secret between two peers using the private key from one
 * and the public key from the other.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/key_agreement.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * Generate a long-term secret, given a private key and a public key.
 *
 * \param context       The key agreement algorithm instance to use for this
 *                      derivation.
 * \param priv          The private key to use for this operation.
 * \param pub           The public key to use for this operation.
 * \param shared        The buffer to receive the long-term secret.
 *
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_key_agreement_long_term_secret_create(
    vccrypt_key_agreement_context_t* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, vccrypt_buffer_t* shared)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->options != NULL);
    MODEL_ASSERT(
        context->options->vccrypt_key_agreement_alg_long_term_secret_create != NULL);
    MODEL_ASSERT(priv != NULL);
    MODEL_ASSERT(priv->size == context->options->private_key_size);
    MODEL_ASSERT(pub != NULL);
    MODEL_ASSERT(pub->size == context->options->public_key_size);
    MODEL_ASSERT(shared != NULL);
    MODEL_ASSERT(shared->size == context->options->shared_secret_size);

    return context->options->vccrypt_key_agreement_alg_long_term_secret_create(
        context, priv, pub, shared);
}
