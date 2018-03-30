/**
 * \file vccrypt_key_agreement_short_term_secret_create.c
 *
 * Create the short-term secret between two peers using the private key from
 * one, the public key from the other, and nonce values from both.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/key_agreement.h>
#include <vccrypt/mac.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * Generate a short-term secret, given a private key, a public key, a server
 * nonce, and a client nonce.
 *
 * Internally, this method generates the long-term shared secret for these two
 * peers, and uses this secret to generate a short-term secret via the HMAC
 * algorithm selected for this algorithm instance.  The long-term secret is used
 * as the key for the HMAC.  The nonces should never be used again for this
 * keypair.
 *
 * Note that when this is used to generate a short-term secret in a
 * non-client/server capacity, one peer should be selected as the client and the
 * other as the server.  Both peers should order the nonces the same, meaning
 * that if Peer A is designated the "server", then both Peer A and Peer B should
 * use Peer A's nonce value as the server nonce and Peer B's nonce value as the
 * client nonce.
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
 * \returns 0 on success and non-zero on error.
 */
int vccrypt_key_agreement_short_term_secret_create(
    vccrypt_key_agreement_context_t* context, const vccrypt_buffer_t* priv,
    const vccrypt_buffer_t* pub, const vccrypt_buffer_t* server_nonce,
    const vccrypt_buffer_t* client_nonce, vccrypt_buffer_t* shared)
{
    int retval = VCCRYPT_STATUS_SUCCESS;

    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->options != NULL);
    MODEL_ASSERT(priv != NULL);
    MODEL_ASSERT(priv->size == context->options->private_key_size);
    MODEL_ASSERT(pub != NULL);
    MODEL_ASSERT(pub->size == context->options->public_key_size);
    MODEL_ASSERT(server_nonce != NULL);
    MODEL_ASSERT(server_nonce->size >= context->options->minimum_nonce_size);
    MODEL_ASSERT(client_nonce != NULL);
    MODEL_ASSERT(client_nonce->size >= context->options->minimum_nonce_size);
    MODEL_ASSERT(shared != NULL);
    MODEL_ASSERT(shared->size == context->options->shared_secret_size);

    /* parameter sanity check */
    if (context == NULL || context->options == NULL ||
        context->options->vccrypt_key_agreement_alg_long_term_secret_create == NULL ||
        priv == NULL || priv->size != context->options->private_key_size ||
        pub == NULL || pub->size != context->options->public_key_size ||
        server_nonce == NULL ||
        server_nonce->size < context->options->minimum_nonce_size ||
        client_nonce == NULL ||
        client_nonce->size < context->options->minimum_nonce_size ||
        shared == NULL ||
        shared->size != context->options->shared_secret_size)
    {
        return VCCRYPT_ERROR_KEY_AGREEMENT_SHORT_TERM_CREATE_INVALID_ARG;
    }

    /* create buffer to hold long-term secret. */
    vccrypt_buffer_t ltk;
    retval = vccrypt_buffer_init(
        &ltk, context->options->alloc_opts,
        context->options->shared_secret_size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        return retval;
    }

    /* get long-term secret */
    retval = vccrypt_key_agreement_long_term_secret_create(
        context, priv, pub, &ltk);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto dispose_ltk;
    }

    /* create hmac options */
    vccrypt_mac_options_t mac_opts;
    retval = vccrypt_mac_options_init(
        &mac_opts, context->options->alloc_opts,
        context->options->hmac_algorithm);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto dispose_ltk;
    }

    /* create hmac instance */
    vccrypt_mac_context_t mac;
    retval = vccrypt_mac_init(&mac_opts, &mac, &ltk);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto dispose_mac_opts;
    }

    /* digest server nonce */
    retval = vccrypt_mac_digest(&mac, server_nonce->data, server_nonce->size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto dispose_mac;
    }

    /* digest client nonce */
    retval = vccrypt_mac_digest(&mac, client_nonce->data, client_nonce->size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto dispose_mac;
    }

    /* finalize hmac */
    retval = vccrypt_mac_finalize(&mac, shared);

    /* fall-through */

dispose_mac:
    dispose((disposable_t*)&mac);

dispose_mac_opts:
    dispose((disposable_t*)&mac_opts);

dispose_ltk:
    dispose((disposable_t*)&ltk);

    return retval;
}
