/**
 * \file vccrypt_key_derivation_derive_key.c
 *
 * Derive a cryptographic key from a password or passphrase.
 *
 * \copyright 2019 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/key_derivation.h>
#include <vpr/parameters.h>

/**
 * \brief Derive a cryptographic key
 *
 * The key buffer is owned by the caller and must be disposed when no
 * longer needed by calling dispose().
 *
 * \param derived_key       A crypto buffer to receive the derived key.
 *                          The buffer should be the size of the desired 
 *                          key length.
 * \param context           Opaque pointer to the
 *                          vccrypt_key_derivation_context_t structure.
 * \param pass              A buffer containing a password or passphrase
 * \param salt              A buffer containing a salt value
 * \param rounds            The number of rounds to process.  More rounds
 *                          increases randomness and computational cost.
 *
 * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
 */
int vccrypt_key_derivation_derive_key(
    vccrypt_buffer_t* derived_key,
    vccrypt_key_derivation_context_t* context,
    const vccrypt_buffer_t* pass, const vccrypt_buffer_t* salt,
    unsigned int rounds)
{
    MODEL_ASSERT(NULL != context);
    MODEL_ASSERT(NULL != context->options);
    MODEL_ASSERT(NULL != pass);
    MODEL_ASSERT(pass->size > 0);
    MODEL_ASSERT(NULL != salt);
    MODEL_ASSERT(salt->size > 0);
    MODEL_ASSERT(NULL != derived_key);
    MODEL_ASSERT(derived_key->size > 0);
    MODEL_ASSERT(rounds > 0);


    /* parameter sanity check */
    if (NULL == context || NULL == context->options ||
        NULL == context->options->vccrypt_key_derivation_alg_derive_key ||
        NULL == pass || 0 == pass->size ||
        NULL == salt || 0 == salt->size ||
        NULL == derived_key || 0 == derived_key->size ||
        0 == rounds)
    {
        return VCCRYPT_ERROR_KEY_DERIVATION_DERIVE_KEY_INVALID_ARG;
    }

    return context->options->vccrypt_key_derivation_alg_derive_key(
        derived_key, context, pass, salt, rounds);
}
