/**
 * \file vccrypt_key_derivation_options_init.c
 *
 * Initialize a key derivation options structure.
 *
 * \copyright 2019-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/mac.h>
#include <vccrypt/key_derivation.h>
#include <vccrypt/interfaces.h>
#include <vpr/abstract_factory.h>
#include <vpr/disposable.h>
#include <vpr/parameters.h>

/**
 * \brief Initialize key derivation options, looking up an appropriate key
 * derivation algorithm registered in the abstract factory.
 *
 * The options structure is owned by the caller and must be disposed when no
 * longer needed by calling dispose().
 *
 * Note that the register method associated with the selected algorithm should
 * have been called during application or library initialization.  Otherwise,
 * the selected algorithm may not be linked to this executable.
 *
 * \param options          The options structure to initialize.
 * \param alloc_opts       The allocator options to use.
 * \param kd_algorithm     The key derivation algorithm to use.
 * \param hmac_algorithm   The HMAC algorithm to use for the PRF.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_KEY_DERIVATION_OPTIONS_INIT_MISSING_IMPL if the
 *             provided instance selector is invalid or unregistered.
 *      - a non-zero error code indicating failure.
 */
int vccrypt_key_derivation_options_init(
    vccrypt_key_derivation_options_t* options,
    allocator_options_t* alloc_opts, uint32_t kd_algorithm,
    uint32_t hmac_algorithm)
{
    MODEL_ASSERT(NULL != options);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(0 != algorithm);

    abstract_factory_registration_t* reg = NULL;

    /* clear the options structure to start */
    memset(options, 0, sizeof(vccrypt_key_derivation_options_t));

    /* attempt to find an applicable implementation. */
    reg = abstract_factory_find(VCCRYPT_INTERFACE_KD, kd_algorithm);
    if (NULL == reg)
    {
        return VCCRYPT_ERROR_KEY_DERIVATION_OPTIONS_INIT_MISSING_IMPL;
    }

    /* the context structure is the options structure to copy. */
    memcpy(options, reg->context, sizeof(vccrypt_key_derivation_options_t));

    /* attempt to find an HMAC implementation */
    reg = abstract_factory_find(VCCRYPT_INTERFACE_MAC, hmac_algorithm);
    if (NULL == reg)
    {
        return VCCRYPT_ERROR_KEY_DERIVATION_OPTIONS_INIT_MISSING_HMAC_IMPL;
    }

    options->hmac_algorithm = hmac_algorithm;
    vccrypt_mac_options_t* mac_opts = (vccrypt_mac_options_t*)reg->context;
    options->hmac_digest_length = mac_opts->mac_size;

    /* set the allocator. */
    options->alloc_opts = alloc_opts;

    /* verify that the disposer and options_init methods are set. */
    if (
        0 == options->hdr.dispose
     || 0 == options->vccrypt_key_derivation_alg_options_init)
    {
        return VCCRYPT_ERROR_KEY_DERIVATION_OPTIONS_INIT_MISSING_IMPL;
    }

    /* Call the implementation specific options init method. */
    return
        options->vccrypt_key_derivation_alg_options_init(options, alloc_opts);
}
