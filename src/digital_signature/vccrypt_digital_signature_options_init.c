/**
 * \file vccrypt_digital_signature_options_init.c
 *
 * Initialize a digital signature options structure.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/digital_signature.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/**
 * \brief Initialize digital signature options, looking up an appropriate
 * digital signature algorithm registered in the abstract factory.
 *
 * The options structure is owned by the caller and must be disposed when no
 * longer needed by calling dispose().
 *
 * Note that the register method associated with the selected algorithm should
 * have been called during application or library initialization.  Otherwise,
 * the selected algorithm may not be linked to this executable.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options to use.
 * \param prng_opts     The PRNG to use for this algorithm.  MUST BE COMPATIBLE
 *                      WITH THIS ALGORITHM.
 * \param algorithm     The digital signature algorithm to use.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_DIGITAL_SIGNATURE_OPTIONS_INIT_MISSING_IMPL if the
 *             provided instance selector is invalid or unregistered.
 *      - a non-zero error code indicating failure.
 */
int vccrypt_digital_signature_options_init(
    vccrypt_digital_signature_options_t* options,
    allocator_options_t* alloc_opts, vccrypt_prng_options_t* prng_opts,
    uint32_t algorithm)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(alloc_opts != NULL);
    MODEL_ASSERT(prng_opts != NULL);
    MODEL_ASSERT(algorithm != 0);

    abstract_factory_registration_t* reg = NULL;

    /* clear the options structure to start */
    memset(options, 0, sizeof(vccrypt_digital_signature_options_t));

    /* attempt to find an applicable implementation. */
    reg = abstract_factory_find(VCCRYPT_INTERFACE_SIGNATURE, algorithm);
    if (reg == NULL)
    {
        return VCCRYPT_ERROR_DIGITAL_SIGNATURE_OPTIONS_INIT_MISSING_IMPL;
    }

    /* the context structure is the options structure to copy. */
    memcpy(options, reg->context, sizeof(vccrypt_digital_signature_options_t));

    /* set the allocator. */
    options->alloc_opts = alloc_opts;

    /* set the prng. */
    options->prng_opts = prng_opts;

    /* verify that the disposer and options init method are set. */
    if (
        0 == options->hdr.dispose
     || 0 == options->vccrypt_digital_signature_alg_options_init)
    {
        return VCCRYPT_ERROR_DIGITAL_SIGNATURE_OPTIONS_INIT_MISSING_IMPL;
    }

    /* Call the implementation-specific options init method. */
    return
        options->vccrypt_digital_signature_alg_options_init(
            options, alloc_opts);
}
