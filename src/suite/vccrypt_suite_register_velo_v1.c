/**
 * \file vccrypt_suite_register_velo_v1.c
 *
 * Register the V1 crypto suite used by Velo and force a link dependency so that
 * all required algorithms and primitives can be used at runtime.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/suite.h>
#include <vpr/abstract_factory.h>
#include <vpr/allocator.h>
#include <vpr/parameters.h>

/* forward decls */
static int velo_v1_hash_init(
    void* options, vccrypt_hash_context_t* context);
static int velo_v1_digital_signature_init(
    void* options, vccrypt_digital_signature_context_t* context);
static int velo_v1_prng_init(
    void* options, vccrypt_prng_context_t* context);

/* static data for this instance */
static abstract_factory_registration_t velo_v1_impl;
static vccrypt_suite_options_t velo_v1_options;
static bool velo_v1_impl_registered = false;

/**
 * Register the Velo V1 crypto suite.
 */
void vccrypt_suite_register_velo_v1()
{
    MODEL_ASSERT(!velo_v1_impl_registered);

    /* only register once */
    if (velo_v1_impl_registered)
    {
        return;
    }

    /* register all requisite algorithms and sources */
    vccrypt_hash_register_SHA_2_512();
    vccrypt_digital_signature_register_ed25519();
    vccrypt_prng_register_source_operating_system();

    /* set up the options for velo V1 */
    velo_v1_options.hdr.dispose = 0; /* disposal handled by init */
    velo_v1_options.alloc_opts = 0; /* allocator handled by init */
    velo_v1_options.hash_alg = VCCRYPT_HASH_ALGORITHM_SHA_2_512;
    velo_v1_options.sign_alg = VCCRYPT_DIGITAL_SIGNATURE_ALGORITHM_ED25519;
    velo_v1_options.prng_src = VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM;
    velo_v1_options.vccrypt_suite_hash_alg_init =
        &velo_v1_hash_init;
    velo_v1_options.vccrypt_suite_digital_signature_alg_init =
        &velo_v1_digital_signature_init;
    velo_v1_options.vccrypt_suite_prng_alg_init =
        &velo_v1_prng_init;

    /* set up this registration for the abstract factory. */
    velo_v1_impl.interface =
        VCCRYPT_INTERFACE_SUITE;
    velo_v1_impl.implementation =
        VCCRYPT_SUITE_VELO_V1;
    velo_v1_impl.implementation_features =
        VCCRYPT_SUITE_VELO_V1;
    velo_v1_impl.factory = 0;
    velo_v1_impl.context = &velo_v1_options;

    /* register this instance. */
    abstract_factory_register(&velo_v1_impl);

    /* only register once */
    velo_v1_impl_registered = true;
}

/**
 * Suite-specific initialization for a hash algorithm instance.
 *
 * \param options       Opaque pointer to the suite options.
 * \param context       Hash algorithm context to initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int velo_v1_hash_init(
    void* options, vccrypt_hash_context_t* context)
{
    vccrypt_suite_options_t* opts = (vccrypt_suite_options_t*)options;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(context != NULL);

    return vccrypt_hash_init(&opts->hash_opts, context);
}

/**
 * Suite-specific initialization for a digital signature algorithm instance.
 *
 * \param options       Opaque pointer to the suite options.
 * \param context       The digital signature instance to initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int velo_v1_digital_signature_init(
    void* options, vccrypt_digital_signature_context_t* context)
{
    vccrypt_suite_options_t* opts = (vccrypt_suite_options_t*)options;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(context != NULL);

    return vccrypt_digital_signature_init(&opts->sign_opts, context);
}

/**
 * Suite-specific initialization for a PRNG source.
 *
 * \param options       Opaque pointer to the suite options.
 * \param context       The PRNG context to initialize.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int velo_v1_prng_init(
    void* options, vccrypt_prng_context_t* context)
{
    vccrypt_suite_options_t* opts = (vccrypt_suite_options_t*)options;

    MODEL_ASSERT(opts != NULL);
    MODEL_ASSERT(context != NULL);

    return vccrypt_prng_init(&opts->prng_opts, context);
}
