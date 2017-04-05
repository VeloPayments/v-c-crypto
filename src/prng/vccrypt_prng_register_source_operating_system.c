/**
 * \file vccrypt_prng_register_source_operating_system.c
 *
 * Register the OS PRNG source to force a link-time dependency.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/prng.h>
#include <vpr/abstract_factory.h>
#include <vpr/allocator.h>
#include <vpr/parameters.h>

#include "vccrypt_prng_source_os.h"

/* static data for this instance */
static abstract_factory_registration_t prng_os_impl;
static vccrypt_prng_options_t prng_os_options;
static bool prng_os_impl_registered = false;

/**
 * Register the operating system source for a PRNG.
 */
void vccrypt_prng_register_source_operating_system()
{
    MODEL_ASSERT(!prng_os_impl_registered);

    /* only register once */
    if (prng_os_impl_registered)
    {
        return;
    }

    /* set up the options for the os prng. */
    prng_os_options.hdr.dispose = 0; /* dispose handled by init */
    prng_os_options.alloc_opts = 0; /* alloc handled by init */
    prng_os_options.vccrypt_prng_alg_init = &vccrypt_prng_os_init;
    prng_os_options.vccrypt_prng_alg_dispose = &vccrypt_prng_os_dispose;
    prng_os_options.vccrypt_prng_alg_read = &vccrypt_prng_os_read;

    /* set up this registration for the prng source. */
    prng_os_impl.interface = VCCRYPT_INTERFACE_PRNG;
    prng_os_impl.implementation = VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM;
    prng_os_impl.implementation_features = VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM;
    prng_os_impl.factory = 0;
    prng_os_impl.context = &prng_os_options;

    /* register this instance. */
    abstract_factory_register(&prng_os_impl);

    /* only register this once */
    prng_os_impl_registered = true;
}
