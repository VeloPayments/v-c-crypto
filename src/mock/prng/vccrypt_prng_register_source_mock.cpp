/**
 * \file src/mock/prng/vccrypt_prng_register_source_mock.cpp
 *
 * \brief Register the mock PRNG instance.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <stdbool.h>
#include <string.h>
#include <vccrypt/prng.h>
#include <vccrypt/mock/prng.h>
#include <vpr/abstract_factory.h>
#include <vpr/allocator.h>
#include <vpr/parameters.h>

/* static data for this instance */
static int vccrypt_prng_mock_options_init(
    void* options, allocator_options_t* alloc_opts);
static void vccrypt_prng_mock_options_dispose(void* disp);
static int vccrypt_prng_mock_init(void* options, void* context);
static void vccrypt_prng_mock_dispose(void* options, void* context);
static int vccrypt_prng_mock_read(
    void* context, uint8_t* buffer, size_t length);
static abstract_factory_registration_t prng_mock_impl;
static vccrypt_prng_options_t prng_mock_options;
static bool prng_mock_impl_registered = false;

/**
 * Register the operating system source for a PRNG.
 */
void vccrypt_prng_register_source_mock()
{
    MODEL_ASSERT(!prng_mock_impl_registered);

    /* only register once */
    if (prng_mock_impl_registered)
    {
        return;
    }

    /* set up the options for the os prng. */
    prng_mock_options.hdr.dispose = &vccrypt_prng_mock_options_dispose;
    prng_mock_options.alloc_opts = 0; /* alloc handled by init */
    prng_mock_options.vccrypt_prng_alg_init = &vccrypt_prng_mock_init;
    prng_mock_options.vccrypt_prng_alg_dispose = &vccrypt_prng_mock_dispose;
    prng_mock_options.vccrypt_prng_alg_read = &vccrypt_prng_mock_read;
    prng_mock_options.vccrypt_prng_alg_options_init =
        &vccrypt_prng_mock_options_init;

    /* set up this registration for the prng source. */
    prng_mock_impl.interface = VCCRYPT_INTERFACE_PRNG;
    prng_mock_impl.implementation = VCCRYPT_PRNG_SOURCE_MOCK;
    prng_mock_impl.implementation_features = VCCRYPT_PRNG_SOURCE_MOCK;
    prng_mock_impl.factory = 0;
    prng_mock_impl.context = &prng_mock_options;

    /* register this instance. */
    abstract_factory_register(&prng_mock_impl);

    /* only register this once */
    prng_mock_impl_registered = true;
}

/**
 * \brief Initialize a PRNG source suitable to use for generating
 * cryptographically random data.
 *
 * \param options           Opaque pointer to this options structure.
 * \param context           Opaque pointer to the vccrypt_prng_context_t
 *                          structure to initialize.
 *
 * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
 */
static int vccrypt_prng_mock_init(void* options, void* context)
{
    vccrypt_prng_options_t* prng_options = (vccrypt_prng_options_t*)options;
    vccrypt_prng_context_t* prng_context = (vccrypt_prng_context_t*)context;

    prng_mock* mock = (prng_mock*)prng_options->options_context;

    if (!mock->prng_init_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->prng_init_mock)(prng_options, prng_context);
    }
}

/**
 * \brief Algorithm-specific disposal for a PRNG instance.
 *
 * \param options           Opaque pointer to this options structure.
 * \param context           Opaque pointer to the vccrypt_prng_context_t
 *                          structure to dispose.
 */
static void vccrypt_prng_mock_dispose(void* options, void* context)
{
    vccrypt_prng_options_t* prng_options = (vccrypt_prng_options_t*)options;
    vccrypt_prng_context_t* prng_context = (vccrypt_prng_context_t*)context;

    prng_mock* mock = (prng_mock*)prng_options->options_context;

    if (!!mock->prng_dispose_mock)
    {
        return (*mock->prng_dispose_mock)(prng_options, prng_context);
    }
}

/**
 * \brief Get cryptographically random bytes and place these into the given
 * buffer.
 *
 * \param context           Opaque pointer to the instance context.
 * \param buffer            Pointer to the buffer to which the random bytes
 *                          will be written.
 * \param length            The number of bytes to write to the buffer.
 *
 * \returns VCCRYPT_STATUS_SUCCESS on success and non-zero on error.
 */
static int vccrypt_prng_mock_read(
    void* context, uint8_t* buffer, size_t length)
{
    vccrypt_prng_context_t* prng_context = (vccrypt_prng_context_t*)context;
    vccrypt_prng_options_t* prng_options = prng_context->options;

    prng_mock* mock = (prng_mock*)prng_options->options_context;

    if (!mock->prng_read_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->prng_read_mock)(prng_context, buffer, length);
    }
}

/**
 * \brief Implementation specific options init method.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options structure for this method.
 *
 * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
 */
static int vccrypt_prng_mock_options_init(
    void* options, allocator_options_t* UNUSED(alloc_opts))
{
    vccrypt_prng_options_t* prng_options = (vccrypt_prng_options_t*)options;

    prng_options->options_context = new prng_mock;

    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure.
 *
 * \param disp      the options structure to dispose.
 */
static void vccrypt_prng_mock_options_dispose(void* disp)
{
    vccrypt_prng_options_t* prng_options = (vccrypt_prng_options_t*)disp;
    MODEL_ASSERT(prng_options != NULL);

    prng_mock* mock = (prng_mock*)prng_options->options_context;
    delete mock;

    memset(prng_options, 0, sizeof(vccrypt_prng_options_t));
}
