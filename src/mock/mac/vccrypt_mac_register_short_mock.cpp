/**
 * \file vccrypt_mac_register_short_mock.cpp
 *
 * \brief Register mock short mac algorithm.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/mock/mac.h>
#include <vpr/abstract_factory.h>
#include <vpr/parameters.h>

/* forward decls */
static int mock_short_mac_alg_init(
    void* options, void* context, vccrypt_buffer_t* key);
static void mock_short_mac_alg_dispose(void* options, void* context);
static int mock_short_mac_alg_options_init(
    void* options, allocator_options_t* alloc_opts);
static void mock_short_mac_alg_option_dispose(void* disp);
static int mock_short_mac_alg_digest(
    void* context, const uint8_t* data, size_t size);
static int mock_short_mac_alg_finalize(
    void* context, vccrypt_buffer_t* mac_buffer);

/* static data for this instance */
static abstract_factory_registration_t mock_short_mac_impl;
static vccrypt_mac_options_t mock_short_mac_options;
static bool mock_short_mac_impl_registered = false;

/**
 * \brief Register the short mac mock.
 */
void vccrypt_mac_register_short_mock()
{
    /* only register once */
    if (mock_short_mac_impl_registered)
    {
        return;
    }

    /* set up the options for mock short mac. */
    mock_short_mac_options.hdr.dispose = &mock_short_mac_alg_option_dispose;
    mock_short_mac_options.alloc_opts = 0; /* allocator handled by init */
    mock_short_mac_options.key_size = VCCRYPT_MAC_SHA_512_KEY_SIZE;
    mock_short_mac_options.key_expansion_supported = true;
    mock_short_mac_options.mac_size = VCCRYPT_MAC_SHA_512_MAC_SIZE;
    mock_short_mac_options.maximum_message_size =
        SIZE_MAX; /* actually, 2^128-1 */
    mock_short_mac_options.vccrypt_mac_alg_init = &mock_short_mac_alg_init;
    mock_short_mac_options.vccrypt_mac_alg_dispose =
        &mock_short_mac_alg_dispose;
    mock_short_mac_options.vccrypt_mac_alg_digest =
        &mock_short_mac_alg_digest;
    mock_short_mac_options.vccrypt_mac_alg_finalize =
        &mock_short_mac_alg_finalize;
    mock_short_mac_options.vccrypt_mac_alg_options_init =
        &mock_short_mac_alg_options_init;

    /* set up this registration for the abstract factory. */
    mock_short_mac_impl.interface = VCCRYPT_INTERFACE_MAC;
    mock_short_mac_impl.implementation = VCCRYPT_MAC_ALGORITHM_SHORT_MOCK;
    mock_short_mac_impl.implementation_features =
        VCCRYPT_MAC_ALGORITHM_SHORT_MOCK;
    mock_short_mac_impl.factory = 0;
    mock_short_mac_impl.context = &mock_short_mac_options;

    /* register this instance */
    abstract_factory_register(&mock_short_mac_impl);

    /* only register once */
    mock_short_mac_impl_registered = true;
}

/**
 * Algorithm-specific initialization.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_mac_context_t structure.
 * \param key       The key to use for this instance.
 *
 * \returns 0 on success and non-zero on error.
*/
static int mock_short_mac_alg_init(
    void* options, void* context, vccrypt_buffer_t* key)
{
    vccrypt_mac_options_t* mac_options = (vccrypt_mac_options_t*)options;
    vccrypt_mac_context_t* mac_context = (vccrypt_mac_context_t*)context;

    mac_mock* mock = (mac_mock*)mac_options->options_context;

    if (!mock->mac_init_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->mac_init_mock)(mac_options, mac_context, key);
    }
}

/**
 * Algorithm-specific disposal.
 *
 * \param options   Opaque pointer to this options structure.
 * \param context   Opaque pointer to vccrypt_mac_context_t structure.
 */
static void mock_short_mac_alg_dispose(void* options, void* context)
{
    vccrypt_mac_options_t* mac_options = (vccrypt_mac_options_t*)options;
    vccrypt_mac_context_t* mac_context = (vccrypt_mac_context_t*)context;

    mac_mock* mock = (mac_mock*)mac_options->options_context;

    if (!!mock->mac_dispose_mock)
    {
        return (*mock->mac_dispose_mock)(mac_options, mac_context);
    }
}

/**
 * Digest data for this instance.
 *
 * \param context       An opaque pointer to the vccrypt_mac_context_t
 *                      structure.
 * \param data          A pointer to raw data to digest.
 * \param size          The size of the data to digest, in bytes.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int mock_short_mac_alg_digest(
    void* context, const uint8_t* data, size_t size)
{
    vccrypt_mac_context_t* mac_context = (vccrypt_mac_context_t*)context;
    vccrypt_mac_options_t* mac_options = mac_context->options;

    mac_mock* mock = (mac_mock*)mac_options->options_context;

    if (!mock->mac_digest_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->mac_digest_mock)(mac_context, data, size);
    }
}

/**
 * Finalize the message authentication code, copying the output data to the
 * given buffer.
 *
 * \param context       An opaque pointer to the vccrypt_mac_context_t
 *                      structure.
 * \param mac_buffer    The buffer to receive the MAC.  Must be large enough
 *                      for the given MAC algorithm.
 *
 * \returns 0 on success and non-zero on failure.
 */
static int mock_short_mac_alg_finalize(
    void* context, vccrypt_buffer_t* mac_buffer)
{
    vccrypt_mac_context_t* mac_context = (vccrypt_mac_context_t*)context;
    vccrypt_mac_options_t* mac_options = mac_context->options;

    mac_mock* mock = (mac_mock*)mac_options->options_context;

    if (!mock->mac_finalize_mock)
    {
        return VCCRYPT_ERROR_MOCK_NOT_ADDED;
    }
    else
    {
        return (*mock->mac_finalize_mock)(mac_context, mac_buffer);
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
static int mock_short_mac_alg_options_init(
    void* options, allocator_options_t* UNUSED(alloc_opts))
{
    vccrypt_mac_options_t* mac_opts = (vccrypt_mac_options_t*)options;

    mac_opts->options_context = new mac_mock;

    return VCCRYPT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure.
 *
 * \param disp      the options structure to dispose.
 */
static void mock_short_mac_alg_option_dispose(void* disp)
{
    vccrypt_mac_options_t* mac_opts = (vccrypt_mac_options_t*)disp;

    MODEL_ASSERT(mac_opts != NULL);

    mac_mock* mock = (mac_mock*)mac_opts->options_context;
    delete mock;

    memset(mac_opts, 0, sizeof(vccrypt_mac_options_t));
}
