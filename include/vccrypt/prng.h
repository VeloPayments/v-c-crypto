/**
 * \file prng.h
 *
 * \brief The PRNG primitive provides a mechanism to generate and expand
 * cryptographic pseudo-random data using facilities provided by the OS or
 * hardware.
 *
 * \copyright 2017-2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_PRNG_HEADER_GUARD
#define VCCRYPT_PRNG_HEADER_GUARD

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <vccrypt/buffer.h>
#include <vccrypt/error_codes.h>
#include <vccrypt/function_decl.h>
#include <vccrypt/interfaces.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>
#include <vpr/uuid.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup PRNGSources Cryptographic PRNG sources.
 *
 * \brief Sources optionally supported by the CPRNG subsystem.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these algorithms to initialize a
 * \ref vccrypt_prng_options_t structure. Registration is a link-time
 * optimization that ensures that only cryptographic primitives needed by the
 * application are linked in the application or library.
 *
 * @{
 */

/**
 * \brief Selector for the CPRNG provided by the operating system.
 */
#define VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM 0x00000100
/**
 * @}
 */

/**
 * \defgroup PRNGSourceRegistration Registration functions for PRNG sources.
 *
 * \brief An appropriate function in this group must be called before using the
 * associated PRNG functionality.
 *
 * This resolves linking of the dependent methods for a given PRNG source.
 * @{
 */

/**
 * \brief Register the CPRNG source provided by the operating system.
 */
void vccrypt_prng_register_source_operating_system();
/**
 * @}
 */

/**
 * \brief PRNG Options.
 */
typedef struct vccrypt_prng_options
{
    /**
     * \brief This options structure is disposable.
     */
    disposable_t hdr;

    /**
     * \brief The allocation options to use.
     */
    allocator_options_t* alloc_opts;

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
    int (*vccrypt_prng_alg_init)(void* options, void* context);

    /**
     * \brief Algorithm-specific disposal for a PRNG instance.
     *
     * \param options           Opaque pointer to this options structure.
     * \param context           Opaque pointer to the vccrypt_prng_context_t
     *                          structure to dispose.
     */
    void (*vccrypt_prng_alg_dispose)(void* options, void* context);

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
    int (*vccrypt_prng_alg_read)(void* context, uint8_t* buffer, size_t length);

    /**
     * \brief Implementation specific options init method.
     *
     * \param options           The options structure to initialize.
     * \param alloc_opts        The allocator options structure for this method.
     *
     * \returns \ref VCCRYPT_STATUS_SUCCESS on success and non-zero on failure.
     */
    int (*vccrypt_prng_alg_options_init)(
        void* options, allocator_options_t* alloc_opts);

    /**
     * \brief Options level context pointer.
     */
    void* options_context;

} vccrypt_prng_options_t;

/**
 * \brief This structure is used to hold the algorithm-dependent prng state as
 * well as references to any external resources necessary to generate
 * cryptographically random numbers.
 */
typedef struct vccrypt_prng_context
{
    /**
     * \brief This context is disposable.
     */
    disposable_t hdr;

    /**
     * \brief The options to use for this context.
     */
    vccrypt_prng_options_t* options;

    /**
     * \brief The opaque state structure used for this prng.
     */
    void* prng_state;

} vccrypt_prng_context_t;

/**
 * \brief Initialize PRNG options, looking up an appropriate source registered
 * in the abstract factory.
 *
 * The options structure is owned by the caller and must be disposed when no
 * longer needed by calling dispose().
 *
 * Note that the register method associated with the selected source should have
 * been called during application or library initialization.  Otherwise, the
 * the selected source may not be linked to this executable.
 *
 * \param options       The options structure to initialize.
 * \param alloc_opts    The allocator options to use.
 * \param source        The PRNG source to use.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_PRNG_OPTIONS_INIT_MISSING_IMPL if the provided
 *             CPRNG source selector is either invalid or unregistered.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_prng_options_init(
    vccrypt_prng_options_t* options, allocator_options_t* alloc_opts,
    uint32_t source);

/**
 * \brief Initialize a prng instance with the given options.
 *
 * If initialization is successful, then this prng instance is owned by the
 * caller and must be disposed by calling dispose() when no longer needed.
 *
 * \param options       The options to use for this algorithm instance.
 * \param context       The prng instance to initialize.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_prng_init(
    vccrypt_prng_options_t* options, vccrypt_prng_context_t* context);

/**
 * \brief Read cryptographically random bytes into the given buffer.
 *
 * Internally, the PRNG source may need to reseed, which may cause the current
 * thread to block until the reseeding process is complete.
 *
 * \param context       The prng instance to initialize.
 * \param buffer        The buffer into which the bytes should be read.
 * \param length        The number of random bytes to write to the buffer.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - \ref VCCRYPT_ERROR_PRNG_READ_WOULD_OVERWRITE if this read would
 *             overwrite the provided \ref vccrypt_buffer_t instance.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_prng_read(
    vccrypt_prng_context_t* context, vccrypt_buffer_t* buffer, size_t length);

/**
 * \brief Read cryptographically random bytes into the given c buffer.
 *
 * Internally, the PRNG source may need to reseed, which may cause the current
 * thread to block until the reseeding process is complete.
 *
 * \param context       The prng instance to initialize.
 * \param buffer        The buffer into which the bytes should be read.
 * \param length        The number of random bytes to write to the buffer.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_prng_read_c(
    vccrypt_prng_context_t* context, uint8_t* buffer, size_t length);

/**
 * \brief Read a cryptographically random UUID from the prng.
 *
 * Internally, the PRNG source may need to reseed, which may cause the current
 * thread to block until the reseeding process is complete.
 *
 * \param context       The prng instance to initialize.
 * \param uuid          The uuid to read.
 *
 * \returns a status indicating success or failure.
 *      - \ref VCCRYPT_STATUS_SUCCESS on success.
 *      - a non-zero error code indicating failure.
 */
int VCCRYPT_DECL_MUST_CHECK
vccrypt_prng_read_uuid(
    vccrypt_prng_context_t* context, vpr_uuid* uuid);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_PRNG_HEADER_GUARD
