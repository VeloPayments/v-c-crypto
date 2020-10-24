/**
 * \file mock/hash.h
 *
 * \brief Mock of the hash algorithm.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_MOCK_HASH_HEADER_GUARD
#define VCCRYPT_MOCK_HASH_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup HashAlgorithms Cryptographic Hash Algorithms.
 *
 * \brief Algorithms optionally supported by the hash subsystem.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these hash algorithms to initialize a \ref
 * vccrypt_hash_options_t structure.  Registration is a link-time optimization
 * that ensures that only cryptographic primitives needed by the application are
 * linked in the application or library.
 *
 * @{
 */

/**
 * \brief Selector for the mock hash algorithm.
 */
#define VCCRYPT_HASH_ALGORITHM_MOCK 0x80000000
/**
 * @}
 */

/**
 * \defgroup HashRegistration Registration functions for Hash Algorithms.
 *
 * \brief An appropriate function in this group must be called before using the
 * associated hash functionality.
 *
 * This resolves linking of the dependent methods for a given hash algorithm.
 * @{
 */

/**
 * \brief Register the mock algorithm.
 */
void vccrypt_hash_register_mock();
/**
 * @}
 */

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

/* C++ mock structs for testing start here. */
#if       defined(__cplusplus)

#include <functional>
#include <memory>

/**
 * \brief The mock structure for hash options.
 */
struct hash_mock
{
    /**
     * \brief init mock.
     */
    std::shared_ptr<
        std::function<int (vccrypt_hash_options_t*, vccrypt_hash_context_t*)>>
    hash_init_mock;

    /**
     * \brief dispose mock.
     */
    std::shared_ptr<
        std::function<void (vccrypt_hash_options_t*, vccrypt_hash_context_t*)>>
    hash_dispose_mock;

    /**
     * \brief digest mock.
     */
    std::shared_ptr<
        std::function<int (vccrypt_hash_context_t*, const uint8_t*, size_t)>>
    hash_digest_mock;

    /**
     * \brief finalize mock.
     */
    std::shared_ptr<
        std::function<int (vccrypt_hash_context_t*, vccrypt_buffer_t*)>>
    hash_finalize_mock;
};

#endif /* defined(__cplusplus) */

#endif  //VCCRYPT_MOCK_HASH_HEADER_GUARD
