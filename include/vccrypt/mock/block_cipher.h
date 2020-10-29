/**
 * \file block_cipher.h
 *
 * \brief Mock the block cipher interface.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_MOCK_BLOCK_CIPHER_HEADER_GUARD
#define VCCRYPT_MOCK_BLOCK_CIPHER_HEADER_GUARD

#include <vccrypt/block_cipher.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup BLOCKAlgorithms Block Cipher Algorithms.
 *
 * \brief Algorithms optionally supported by the Block Cipher subsystem.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these Block Cipher algorithms to initialize a \brief
 * vccrypt_block_options_t structure. Registration is a link-time optimization
 * that ensures that only cryptographic primitives needed by the application are
 * linked in the application or library.
 *
 * @{
 */

/**
 * \brief Selector for the mock algorithm.
 */
#define VCCRYPT_BLOCK_ALGORITHM_MOCK 0x80000000
/**
 * @}
 */

/**
 * \defgroup BLOCKRegistration Registration functions for Block Cipher Algorithms.
 *
 * \brief An appropriate function in this group must be called before using the
 * associated block cipher functionality.
 *
 * This resolves linking of the dependent methods for a given block cipher
 * algorithm.
 * @{
 */

/**
 * \brief Register the mock algorithm.
 */
void vccrypt_block_register_mock();
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
 * \brief The mock structure for block options.
 */
struct block_mock
{
    /**
     * \brief init mock.
     */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_block_options_t*, vccrypt_block_context_t*,
                vccrypt_buffer_t*, bool)>>
    block_init_mock;

    /**
     * \brief dispose mock.
     */
    std::shared_ptr<
        std::function<
            void (vccrypt_block_options_t*, vccrypt_block_context_t*)>>
    block_dispose_mock;

    /**
     * \brief encrypt mock.
     */
    std::shared_ptr<
        std::function<
            int (vccrypt_block_context_t*, const void*, const void*, void*)>>
    block_encrypt_mock;

    /**
     * \brief decrypt mock.
     */
    std::shared_ptr<
        std::function<
            int (vccrypt_block_context_t*, const void*, const void*, void*)>>
    block_decrypt_mock;
};

#endif /* defined(__cplusplus) */

#endif  //VCCRYPT_MOCK_BLOCK_CIPHER_HEADER_GUARD
