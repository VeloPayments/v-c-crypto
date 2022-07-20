/**
 * \file mock/stream_cipher.h
 *
 * \brief Mock of the stream cipher interface.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCRYPT_MOCK_STREAM_CIPHER_HEADER_GUARD
#define VCCRYPT_MOCK_STREAM_CIPHER_HEADER_GUARD

#include <vccrypt/stream_cipher.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup STREAMAlgorithms Stream Cipher Algorithms.
 *
 * \brief Algorithms optionally supported by the Stream Cipher subsystem.
 *
 * Note that the appropriate register method must be called during startup
 * before using one of these Stream Cipher algorithms to initialize a
 * vccrypt_stream_options_t structure. Registration is a link-time optimization
 * that ensures that only cryptographic primitives needed by the application are
 * linked in the application or library.
 *
 * @{
 */

/**
 * \brief Selector for AES-256-CTR FIPS mode.
 */
#define VCCRYPT_STREAM_ALGORITHM_MOCK 0x10000000
/**
 * @}
 */

/**
 * \defgroup STREAMRegistration Registration functions for Stream Cipher Algorithms.
 *
 * \brief An appropriate function in this group must be called before using the
 * associated stream cipher functionality.
 *
 * This resolves linking of the dependent methods for a given stream cipher
 * algorithm.
 * @{
 */

/**
 * \brief Register the mock algorithm.
 */
void vccrypt_stream_register_mock();
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
 * \brief The mock structure for stream options.
 */
struct stream_mock
{
    /**
     * \brief init mock.
     */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_stream_options_t*, vccrypt_stream_context_t*,
                const vccrypt_buffer_t*)>>
    stream_init_mock;

    /**
     * \brief dispose mock.
     */
    std::shared_ptr<
        std::function<
            void (vccrypt_stream_options_t*, vccrypt_stream_context_t*)>>
    stream_dispose_mock;

    /**
     * \brief start encryption mock.
     */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_stream_context_t*, const void*, size_t, void*,
                size_t*)>>
    stream_start_encyption_mock;

    /**
     * \brief continue encryption mock.
     */
    std::shared_ptr<
        std::function<
            int (vccrypt_stream_context_t*, const void*, size_t, size_t)>>
    stream_continue_encyption_mock;

    /**
     * \brief start decryption mock.
     */
    std::shared_ptr<
        std::function<
            int (vccrypt_stream_context_t*, const void*, size_t*)>>
    stream_start_decryption_mock;

    /**
     * \brief continue decryption mock.
     */
    std::shared_ptr<
        std::function<
            int (vccrypt_stream_context_t*, const void*, size_t, size_t)>>
    stream_continue_decryption_mock;

    /**
     * \brief encrypt mock.
     */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_stream_context_t*, const void*, size_t, void*,
                size_t*)>>
    stream_encrypt_mock;

    /**
     * \brief decrypt mock.
     */
    std::shared_ptr<
        std::function<
            int (
                vccrypt_stream_context_t*, const void*, size_t, void*,
                size_t*)>>
    stream_decrypt_mock;
};

#endif /* defined(__cplusplus) */

#endif  //VCCRYPT_MOCK_STREAM_CIPHER_HEADER_GUARD
