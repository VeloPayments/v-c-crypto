/**
 * \file test_aes_ctr.cpp
 *
 * Unit tests for AES CTR Mode.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#include <vccrypt/stream_cipher.h>
#include <vpr/allocator/malloc_allocator.h>

#include "../../src/stream_cipher/aes/aes.h"
#include "../../src/stream_cipher/stream_cipher_private.h"

/* DISABLED GTEST */
#if 0

static uint64_t mmhtonll(uint64_t n)
{
    return ((((0xFF00000000000000 & n) >> 56) << 0) | (((0x00FF000000000000 & n) >> 48) << 8) | (((0x0000FF0000000000 & n) >> 40) << 16) | (((0x000000FF00000000 & n) >> 32) << 24) | (((0x00000000FF000000 & n) >> 24) << 32) | (((0x0000000000FF0000 & n) >> 16) << 40) | (((0x000000000000FF00 & n) >> 8) << 48) | (((0x00000000000000FF & n) >> 0) << 56));
}

class aes_ctr_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        /* register all AES stream ciphers. */
        vccrypt_stream_register_AES_256_CTR_FIPS();
        vccrypt_stream_register_AES_256_2X_CTR();
        vccrypt_stream_register_AES_256_3X_CTR();
        vccrypt_stream_register_AES_256_4X_CTR();

        /* set up allocator */
        malloc_allocator_options_init(&alloc_opts);

        /* set up options for each variation. */
        fips_options_init_result =
            vccrypt_stream_options_init(
                &fips_options, &alloc_opts,
                VCCRYPT_STREAM_ALGORITHM_AES_256_CTR_FIPS);
        x2_options_init_result =
            vccrypt_stream_options_init(
                &x2_options, &alloc_opts,
                VCCRYPT_STREAM_ALGORITHM_AES_256_2X_CTR);
        x3_options_init_result =
            vccrypt_stream_options_init(
                &x3_options, &alloc_opts,
                VCCRYPT_STREAM_ALGORITHM_AES_256_3X_CTR);
        x4_options_init_result =
            vccrypt_stream_options_init(
                &x4_options, &alloc_opts,
                VCCRYPT_STREAM_ALGORITHM_AES_256_4X_CTR);
    }

    void TearDown() override
    {
        /* tear down options for each variation. */
        if (0 == fips_options_init_result)
        {
            dispose((disposable_t*)&fips_options);
        }
        if (0 == x2_options_init_result)
        {
            dispose((disposable_t*)&x2_options);
        }
        if (0 == x3_options_init_result)
        {
            dispose((disposable_t*)&x3_options);
        }
        if (0 == x4_options_init_result)
        {
            dispose((disposable_t*)&x4_options);
        }

        dispose((disposable_t*)&alloc_opts);
    }

    allocator_options_t alloc_opts;
    vccrypt_stream_options_t fips_options;
    vccrypt_stream_options_t x2_options;
    vccrypt_stream_options_t x3_options;
    vccrypt_stream_options_t x4_options;

    int fips_options_init_result;
    int x2_options_init_result;
    int x3_options_init_result;
    int x4_options_init_result;
};

/**
 * We should be able to create an options structure for each of the supported
 * CTR mode ciphers.
 */
TEST_F(aes_ctr_test, register_options)
{
    /* Test FIPS AES-256-CTR options init. */
    ASSERT_EQ(0, fips_options_init_result);
    EXPECT_NE(nullptr, fips_options.hdr.dispose);
    EXPECT_EQ(&alloc_opts, fips_options.alloc_opts);
    EXPECT_EQ(32U, fips_options.key_size);
    EXPECT_EQ(8U, fips_options.IV_size);
    EXPECT_EQ(UINT64_MAX, fips_options.maximum_message_size);
    EXPECT_NE(nullptr, fips_options.vccrypt_stream_alg_init);
    EXPECT_NE(nullptr, fips_options.vccrypt_stream_alg_start_encryption);
    EXPECT_NE(nullptr, fips_options.vccrypt_stream_alg_start_decryption);
    EXPECT_NE(nullptr, fips_options.vccrypt_stream_alg_encrypt);
    EXPECT_NE(nullptr, fips_options.vccrypt_stream_alg_decrypt);

    /* Test AES-256-2X-CTR options init. */
    ASSERT_EQ(0, x2_options_init_result);
    EXPECT_NE(nullptr, x2_options.hdr.dispose);
    EXPECT_EQ(&alloc_opts, x2_options.alloc_opts);
    EXPECT_EQ(32U, x2_options.key_size);
    EXPECT_EQ(8U, x2_options.IV_size);
    EXPECT_EQ(UINT64_MAX, x2_options.maximum_message_size);
    EXPECT_NE(nullptr, x2_options.vccrypt_stream_alg_init);
    EXPECT_NE(nullptr, x2_options.vccrypt_stream_alg_start_encryption);
    EXPECT_NE(nullptr, x2_options.vccrypt_stream_alg_start_decryption);
    EXPECT_NE(nullptr, x2_options.vccrypt_stream_alg_encrypt);
    EXPECT_NE(nullptr, x2_options.vccrypt_stream_alg_decrypt);

    /* Test AES-256-3X-CTR options init. */
    ASSERT_EQ(0, x3_options_init_result);
    EXPECT_NE(nullptr, x3_options.hdr.dispose);
    EXPECT_EQ(&alloc_opts, x3_options.alloc_opts);
    EXPECT_EQ(32U, x3_options.key_size);
    EXPECT_EQ(8U, x3_options.IV_size);
    EXPECT_EQ(UINT64_MAX, x3_options.maximum_message_size);
    EXPECT_NE(nullptr, x3_options.vccrypt_stream_alg_init);
    EXPECT_NE(nullptr, x3_options.vccrypt_stream_alg_start_encryption);
    EXPECT_NE(nullptr, x3_options.vccrypt_stream_alg_start_decryption);
    EXPECT_NE(nullptr, x3_options.vccrypt_stream_alg_encrypt);
    EXPECT_NE(nullptr, x3_options.vccrypt_stream_alg_decrypt);

    /* Test AES-256-4X-CTR options init. */
    ASSERT_EQ(0, x4_options_init_result);
    EXPECT_NE(nullptr, x4_options.hdr.dispose);
    EXPECT_EQ(&alloc_opts, x4_options.alloc_opts);
    EXPECT_EQ(32U, x4_options.key_size);
    EXPECT_EQ(8U, x4_options.IV_size);
    EXPECT_EQ(UINT64_MAX, x4_options.maximum_message_size);
    EXPECT_NE(nullptr, x4_options.vccrypt_stream_alg_init);
    EXPECT_NE(nullptr, x4_options.vccrypt_stream_alg_start_encryption);
    EXPECT_NE(nullptr, x4_options.vccrypt_stream_alg_start_decryption);
    EXPECT_NE(nullptr, x4_options.vccrypt_stream_alg_encrypt);
    EXPECT_NE(nullptr, x4_options.vccrypt_stream_alg_decrypt);
}

/**
 * We should be able to initialize, start, and encrypt using a FIPS compatible
 * stream cipher. TEST from RFC-3686 (Test Case #7).
 */
TEST_F(aes_ctr_test, aes_256_ctr_fips_01)
{
    vccrypt_stream_context_t ctx;
    vccrypt_buffer_t key;

    const uint8_t KEY[32] = {
        0x77, 0x6b, 0xef, 0xf2, 0x85, 0x1d, 0xb0, 0x6f,
        0x4c, 0x8a, 0x05, 0x42, 0xc8, 0x69, 0x6f, 0x6c,
        0x6a, 0x81, 0xaf, 0x1e, 0xec, 0x96, 0xb4, 0xd3,
        0x7f, 0xc1, 0xd6, 0x89, 0xe6, 0xc1, 0xc1, 0x04
    };
    const uint8_t COUNT_BLOCK[16] = {
        0x00, 0x00, 0x00, 0x60, 0xdb, 0x56, 0x72, 0xc9,
        0x7a, 0xa8, 0xf0, 0xb2, 0x00, 0x00, 0x00, 0x01
    };
    const uint8_t PLAINTEXT[16] = {
        0x53, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20, 0x62,
        0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x6d, 0x73, 0x67
    };
    const uint8_t CIPHERTEXT[16] = {
        0x14, 0x5a, 0xd0, 0x1d, 0xbf, 0x82, 0x4e, 0xc7,
        0x56, 0x08, 0x63, 0xdc, 0x71, 0xe3, 0xe0, 0xc0
    };
    uint64_t DUMMY_IV = mmhtonll(0x0102030405060708UL);
    uint8_t output[24];
    uint8_t poutput[16];
    size_t offset = 99;

    /* write junk to the output buffer */
    memset(output, 0xFC, sizeof(output));

    /* create a buffer for the key data. */
    ASSERT_EQ(0, vccrypt_buffer_init(&key, &alloc_opts, sizeof(KEY)));
    /* read the key into the buffer. */
    ASSERT_EQ(0, vccrypt_buffer_read_data(&key, KEY, sizeof(KEY)));

    /* create a new stream cipher with the given key. */
    ASSERT_EQ(0, vccrypt_stream_init(&fips_options, &ctx, &key));

    /* start encryption using a dummy IV. */
    ASSERT_EQ(0,
        vccrypt_stream_start_encryption(
            &ctx, &DUMMY_IV, sizeof(DUMMY_IV), output, &offset));
    /* the offset should be set to 8. */
    EXPECT_EQ(8U, offset);
    /* the first 8 bytes of output should be set to the value of DUMMY_IV */
    EXPECT_EQ(0x01U, output[0]);
    EXPECT_EQ(0x02U, output[1]);
    EXPECT_EQ(0x03U, output[2]);
    EXPECT_EQ(0x04U, output[3]);
    EXPECT_EQ(0x05U, output[4]);
    EXPECT_EQ(0x06U, output[5]);
    EXPECT_EQ(0x07U, output[6]);
    EXPECT_EQ(0x08U, output[7]);

    /* We need to do a little surgery for this test vector to work.  This is a
     * known-good CTR mode test vector, but the RFC we are using works
     * differently than how we use CTR mode.  We use a 64-bit nonce and a 64-bit
     * counter.  So, we need to update the current counter to match the above
     * counter.
     */
    aes_ctr_context_data_t* priv = (aes_ctr_context_data_t*)ctx.stream_state;
    ASSERT_NE(nullptr, priv);
    memcpy(priv->ctr, COUNT_BLOCK, sizeof(COUNT_BLOCK));
    /* start encryption creates the first 16 bytes of the stream.  We need to
     * redo this with the correct IV. */
    AES_encrypt(priv->ctr, priv->stream, &priv->key);

    /* encrypt the plaintext. */
    ASSERT_EQ(0,
        vccrypt_stream_encrypt(
            &ctx, PLAINTEXT, sizeof(PLAINTEXT), output, &offset));
    /* the offset should be set to 24. */
    EXPECT_EQ(24U, offset);
    /* the next 16 bytes of output should correspond to our ciphertext. */
    for (int i = 0; i < 16; ++i)
    {
        EXPECT_EQ(CIPHERTEXT[i], output[i + 8]);
    }

    /* start decryption using the dummy IV. */
    ASSERT_EQ(0,
        vccrypt_stream_start_decryption(
            &ctx, output, &offset));
    /* the offset should be set to 8 */
    EXPECT_EQ(8U, offset);

    /* We need to do a little surgery for this test vector to work.  This is a
     * known-good CTR mode test vector, but the RFC we are using works
     * differently than how we use CTR mode.  We use a 64-bit nonce and a 64-bit
     * counter.  So, we need to update the current counter to match the above
     * counter.
     */
    memcpy(priv->ctr, COUNT_BLOCK, sizeof(COUNT_BLOCK));
    /* start encryption creates the first 16 bytes of the stream.  We need to
     * redo this with the correct IV. */
    AES_encrypt(priv->ctr, priv->stream, &priv->key);

    offset = 0;

    /* decrypt the ciphertext. */
    ASSERT_EQ(0,
        vccrypt_stream_decrypt(
            &ctx, output + 8, 16, poutput, &offset));
    /* the offset should be set to 16. */
    EXPECT_EQ(16U, offset);
    /* the next 16 bytes of output should correspond to our ciphertext. */
    for (int i = 0; i < 16; ++i)
    {
        EXPECT_EQ(PLAINTEXT[i], poutput[i]);
    }

    /* tear down this instance. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&ctx);
}

/**
 * We should be able to initialize, start, and encrypt using a FIPS compatible
 * stream cipher. TEST from RFC-3686 (Test Case #8).
 */
TEST_F(aes_ctr_test, aes_256_ctr_fips_02)
{
    vccrypt_stream_context_t ctx;
    vccrypt_buffer_t key;

    const uint8_t KEY[32] = {
        0xf6, 0xd6, 0x6d, 0x6b, 0xd5, 0x2d, 0x59, 0xbb,
        0x07, 0x96, 0x36, 0x58, 0x79, 0xef, 0xf8, 0x86,
        0xc6, 0x6d, 0xd5, 0x1a, 0x5b, 0x6a, 0x99, 0x74,
        0x4b, 0x50, 0x59, 0x0c, 0x87, 0xa2, 0x38, 0x84
    };
    const uint8_t COUNT_BLOCK[16] = {
        0x00, 0xfa, 0xac, 0x24, 0xc1, 0x58, 0x5e, 0xf1,
        0x5a, 0x43, 0xd8, 0x75, 0x00, 0x00, 0x00, 0x01
    };
    const uint8_t PLAINTEXT[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const uint8_t CIPHERTEXT[32] = {
        0xf0, 0x5e, 0x23, 0x1b, 0x38, 0x94, 0x61, 0x2c,
        0x49, 0xee, 0x00, 0x0b, 0x80, 0x4e, 0xb2, 0xa9,
        0xb8, 0x30, 0x6b, 0x50, 0x8f, 0x83, 0x9d, 0x6a,
        0x55, 0x30, 0x83, 0x1d, 0x93, 0x44, 0xaf, 0x1c
    };

    uint64_t DUMMY_IV = mmhtonll(0x0102030405060708UL);
    uint8_t output[40];
    uint8_t poutput[32];
    size_t offset = 99;

    /* write junk to the output buffer */
    memset(output, 0xFC, sizeof(output));

    /* create a buffer for the key data. */
    ASSERT_EQ(0, vccrypt_buffer_init(&key, &alloc_opts, sizeof(KEY)));
    /* read the key into the buffer. */
    ASSERT_EQ(0, vccrypt_buffer_read_data(&key, KEY, sizeof(KEY)));

    /* create a new stream cipher with the given key. */
    ASSERT_EQ(0, vccrypt_stream_init(&fips_options, &ctx, &key));

    /* start encryption using a dummy IV. */
    ASSERT_EQ(0,
        vccrypt_stream_start_encryption(
            &ctx, &DUMMY_IV, sizeof(DUMMY_IV), output, &offset));
    /* the offset should be set to 8. */
    EXPECT_EQ(8U, offset);
    /* the first 8 bytes of output should be set to the value of DUMMY_IV */
    EXPECT_EQ(0x01U, output[0]);
    EXPECT_EQ(0x02U, output[1]);
    EXPECT_EQ(0x03U, output[2]);
    EXPECT_EQ(0x04U, output[3]);
    EXPECT_EQ(0x05U, output[4]);
    EXPECT_EQ(0x06U, output[5]);
    EXPECT_EQ(0x07U, output[6]);
    EXPECT_EQ(0x08U, output[7]);

    /* We need to do a little surgery for this test vector to work.  This is a
     * known-good CTR mode test vector, but the RFC we are using works
     * differently than how we use CTR mode.  We use a 64-bit nonce and a 64-bit
     * counter.  So, we need to update the current counter to match the above
     * counter.
     */
    aes_ctr_context_data_t* priv = (aes_ctr_context_data_t*)ctx.stream_state;
    ASSERT_NE(nullptr, priv);
    memcpy(priv->ctr, COUNT_BLOCK, sizeof(COUNT_BLOCK));
    /* start encryption creates the first 16 bytes of the stream.  We need to
     * redo this with the correct IV. */
    AES_encrypt(priv->ctr, priv->stream, &priv->key);

    /* encrypt the plaintext. */
    ASSERT_EQ(0,
        vccrypt_stream_encrypt(
            &ctx, PLAINTEXT, sizeof(PLAINTEXT), output, &offset));
    /* the offset should be set to 40. */
    EXPECT_EQ(40U, offset);
    /* the next 32 bytes of output should correspond to our ciphertext. */
    for (int i = 0; i < 32; ++i)
    {
        EXPECT_EQ(CIPHERTEXT[i], output[i + 8]);
    }

    /* start decryption using the dummy IV. */
    ASSERT_EQ(0,
        vccrypt_stream_start_decryption(
            &ctx, output, &offset));
    /* the offset should be set to 8 */
    EXPECT_EQ(8U, offset);

    /* We need to do a little surgery for this test vector to work.  This is a
     * known-good CTR mode test vector, but the RFC we are using works
     * differently than how we use CTR mode.  We use a 64-bit nonce and a 64-bit
     * counter.  So, we need to update the current counter to match the above
     * counter.
     */
    memcpy(priv->ctr, COUNT_BLOCK, sizeof(COUNT_BLOCK));
    /* start encryption creates the first 16 bytes of the stream.  We need to
     * redo this with the correct IV. */
    AES_encrypt(priv->ctr, priv->stream, &priv->key);

    offset = 0;

    /* decrypt the ciphertext. */
    ASSERT_EQ(0,
        vccrypt_stream_decrypt(
            &ctx, output + 8, 32, poutput, &offset));
    /* the offset should be set to 16. */
    EXPECT_EQ(32U, offset);
    /* the next 32 bytes of output should correspond to our ciphertext. */
    for (int i = 0; i < 32; ++i)
    {
        EXPECT_EQ(PLAINTEXT[i], poutput[i]);
    }

    /* tear down this instance. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&ctx);
}

/**
 * We should be able to initialize, start, and encrypt using a FIPS compatible
 * stream cipher. TEST from RFC-3686 (Test Case #9).
 */
TEST_F(aes_ctr_test, aes_256_ctr_fips_03)
{
    vccrypt_stream_context_t ctx;
    vccrypt_buffer_t key;

    const uint8_t KEY[32] = {
        0xff, 0x7a, 0x61, 0x7c, 0xe6, 0x91, 0x48, 0xe4,
        0xf1, 0x72, 0x6e, 0x2f, 0x43, 0x58, 0x1d, 0xe2,
        0xaa, 0x62, 0xd9, 0xf8, 0x05, 0x53, 0x2e, 0xdf,
        0xf1, 0xee, 0xd6, 0x87, 0xfb, 0x54, 0x15, 0x3d
    };
    const uint8_t COUNT_BLOCK[16] = {
        0x00, 0x1c, 0xc5, 0xb7, 0x51, 0xa5, 0x1d, 0x70,
        0xa1, 0xc1, 0x11, 0x48, 0x00, 0x00, 0x00, 0x01
    };
    const uint8_t PLAINTEXT[36] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23
    };
    const uint8_t CIPHERTEXT[36] = {
        0xeb, 0x6c, 0x52, 0x82, 0x1d, 0x0b, 0xbb, 0xf7,
        0xce, 0x75, 0x94, 0x46, 0x2a, 0xca, 0x4f, 0xaa,
        0xb4, 0x07, 0xdf, 0x86, 0x65, 0x69, 0xfd, 0x07,
        0xf4, 0x8c, 0xc0, 0xb5, 0x83, 0xd6, 0x07, 0x1f,
        0x1e, 0xc0, 0xe6, 0xb8
    };

    uint64_t DUMMY_IV = mmhtonll(0x0102030405060708UL);
    uint8_t output[44];
    uint8_t poutput[36];
    size_t offset = 99;

    /* write junk to the output buffer */
    memset(output, 0xFC, sizeof(output));

    /* create a buffer for the key data. */
    ASSERT_EQ(0, vccrypt_buffer_init(&key, &alloc_opts, sizeof(KEY)));
    /* read the key into the buffer. */
    ASSERT_EQ(0, vccrypt_buffer_read_data(&key, KEY, sizeof(KEY)));

    /* create a new stream cipher with the given key. */
    ASSERT_EQ(0, vccrypt_stream_init(&fips_options, &ctx, &key));

    /* start encryption using a dummy IV. */
    ASSERT_EQ(0,
        vccrypt_stream_start_encryption(
            &ctx, &DUMMY_IV, sizeof(DUMMY_IV), output, &offset));
    /* the offset should be set to 8. */
    EXPECT_EQ(8U, offset);
    /* the first 8 bytes of output should be set to the value of DUMMY_IV */
    EXPECT_EQ(0x01U, output[0]);
    EXPECT_EQ(0x02U, output[1]);
    EXPECT_EQ(0x03U, output[2]);
    EXPECT_EQ(0x04U, output[3]);
    EXPECT_EQ(0x05U, output[4]);
    EXPECT_EQ(0x06U, output[5]);
    EXPECT_EQ(0x07U, output[6]);
    EXPECT_EQ(0x08U, output[7]);

    /* We need to do a little surgery for this test vector to work.  This is a
     * known-good CTR mode test vector, but the RFC we are using works
     * differently than how we use CTR mode.  We use a 64-bit nonce and a 64-bit
     * counter.  So, we need to update the current counter to match the above
     * counter.
     */
    aes_ctr_context_data_t* priv = (aes_ctr_context_data_t*)ctx.stream_state;
    ASSERT_NE(nullptr, priv);
    memcpy(priv->ctr, COUNT_BLOCK, sizeof(COUNT_BLOCK));
    /* start encryption creates the first 16 bytes of the stream.  We need to
     * redo this with the correct IV. */
    AES_encrypt(priv->ctr, priv->stream, &priv->key);

    /* encrypt the plaintext. */
    ASSERT_EQ(0,
        vccrypt_stream_encrypt(
            &ctx, PLAINTEXT, sizeof(PLAINTEXT), output, &offset));
    /* the offset should be set to 44. */
    EXPECT_EQ(44U, offset);
    /* the next 36 bytes of output should correspond to our ciphertext. */
    for (int i = 0; i < 36; ++i)
    {
        EXPECT_EQ(CIPHERTEXT[i], output[i + 8]);
    }

    /* start decryption using the dummy IV. */
    ASSERT_EQ(0,
        vccrypt_stream_start_decryption(
            &ctx, output, &offset));
    /* the offset should be set to 8 */
    EXPECT_EQ(8U, offset);

    /* We need to do a little surgery for this test vector to work.  This is a
     * known-good CTR mode test vector, but the RFC we are using works
     * differently than how we use CTR mode.  We use a 64-bit nonce and a 64-bit
     * counter.  So, we need to update the current counter to match the above
     * counter.
     */
    memcpy(priv->ctr, COUNT_BLOCK, sizeof(COUNT_BLOCK));
    /* start encryption creates the first 16 bytes of the stream.  We need to
     * redo this with the correct IV. */
    AES_encrypt(priv->ctr, priv->stream, &priv->key);

    offset = 0;

    /* decrypt the ciphertext. */
    ASSERT_EQ(0,
        vccrypt_stream_decrypt(
            &ctx, output + 8, 36, poutput, &offset));
    /* the offset should be set to 16. */
    EXPECT_EQ(36U, offset);
    /* the next 16 bytes of output should correspond to our ciphertext. */
    for (int i = 0; i < 36; ++i)
    {
        EXPECT_EQ(PLAINTEXT[i], poutput[i]);
    }

    /* tear down this instance. */
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&ctx);
}
#endif
