/**
 * \file test_aes_cbc.cpp
 *
 * Unit tests for AES CBC Mode.
 *
 * \copyright 2018-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <string.h>
#include <vccrypt/block_cipher.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

class aes_cbc_test {
public:
    void setUp()
    {
        /* register all AES block ciphers. */
        vccrypt_block_register_AES_256_CBC_FIPS();
        vccrypt_block_register_AES_256_2X_CBC();
        vccrypt_block_register_AES_256_3X_CBC();
        vccrypt_block_register_AES_256_4X_CBC();

        /* set up allocator */
        malloc_allocator_options_init(&alloc_opts);

        /* set up options for each variant. */
        fips_options_init_result =
            vccrypt_block_options_init(
                &fips_options, &alloc_opts,
                VCCRYPT_BLOCK_ALGORITHM_AES_256_CBC_FIPS);
        x2_options_init_result =
            vccrypt_block_options_init(
                &x2_options, &alloc_opts,
                VCCRYPT_BLOCK_ALGORITHM_AES_256_2X_CBC);
        x3_options_init_result =
            vccrypt_block_options_init(
                &x3_options, &alloc_opts,
                VCCRYPT_BLOCK_ALGORITHM_AES_256_3X_CBC);
        x4_options_init_result =
            vccrypt_block_options_init(
                &x4_options, &alloc_opts,
                VCCRYPT_BLOCK_ALGORITHM_AES_256_4X_CBC);
    }

    void tearDown()
    {
        /* tear down options for each variant. */
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
    vccrypt_block_options_t fips_options;
    vccrypt_block_options_t x2_options;
    vccrypt_block_options_t x3_options;
    vccrypt_block_options_t x4_options;

    int fips_options_init_result;
    int x2_options_init_result;
    int x3_options_init_result;
    int x4_options_init_result;
};

TEST_SUITE(aes_cbc_test);

#define BEGIN_TEST_F(name) \
TEST(name) \
{ \
    aes_cbc_test fixture; \
    fixture.setUp();

#define END_TEST_F() \
    fixture.tearDown(); \
}

/**
 * We should be able to create an options structure for each of the supported
 * CBC mode ciphers.
 */
BEGIN_TEST_F(register_options)
    /* Test FIPS AES-256-CBC options init. */
    TEST_ASSERT(0 == fixture.fips_options_init_result);
    TEST_EXPECT(nullptr != fixture.fips_options.hdr.dispose);
    TEST_EXPECT(&fixture.alloc_opts == fixture.fips_options.alloc_opts);
    TEST_EXPECT(32U == fixture.fips_options.key_size);
    TEST_EXPECT(16U == fixture.fips_options.IV_size);
    TEST_EXPECT(UINT64_MAX == fixture.fips_options.maximum_message_size);
    TEST_EXPECT(nullptr != fixture.fips_options.vccrypt_block_alg_init);
    TEST_EXPECT(nullptr != fixture.fips_options.vccrypt_block_alg_encrypt);
    TEST_EXPECT(nullptr != fixture.fips_options.vccrypt_block_alg_decrypt);

    /* Test AES-256-2X-CBC options init. */
    TEST_ASSERT(0 == fixture.x2_options_init_result);
    TEST_EXPECT(nullptr != fixture.x2_options.hdr.dispose);
    TEST_EXPECT(&fixture.alloc_opts == fixture.x2_options.alloc_opts);
    TEST_EXPECT(32U == fixture.x2_options.key_size);
    TEST_EXPECT(16U == fixture.x2_options.IV_size);
    TEST_EXPECT(UINT64_MAX == fixture.x2_options.maximum_message_size);
    TEST_EXPECT(nullptr != fixture.x2_options.vccrypt_block_alg_init);
    TEST_EXPECT(nullptr != fixture.x2_options.vccrypt_block_alg_encrypt);
    TEST_EXPECT(nullptr != fixture.x2_options.vccrypt_block_alg_decrypt);

    /* Test AES-256-3X-CBC options init. */
    TEST_ASSERT(0 == fixture.x3_options_init_result);
    TEST_EXPECT(nullptr != fixture.x3_options.hdr.dispose);
    TEST_EXPECT(&fixture.alloc_opts == fixture.x3_options.alloc_opts);
    TEST_EXPECT(32U == fixture.x3_options.key_size);
    TEST_EXPECT(16U == fixture.x3_options.IV_size);
    TEST_EXPECT(UINT64_MAX == fixture.x3_options.maximum_message_size);
    TEST_EXPECT(nullptr != fixture.x3_options.vccrypt_block_alg_init);
    TEST_EXPECT(nullptr != fixture.x3_options.vccrypt_block_alg_encrypt);
    TEST_EXPECT(nullptr != fixture.x3_options.vccrypt_block_alg_decrypt);

    /* Test AES-256-4X-CBC options init. */
    TEST_ASSERT(0 == fixture.x4_options_init_result);
    TEST_EXPECT(nullptr != fixture.x4_options.hdr.dispose);
    TEST_EXPECT(&fixture.alloc_opts == fixture.x4_options.alloc_opts);
    TEST_EXPECT(32U == fixture.x4_options.key_size);
    TEST_EXPECT(16U == fixture.x4_options.IV_size);
    TEST_EXPECT(UINT64_MAX == fixture.x4_options.maximum_message_size);
    TEST_EXPECT(nullptr != fixture.x4_options.vccrypt_block_alg_init);
    TEST_EXPECT(nullptr != fixture.x4_options.vccrypt_block_alg_encrypt);
    TEST_EXPECT(nullptr != fixture.x4_options.vccrypt_block_alg_decrypt);
END_TEST_F()

/**
 * We should be able to initialize, encrypt, and decrypt using a FIPS compatible
 * block cipher.  TEST from FIPS-800-38a (F.2.5).
 */
BEGIN_TEST_F(aes_256_cbc_fips_f25)
    vccrypt_block_context_t ctx;
    vccrypt_buffer_t key;

    const uint8_t KEY[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    const uint8_t IV[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const uint8_t PLAINTEXT[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };
    const uint8_t CIPHERTEXT[64] = {
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
        0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
        0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
        0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
        0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
        0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
        0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc,
        0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
    };
    uint8_t output[64];
    uint8_t poutput[64];

    /* write junk to the output buffers */
    memset(output, 0xFC, sizeof(output));
    memset(poutput, 0xFC, sizeof(poutput));

    /* create a buffer for the key data. */
    TEST_ASSERT(
        0 == vccrypt_buffer_init(&key, &fixture.alloc_opts, sizeof(KEY)));

    /* read the key into the buffer. */
    TEST_ASSERT(0 == vccrypt_buffer_read_data(&key, KEY, sizeof(KEY)));

    /* create a new block cipher with the given key. */
    TEST_ASSERT(
        0 == vccrypt_block_init(&fixture.fips_options, &ctx, &key, true));

    /* encrypt each plaintext block, writing to output. */
    TEST_ASSERT(0 == vccrypt_block_encrypt(&ctx, IV, PLAINTEXT, output));
    TEST_ASSERT(
        0 == vccrypt_block_encrypt(&ctx, output, PLAINTEXT + 16, output + 16));
    TEST_ASSERT(
        0
            == vccrypt_block_encrypt(
                    &ctx, output + 16, PLAINTEXT + 32, output + 32));
    TEST_ASSERT(
        0
            == vccrypt_block_encrypt(
                    &ctx, output + 32, PLAINTEXT + 48, output + 48));

    /* the encrypted data should match our ciphertext */
    TEST_ASSERT(0 == memcmp(output, CIPHERTEXT, sizeof(output)));

    /* clean up encryption context */
    dispose((disposable_t*)&ctx);

    /* create a new block cipher with the given key. */
    TEST_ASSERT(
        0 == vccrypt_block_init(&fixture.fips_options, &ctx, &key, false));

    /* decrypt each ciphertext block, writing it to poutput. */
    TEST_ASSERT(0 == vccrypt_block_decrypt(&ctx, IV, CIPHERTEXT, poutput));
    TEST_ASSERT(
        0
            == vccrypt_block_decrypt(
                    &ctx, CIPHERTEXT, CIPHERTEXT + 16, poutput + 16));
    TEST_ASSERT(
        0
            == vccrypt_block_decrypt(
                    &ctx, CIPHERTEXT + 16, CIPHERTEXT + 32, poutput + 32));
    TEST_ASSERT(
        0
            == vccrypt_block_decrypt(
                    &ctx, CIPHERTEXT + 32, CIPHERTEXT + 48, poutput + 48));

    /* the decrypted data should match our plaintext */
    TEST_ASSERT(0 == memcmp(poutput, PLAINTEXT, sizeof(poutput)));

    dispose((disposable_t*)&ctx);
    dispose((disposable_t*)&key);
END_TEST_F()
