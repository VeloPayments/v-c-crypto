/**
 * \file test_aes_core.cpp
 *
 * Unit tests for aes_core.
 *
 * \copyright 2018 Velo-Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include "../../src/stream_cipher/aes/aes.h"

/**
 * Test that AES-256-ECB works as expected.
 */
TEST(aes_core_test, AES_256_ECB)
{
    const uint8_t key[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    const uint8_t plaintext[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    const uint8_t ciphertext[16] = {
        0xdc,
        0x95,
        0xc0,
        0x78,
        0xa2,
        0x40,
        0x89,
        0x89,
        0xad,
        0x48,
        0xa2,
        0x14,
        0x92,
        0x84,
        0x20,
        0x87,
    };

    uint8_t test_plaintext[16] = { 0 };
    uint8_t test_ciphertext[16] = { 0 };

    AES_KEY test_key;

    /* test encryption AES-256-ECB */
    ASSERT_EQ(0, AES_set_encrypt_key(key, 256, 1, &test_key));
    AES_encrypt(plaintext, test_ciphertext, &test_key);
    for (int i = 0; i < 16; ++i)
    {
        EXPECT_EQ(test_ciphertext[i], ciphertext[i]);
    }

    /* test decryption AES-256-ECB */
    ASSERT_EQ(0, AES_set_decrypt_key(key, 256, 1, &test_key));
    AES_decrypt(ciphertext, test_plaintext, &test_key);
    for (int i = 0; i < 16; ++i)
    {
        EXPECT_EQ(test_plaintext[i], plaintext[i]);
    }
}

/**
 * Test that AES-256X2-ECB works as expected.
 */
TEST(aes_core_test, AES_256X2_ECB)
{
    const uint8_t key[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    const uint8_t plaintext[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    const uint8_t ciphertext[16] = {
        0x19, 0x95, 0x17, 0x74, 0xcd, 0x04, 0x09, 0x72,
        0x91, 0x97, 0xe6, 0x02, 0x76, 0x21, 0xc6, 0xd4
    };

    uint8_t test_plaintext[16] = { 0 };
    uint8_t test_ciphertext[16] = { 0 };

    AES_KEY test_key;

    /* test encryption AES-256X2-ECB */
    ASSERT_EQ(0, AES_set_encrypt_key(key, 256, 2, &test_key));
    AES_encrypt(plaintext, test_ciphertext, &test_key);
    for (int i = 0; i < 16; ++i)
    {
        EXPECT_EQ(test_ciphertext[i], ciphertext[i]);
    }

    /* test decryption AES-256X2-ECB */
    ASSERT_EQ(0, AES_set_decrypt_key(key, 256, 2, &test_key));
    AES_decrypt(ciphertext, test_plaintext, &test_key);
    for (int i = 0; i < 16; ++i)
    {
        EXPECT_EQ(test_plaintext[i], plaintext[i]);
    }
}

/**
 * Test that AES-256X3-ECB works as expected.
 */
TEST(aes_core_test, AES_256X3_ECB)
{
    const uint8_t key[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    const uint8_t plaintext[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    const uint8_t ciphertext[16] = {
        0x9f,
        0x25,
        0xf0,
        0xc0,
        0x05,
        0x5f,
        0x73,
        0xb1,
        0xc2,
        0x95,
        0x65,
        0xab,
        0x7a,
        0x2d,
        0x35,
        0xfb,
    };

    uint8_t test_plaintext[16] = { 0 };
    uint8_t test_ciphertext[16] = { 0 };

    AES_KEY test_key;

    /* test encryption AES-256X3-ECB */
    ASSERT_EQ(0, AES_set_encrypt_key(key, 256, 3, &test_key));
    AES_encrypt(plaintext, test_ciphertext, &test_key);
    for (int i = 0; i < 16; ++i)
    {
        EXPECT_EQ(test_ciphertext[i], ciphertext[i]);
    }

    /* test decryption AES-256X3-ECB */
    ASSERT_EQ(0, AES_set_decrypt_key(key, 256, 3, &test_key));
    AES_decrypt(ciphertext, test_plaintext, &test_key);
    for (int i = 0; i < 16; ++i)
    {
        EXPECT_EQ(test_plaintext[i], plaintext[i]);
    }
}

/**
 * Test that AES-256X4-ECB works as expected.
 */
TEST(aes_core_test, AES_256X4_ECB)
{
    const uint8_t key[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    const uint8_t plaintext[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    const uint8_t ciphertext[16] = {
        0x1a,
        0x14,
        0x4d,
        0xd9,
        0x82,
        0x99,
        0xaf,
        0x5f,
        0x3e,
        0x3a,
        0xc8,
        0xc9,
        0xa6,
        0x8e,
        0xac,
        0x5d,
    };

    uint8_t test_plaintext[16] = { 0 };
    uint8_t test_ciphertext[16] = { 0 };

    AES_KEY test_key;

    /* test encryption AES-256X4-ECB */
    ASSERT_EQ(0, AES_set_encrypt_key(key, 256, 4, &test_key));
    AES_encrypt(plaintext, test_ciphertext, &test_key);
    for (int i = 0; i < 16; ++i)
    {
        EXPECT_EQ(test_ciphertext[i], ciphertext[i]);
    }

    /* test decryption AES-256X4-ECB */
    ASSERT_EQ(0, AES_set_decrypt_key(key, 256, 4, &test_key));
    AES_decrypt(ciphertext, test_plaintext, &test_key);
    for (int i = 0; i < 16; ++i)
    {
        EXPECT_EQ(test_plaintext[i], plaintext[i]);
    }
}
