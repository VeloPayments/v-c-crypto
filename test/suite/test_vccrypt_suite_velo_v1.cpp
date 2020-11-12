/**
 * \file test_vccrypt_suite_velo_v1.cpp
 *
 * Unit tests for the Velo V1 crypto suite.
 *
 * \copyright 2017-2020 Velo-Payments, Inc.  All rights reserved.
 */

#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include <vccrypt/suite.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

static uint64_t mmhtonll(uint64_t n)
{
    return ((((0xFF00000000000000 & n) >> 56) << 0) | (((0x00FF000000000000 & n) >> 48) << 8) | (((0x0000FF0000000000 & n) >> 40) << 16) | (((0x000000FF00000000 & n) >> 32) << 24) | (((0x00000000FF000000 & n) >> 24) << 32) | (((0x0000000000FF0000 & n) >> 16) << 40) | (((0x000000000000FF00 & n) >> 8) << 48) | (((0x00000000000000FF & n) >> 0) << 56));
}


class vccrypt_suite_velo_v1 : public ::testing::Test {
protected:
    void SetUp() override
    {
        vccrypt_suite_register_velo_v1();

        malloc_allocator_options_init(&alloc_opts);

        suite_init_result =
            vccrypt_suite_options_init(&options, &alloc_opts,
                VCCRYPT_SUITE_VELO_V1);
    }

    void TearDown() override
    {
        if (suite_init_result == 0)
        {
            dispose((disposable_t*)&options);
        }

        dispose((disposable_t*)&alloc_opts);
    }

    int suite_init_result;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t options;
};

/**
 * Initialization of the Velo V1 crypto suite should succeed.
 */
TEST_F(vccrypt_suite_velo_v1, init)
{
    /* verify that the suite was properly initialized. */
    ASSERT_EQ(0, suite_init_result);
}

/**
 * Verify that the suite ID is set.
 */
TEST_F(vccrypt_suite_velo_v1, suite_id)
{
    /* verify that the suite was properly initialized. */
    ASSERT_EQ(0, suite_init_result);

    ASSERT_EQ(VCCRYPT_SUITE_VELO_V1, options.suite_id);
}

/**
 * Verify that the hash algorithm is SHA-512 by running an example test vector.
 */
TEST_F(vccrypt_suite_velo_v1, hash_sha512)
{
    const char INPUT[] =
        "\x21";
    const char EXPECTED_HASH[] =
        "\x38\x31\xa6\xa6\x15\x5e\x50\x9d\xee\x59\xa7\xf4\x51\xeb\x35\x32"
        "\x4d\x8f\x8f\x2d\xf6\xe3\x70\x88\x94\x74\x0f\x98\xfd\xee\x23\x88"
        "\x9f\x4d\xe5\xad\xb0\xc5\x01\x0d\xfb\x55\x5c\xda\x77\xc8\xab\x5d"
        "\xc9\x02\x09\x4c\x52\xde\x32\x78\xf3\x5a\x75\xeb\xc2\x5f\x09\x3a";
    vccrypt_hash_context_t hash_ctx;
    vccrypt_buffer_t md;

    /* verify that the suite was properly initialized. */
    ASSERT_EQ(0, suite_init_result);

    /* test that we can build a hash buffer using the suite buffer routine */
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_hash(&options, &md));
    ASSERT_EQ(64U, md.size);

    /* test that we can initialize a hash context using the suite */
    ASSERT_EQ(0,
        vccrypt_suite_hash_init(&options, &hash_ctx));

    /* digest the message data */
    ASSERT_EQ(0,
        vccrypt_hash_digest(
            &hash_ctx, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    /* finalize the hash */
    ASSERT_EQ(0,
        vccrypt_hash_finalize(&hash_ctx, &md));

    /* the hash should match the test vector */
    ASSERT_EQ(0, memcmp(md.data, EXPECTED_HASH, 64));

    /* clean up */
    dispose((disposable_t*)&hash_ctx);
    dispose((disposable_t*)&md);
}

/**
 * Verify that the prng seems sane.
 */
TEST_F(vccrypt_suite_velo_v1, prng)
{
    uint8_t zero_bytes[32] = { 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0 };

    vccrypt_prng_context_t prng;
    vccrypt_buffer_t buffer;

    /* verify that the suite was properly initialized. */
    ASSERT_EQ(0, suite_init_result);

    //instantiate a prng from the suite
    ASSERT_EQ(0,
        vccrypt_suite_prng_init(
            &options, &prng));

    //buffer creation should succeed
    ASSERT_EQ(0,
        vccrypt_buffer_init(&buffer, &alloc_opts, 32));

    //PRECONDITION: set the buffer to all zeroes to cause the assertion below to
    //fail if the read does nothing
    memset(buffer.data, 0, 32);

    //prng read should succeed
    ASSERT_EQ(0,
        vccrypt_prng_read(&prng, &buffer, 32));

    //the data read should be random.  There's no good way to test for
    //randomness, so let's at least ensure that something was written, and it's
    //highly improbable that all zeros would have been written
    ASSERT_NE(0,
        memcmp(buffer.data, zero_bytes, 32));

    //clean up
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&prng);
}

/**
 * Test that we can generate a random keypair using the suite, and sign / verify
 * a message.
 */
TEST_F(vccrypt_suite_velo_v1, keygen_sign)
{
    const uint8_t message[] = "foo suite bar baz";
    vccrypt_digital_signature_context_t context;

    /* verify that the suite was properly initialized. */
    ASSERT_EQ(0, suite_init_result);

    //create a buffer for the private key
    vccrypt_buffer_t priv;
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_signature_private_key(&options, &priv));
    ASSERT_EQ(64U, priv.size);

    //create a buffer for the public key
    vccrypt_buffer_t pub;
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_signature_public_key(&options, &pub));
    ASSERT_EQ(32U, pub.size);

    //create a buffer for the signature
    vccrypt_buffer_t signature;
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_signature(&options, &signature));
    ASSERT_EQ(64U, signature.size);

    //create the digital signature context
    ASSERT_EQ(0, vccrypt_suite_digital_signature_init(&options, &context));

    //generate a keypair
    ASSERT_EQ(0,
        vccrypt_digital_signature_keypair_create(&context, &priv, &pub));

    //sign the message
    ASSERT_EQ(0,
        vccrypt_digital_signature_sign(
            &context, &signature, &priv,
            message, sizeof(message)));

    //verify the signature
    ASSERT_EQ(0,
        vccrypt_digital_signature_verify(
            &context, &signature, &pub,
            message, sizeof(message)));

    //dispose the digital signature context
    dispose((disposable_t*)&context);

    //dispose all buffers
    dispose((disposable_t*)&priv);
    dispose((disposable_t*)&pub);
    dispose((disposable_t*)&signature);
}

/**
 * Test that we can use HMAC-SHA-512-256 from the crypto suite.
 */
TEST_F(vccrypt_suite_velo_v1, hmac_sha_512_256)
{
    const uint8_t KEY[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19
    };
    const uint8_t DATA[] = {
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd
    };
    const uint8_t EXPECTED_HMAC[] = {
        0x36, 0xd6, 0x0c, 0x8a, 0xa1, 0xd0, 0xbe, 0x85,
        0x6e, 0x10, 0x80, 0x4c, 0xf8, 0x36, 0xe8, 0x21,
        0xe8, 0x73, 0x3c, 0xba, 0xfe, 0xae, 0x87, 0x63,
        0x05, 0x89, 0xfd, 0x0b, 0x9b, 0x0a, 0x2f, 0x4c
    };

    /* verify that the suite was properly initialized. */
    ASSERT_EQ(0, suite_init_result);

    //create a buffer sized for the key
    vccrypt_buffer_t key;
    ASSERT_EQ(0, vccrypt_buffer_init(&key, &alloc_opts, sizeof(KEY)));
    memcpy(key.data, KEY, sizeof(KEY));

    //initialize MAC
    vccrypt_mac_context_t mac;
    ASSERT_EQ(0, vccrypt_suite_mac_short_init(&options, &mac, &key));

    //digest input
    ASSERT_EQ(0, vccrypt_mac_digest(&mac, DATA, sizeof(DATA)));

    //create output buffer
    vccrypt_buffer_t outbuf;
    ASSERT_EQ(0, vccrypt_suite_buffer_init_for_mac_authentication_code(&options, &outbuf, true));
    ASSERT_EQ(sizeof(EXPECTED_HMAC), outbuf.size);

    //finalize hmac
    ASSERT_EQ(0, vccrypt_mac_finalize(&mac, &outbuf));

    //the HMAC output should match our expected HMAC
    ASSERT_EQ(0, memcmp(outbuf.data, EXPECTED_HMAC, sizeof(EXPECTED_HMAC)));

    //clean up
    dispose((disposable_t*)&outbuf);
    dispose((disposable_t*)&mac);
    dispose((disposable_t*)&key);
}

/**
 * Test that we can use HMAC-SHA-512 from the crypto suite.
 */
TEST_F(vccrypt_suite_velo_v1, hmac_sha_512)
{
    const uint8_t KEY[] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
    };
    const uint8_t DATA[] = {
        'a', 'b', 'c'
    };
    const uint8_t EXPECTED_HMAC[] = {
        0x06, 0xba, 0x03, 0xa4, 0x4e, 0xf9, 0x1b, 0xf5,
        0xa4, 0xc7, 0xaf, 0x26, 0xd9, 0xe7, 0xc7, 0xd8,
        0xd8, 0x0b, 0x95, 0xcc, 0x8d, 0xa3, 0xeb, 0x01,
        0xb2, 0x31, 0xb9, 0x93, 0x22, 0x03, 0xe7, 0x1c,
        0x2a, 0xad, 0xb1, 0xf4, 0xfd, 0x2d, 0x85, 0x51,
        0xd7, 0x9e, 0x01, 0x97, 0x27, 0xfb, 0x32, 0xf0,
        0x6b, 0x59, 0x70, 0x19, 0x0a, 0x56, 0xbf, 0x6f,
        0xab, 0xc9, 0x72, 0x39, 0xf5, 0xdc, 0xaa, 0x61
    };

    /* verify that the suite was properly initialized. */
    ASSERT_EQ(0, suite_init_result);

    //create a buffer sized for the key
    vccrypt_buffer_t key;
    ASSERT_EQ(
        0,
        vccrypt_suite_buffer_init_for_mac_private_key(&options, &key, false));
    ASSERT_EQ(sizeof(KEY), key.size);
    memcpy(key.data, KEY, sizeof(KEY));

    //initialize MAC
    vccrypt_mac_context_t mac;
    ASSERT_EQ(0, vccrypt_suite_mac_init(&options, &mac, &key));

    //digest input
    ASSERT_EQ(0, vccrypt_mac_digest(&mac, DATA, sizeof(DATA)));

    //create output buffer
    vccrypt_buffer_t outbuf;
    ASSERT_EQ(0, vccrypt_suite_buffer_init_for_mac_authentication_code(&options, &outbuf, false));
    ASSERT_EQ(sizeof(EXPECTED_HMAC), outbuf.size);

    //finalize hmac
    ASSERT_EQ(0, vccrypt_mac_finalize(&mac, &outbuf));

    //the HMAC output should match our expected HMAC
    ASSERT_EQ(0, memcmp(outbuf.data, EXPECTED_HMAC, sizeof(EXPECTED_HMAC)));

    //clean up
    dispose((disposable_t*)&outbuf);
    dispose((disposable_t*)&mac);
    dispose((disposable_t*)&key);
}

/**
 * Test that we can use Curve25519-Auth-HMAC-SHA-512 from the crypto suite.
 */
TEST_F(vccrypt_suite_velo_v1, curve25519_auth)
{
    vccrypt_key_agreement_context_t key;

    /* verify that the suite was properly initialized. */
    ASSERT_EQ(0, suite_init_result);

    //we should be able to create an algorithm instance
    ASSERT_EQ(0, vccrypt_suite_auth_key_agreement_init(&options, &key));

    //create buffers for public and private keys
    vccrypt_buffer_t alice_private, alice_public, bob_private, bob_public;
    vccrypt_buffer_t ab_shared, ba_shared;
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_auth_key_agreement_private_key(
            &options, &alice_private));
    ASSERT_EQ(32U, alice_private.size);
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_auth_key_agreement_public_key(
            &options, &alice_public));
    ASSERT_EQ(32U, alice_public.size);
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_auth_key_agreement_private_key(
            &options, &bob_private));
    ASSERT_EQ(32U, bob_private.size);
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_auth_key_agreement_public_key(
            &options, &bob_public));
    ASSERT_EQ(32U, bob_public.size);
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_auth_key_agreement_shared_secret(
            &options, &ab_shared));
    ASSERT_EQ(64U, ab_shared.size);
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_auth_key_agreement_shared_secret(
            &options, &ba_shared));
    ASSERT_EQ(64U, ba_shared.size);

    //generate alice's keypair
    ASSERT_EQ(0,
        vccrypt_key_agreement_keypair_create(
            &key, &alice_private, &alice_public));

    //generate bob's keypair
    ASSERT_EQ(0,
        vccrypt_key_agreement_keypair_create(
            &key, &bob_private, &bob_public));

    //generate the alice-bob shared secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_long_term_secret_create(
            &key, &alice_private, &bob_public, &ab_shared));

    //generate the bob-alice shared secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_long_term_secret_create(
            &key, &bob_private, &alice_public, &ba_shared));

    //the two shared secrets should match
    ASSERT_EQ(0, memcmp(ab_shared.data, ba_shared.data, 64));

    //create a prng instance
    vccrypt_prng_context_t prng;
    ASSERT_EQ(0, vccrypt_suite_prng_init(&options, &prng));

    //create a buffer for alice's nonce
    vccrypt_buffer_t alice_nonce;
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_auth_key_agreement_nonce(
            &options, &alice_nonce));
    ASSERT_EQ(64U, alice_nonce.size);

    //read random bytes for alice's nonce
    ASSERT_EQ(0,
        vccrypt_prng_read(&prng, &alice_nonce, alice_nonce.size));

    //create a buffer for bob's nonce
    vccrypt_buffer_t bob_nonce;
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_auth_key_agreement_nonce(
            &options, &bob_nonce));
    ASSERT_EQ(64U, bob_nonce.size);

    //read random bytes for bob's nonce
    ASSERT_EQ(0,
        vccrypt_prng_read(&prng, &bob_nonce, bob_nonce.size));

    //generate the alice-bob short-term secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_short_term_secret_create(
            &key, &alice_private, &bob_public, &alice_nonce, &bob_nonce,
            &ab_shared));

    //generate the bob-alice short-term secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_short_term_secret_create(
            &key, &bob_private, &alice_public, &alice_nonce, &bob_nonce,
            &ba_shared));

    //the two shared secrets should match
    ASSERT_EQ(0, memcmp(ab_shared.data, ba_shared.data, 64));

    dispose((disposable_t*)&alice_nonce);
    dispose((disposable_t*)&bob_nonce);
    dispose((disposable_t*)&prng);
    dispose((disposable_t*)&alice_private);
    dispose((disposable_t*)&alice_public);
    dispose((disposable_t*)&bob_private);
    dispose((disposable_t*)&bob_public);
    dispose((disposable_t*)&ab_shared);
    dispose((disposable_t*)&ba_shared);
    dispose((disposable_t*)&key);
}

/**
 * Test that we can derive a cryptographic key from a password.
 *
 * TODO: once we have a test vector for SHA-512/256, verify expected
 * value.  For now we are testing the algorithm more comprehensively
 * using SHA-512 elsewhere.
 *
 */
TEST_F(vccrypt_suite_velo_v1, key_derivation)
{
    vccrypt_key_derivation_context_t ctx;

    /* verify that the suite was properly initialized. */
    ASSERT_EQ(0, suite_init_result);

    // ensure we have the right HMAC algorithm
    EXPECT_EQ((unsigned int)VCCRYPT_MAC_ALGORITHM_SHA_2_512_256_HMAC,
        options.key_derivation_opts.hmac_algorithm);
    EXPECT_EQ(32u, options.key_derivation_opts.hmac_digest_length);


    // we should be able to create an algorithm instance
    ASSERT_EQ(0, vccrypt_suite_key_derivation_init(&ctx, &options));


    // as a starting point we should be able to derive a key from a
    // password and a salt
    const char* password = "password123";
    vccrypt_buffer_t password_buffer;
    ASSERT_EQ(0, vccrypt_buffer_init(&password_buffer, &alloc_opts, strlen(password)));
    memcpy(password_buffer.data, password, strlen(password));

    vccrypt_buffer_t salt_buffer;
    ASSERT_EQ(0, vccrypt_buffer_init(&salt_buffer, &alloc_opts, 10));
    uint8_t salt[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
    memcpy(salt_buffer.data, &salt[0], sizeof(salt));

    vccrypt_buffer_t dk_buffer;
    ASSERT_EQ(0, vccrypt_buffer_init(&dk_buffer, &alloc_opts, 10));
    ASSERT_EQ(10U, dk_buffer.size);

    ASSERT_EQ(0,
        vccrypt_key_derivation_derive_key(&dk_buffer,
            &ctx, &password_buffer, &salt_buffer,
            10));  // just a few rounds for this test.


    // verify derived key is not all 0
    uint8_t test_block[dk_buffer.size];
    memset(test_block, 0, sizeof(test_block));

    EXPECT_NE(0, memcmp(dk_buffer.data, test_block, dk_buffer.size));


    dispose((disposable_t*)&dk_buffer);
    dispose((disposable_t*)&salt_buffer);
    dispose((disposable_t*)&password_buffer);
    dispose((disposable_t*)&ctx);
}


/**
 * Test that we can use Curve25519-Cipher-HMAC-SHA-512 from the crypto suite.
 */
TEST_F(vccrypt_suite_velo_v1, curve25519_cipher)
{
    vccrypt_key_agreement_context_t key;

    /* verify that the suite was properly initialized. */
    ASSERT_EQ(0, suite_init_result);

    //we should be able to create an algorithm instance
    ASSERT_EQ(0, vccrypt_suite_cipher_key_agreement_init(&options, &key));

    //create buffers for public and private keys
    vccrypt_buffer_t alice_private, alice_public, bob_private, bob_public;
    vccrypt_buffer_t ab_shared, ba_shared;
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_private_key(
            &options, &alice_private));
    ASSERT_EQ(32U, alice_private.size);
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
            &options, &alice_public));
    ASSERT_EQ(32U, alice_public.size);
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_private_key(
            &options, &bob_private));
    ASSERT_EQ(32U, bob_private.size);
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
            &options, &bob_public));
    ASSERT_EQ(32U, bob_public.size);
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
            &options, &ab_shared));
    ASSERT_EQ(32U, ab_shared.size);
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
            &options, &ba_shared));
    ASSERT_EQ(32U, ba_shared.size);

    //generate alice's keypair
    ASSERT_EQ(0,
        vccrypt_key_agreement_keypair_create(
            &key, &alice_private, &alice_public));

    //generate bob's keypair
    ASSERT_EQ(0,
        vccrypt_key_agreement_keypair_create(
            &key, &bob_private, &bob_public));

    //generate the alice-bob shared secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_long_term_secret_create(
            &key, &alice_private, &bob_public, &ab_shared));

    //generate the bob-alice shared secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_long_term_secret_create(
            &key, &bob_private, &alice_public, &ba_shared));

    //the two shared secrets should match
    ASSERT_EQ(0, memcmp(ab_shared.data, ba_shared.data, 32));

    //create a prng instance
    vccrypt_prng_context_t prng;
    ASSERT_EQ(0, vccrypt_suite_prng_init(&options, &prng));

    //create a buffer for alice's nonce
    vccrypt_buffer_t alice_nonce;
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &options, &alice_nonce));
    ASSERT_EQ(32U, alice_nonce.size);

    //read random bytes for alice's nonce
    ASSERT_EQ(0,
        vccrypt_prng_read(&prng, &alice_nonce, alice_nonce.size));

    //create a buffer for bob's nonce
    vccrypt_buffer_t bob_nonce;
    ASSERT_EQ(0,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &options, &bob_nonce));
    ASSERT_EQ(32U, bob_nonce.size);

    //read random bytes for bob's nonce
    ASSERT_EQ(0,
        vccrypt_prng_read(&prng, &bob_nonce, bob_nonce.size));

    //generate the alice-bob short-term secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_short_term_secret_create(
            &key, &alice_private, &bob_public, &alice_nonce, &bob_nonce,
            &ab_shared));

    //generate the bob-alice short-term secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_short_term_secret_create(
            &key, &bob_private, &alice_public, &alice_nonce, &bob_nonce,
            &ba_shared));

    //the two shared secrets should match
    ASSERT_EQ(0, memcmp(ab_shared.data, ba_shared.data, 32));

    dispose((disposable_t*)&alice_nonce);
    dispose((disposable_t*)&bob_nonce);
    dispose((disposable_t*)&prng);
    dispose((disposable_t*)&alice_private);
    dispose((disposable_t*)&alice_public);
    dispose((disposable_t*)&bob_private);
    dispose((disposable_t*)&bob_public);
    dispose((disposable_t*)&ab_shared);
    dispose((disposable_t*)&ba_shared);
    dispose((disposable_t*)&key);
}

/**
 * Test that we can encrypt and decrypt using a block cipher from the
 * crypto suite.
 */
TEST_F(vccrypt_suite_velo_v1, block_cipher)
{
    vccrypt_block_context_t context;
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

    uint8_t output[64];
    uint8_t poutput[64];

    /* verify that the suite was properly initialized. */
    ASSERT_EQ(0, suite_init_result);

    // write junk to the output buffers
    memset(output, 0xFC, sizeof(output));
    memset(poutput, 0xFC, sizeof(poutput));

    // create a buffer for the key data
    ASSERT_EQ(0, vccrypt_buffer_init(&key, &alloc_opts, sizeof(KEY)));
    // read the key into the buffer.
    ASSERT_EQ(0, vccrypt_buffer_read_data(&key, KEY, sizeof(KEY)));

    // instantiate the algorithm instance from the suite to encrypt
    ASSERT_EQ(0, vccrypt_suite_block_init(&options, &context, &key, true));

    // encrypt each plaintext block, writing to output.
    ASSERT_EQ(0, vccrypt_block_encrypt(&context, IV, PLAINTEXT, output));
    ASSERT_EQ(0, vccrypt_block_encrypt(&context, output, PLAINTEXT + 16, output + 16));
    ASSERT_EQ(0, vccrypt_block_encrypt(&context, output + 16, PLAINTEXT + 32, output + 32));
    ASSERT_EQ(0, vccrypt_block_encrypt(&context, output + 32, PLAINTEXT + 48, output + 48));

    // clean up encryption context
    dispose((disposable_t*)&context);

    // the encrypted data should not match the plain text
    ASSERT_NE(0, memcmp(output, PLAINTEXT, sizeof(output)));

    // instantiate the algorithm instance from the suite to decrypt
    ASSERT_EQ(0, vccrypt_suite_block_init(&options, &context, &key, false));

    // decrypt each ciphertext block, writing it to poutput.
    ASSERT_EQ(0, vccrypt_block_decrypt(&context, IV, output, poutput));
    ASSERT_EQ(0, vccrypt_block_decrypt(&context, output, output + 16, poutput + 16));
    ASSERT_EQ(0, vccrypt_block_decrypt(&context, output + 16, output + 32, poutput + 32));
    ASSERT_EQ(0, vccrypt_block_decrypt(&context, output + 32, output + 48, poutput + 48));

    // the decrypted data should match our plaintext
    ASSERT_EQ(0, memcmp(poutput, PLAINTEXT, sizeof(poutput)));

    // cleanup
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&key);
}

/**
 * Test that we can encrypt and decrypt using a stream cipher from the
 * crypto suite.
 */
TEST_F(vccrypt_suite_velo_v1, stream_cipher)
{
    vccrypt_stream_context_t context;
    vccrypt_buffer_t key;

    const uint8_t KEY[32] = {
        0xf6, 0xd6, 0x6d, 0x6b, 0xd5, 0x2d, 0x59, 0xbb,
        0x07, 0x96, 0x36, 0x58, 0x79, 0xef, 0xf8, 0x86,
        0xc6, 0x6d, 0xd5, 0x1a, 0x5b, 0x6a, 0x99, 0x74,
        0x4b, 0x50, 0x59, 0x0c, 0x87, 0xa2, 0x38, 0x84
    };
    const uint8_t PLAINTEXT[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    /* verify that the suite was properly initialized. */
    ASSERT_EQ(0, suite_init_result);

    // create a buffer for the key data
    ASSERT_EQ(0, vccrypt_buffer_init(&key, &alloc_opts, sizeof(KEY)));
    // read the key into the buffer.
    ASSERT_EQ(0, vccrypt_buffer_read_data(&key, KEY, sizeof(KEY)));

    // instantiate the algorithm instance from the suite
    ASSERT_EQ(0, vccrypt_suite_stream_init(&options, &context, &key));


    uint64_t DUMMY_IV = mmhtonll(0x0102030405060708UL);
    uint8_t output[40];
    uint8_t poutput[32];
    size_t offset = 99;

    // write junk to the output buffer
    memset(output, 0xFC, sizeof(output));

    // start encryption using a dummy IV.
    ASSERT_EQ(0,
        vccrypt_stream_start_encryption(
            &context, &DUMMY_IV, sizeof(DUMMY_IV), output, &offset));

    // the offset should be set to 8.
    EXPECT_EQ(8U, offset);

    // the first 8 bytes of output should be set to the value of DUMMY_IV
    EXPECT_EQ(0x01U, output[0]);
    EXPECT_EQ(0x02U, output[1]);
    EXPECT_EQ(0x03U, output[2]);
    EXPECT_EQ(0x04U, output[3]);
    EXPECT_EQ(0x05U, output[4]);
    EXPECT_EQ(0x06U, output[5]);
    EXPECT_EQ(0x07U, output[6]);
    EXPECT_EQ(0x08U, output[7]);

    // encrypt the plaintext.
    ASSERT_EQ(0,
        vccrypt_stream_encrypt(
            &context, PLAINTEXT, sizeof(PLAINTEXT), output, &offset));

    // the offset should be set to 40.
    EXPECT_EQ(40U, offset);

    // we don't know what encryption algorithm was used, but we can ensure
    // the cipher text is not the same as the plain text.
    ASSERT_NE(0, memcmp(output + 8, PLAINTEXT, sizeof(PLAINTEXT)));

    // start decryption using the dummy IV.
    ASSERT_EQ(0,
        vccrypt_stream_start_decryption(
            &context, output, &offset));

    // the offset should be set to 8
    EXPECT_EQ(8U, offset);

    offset = 0;

    // decrypt the ciphertext.
    ASSERT_EQ(0,
        vccrypt_stream_decrypt(
            &context, output + 8, 32, poutput, &offset));

    // the output should correspond to our plaintext.
    ASSERT_EQ(0, memcmp(poutput, PLAINTEXT, sizeof(PLAINTEXT)));

    // cleanup
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&key);
}

/**
 * Test that we can create a vccrypt buffer for holding UUID bytes.
 */
TEST_F(vccrypt_suite_velo_v1, vccrypt_suite_buffer_init_for_uuid)
{
    vccrypt_buffer_t uuidbuffer;

    /* verify that the suite was properly initialized. */
    ASSERT_EQ(0, suite_init_result);

    /* clear the buffer. */
    memset(&uuidbuffer, 0, sizeof(uuidbuffer));

    /* we should be able to create the buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_uuid(&options, &uuidbuffer));

    /* the buffer size should be 16 bytes -- the size of a raw uuid. */
    EXPECT_EQ(16U, uuidbuffer.size);

    /* the data should not be NULL. */
    EXPECT_NE(nullptr, uuidbuffer.data);

    /* dispose of the buffer. */
    dispose((disposable_t*)&uuidbuffer);
}
