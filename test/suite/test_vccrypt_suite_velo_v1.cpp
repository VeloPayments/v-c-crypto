/**
 * \file test_vccrypt_suite_velo_v1.cpp
 *
 * Unit tests for the Velo V1 crypto suite.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include <vccrypt/suite.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

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
    ASSERT_EQ(0, suite_init_result);
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
