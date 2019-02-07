/**
 * \file test_vccrypt_ed25519_ref.cpp
 *
 * Unit tests for the reference ed25519 implementation.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include <vccrypt/digital_signature.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

class vccrypt_ed25519_ref_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        //make sure our prng has been registered
        vccrypt_digital_signature_register_ed25519();
        //make sure ed25519 has been registered
        vccrypt_prng_register_source_operating_system();

        malloc_allocator_options_init(&alloc_opts);

        vccrypt_prng_options_init(
            &prng_opts, &alloc_opts, VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM);
    }

    void TearDown() override
    {
        dispose((disposable_t*)&prng_opts);
        dispose((disposable_t*)&alloc_opts);
    }

    allocator_options_t alloc_opts;
    vccrypt_prng_options_t prng_opts;
};

/**
 * We should be able to get ed25519 options if it has been registered.
 */
TEST_F(vccrypt_ed25519_ref_test, options_init)
{
    vccrypt_digital_signature_options_t options;

    //we should be able to initialize options for this algorithm
    ASSERT_EQ(0,
        vccrypt_digital_signature_options_init(
            &options, &alloc_opts, &prng_opts,
            VCCRYPT_DIGITAL_SIGNATURE_ALGORITHM_ED25519));

    dispose((disposable_t*)&options);
}

/**
 * We should be able to create an ed25519 instance.
 */
TEST_F(vccrypt_ed25519_ref_test, init)
{
    vccrypt_digital_signature_options_t options;
    vccrypt_digital_signature_context_t context;

    //we should be able to initialize options for this algorithm
    ASSERT_EQ(0,
        vccrypt_digital_signature_options_init(
            &options, &alloc_opts, &prng_opts,
            VCCRYPT_DIGITAL_SIGNATURE_ALGORITHM_ED25519));

    //we should be able to create an algorithm instance
    ASSERT_EQ(0, vccrypt_digital_signature_init(&options, &context));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
}

/**
 * Test the signature test vectors.
 */
TEST_F(vccrypt_ed25519_ref_test, simple_sign)
{
    vccrypt_digital_signature_options_t options;
    vccrypt_digital_signature_context_t context;

    //we should be able to initialize options for this algorithm
    ASSERT_EQ(0,
        vccrypt_digital_signature_options_init(
            &options, &alloc_opts, &prng_opts,
            VCCRYPT_DIGITAL_SIGNATURE_ALGORITHM_ED25519));

    char* test_signature_path = std::getenv("TEST_SIGNATURE_PATH");
    std::string sign_path;

    if (test_signature_path != nullptr)
    {
        sign_path = std::string(test_signature_path);
    }

    sign_path += "/test/digital_signature/sign.input";

    //read the signature input file
    ifstream in(sign_path);

    //this stream should be valid
    ASSERT_TRUE(in.good());

    //iterate through all test vectors
    string line, priv, pub, msg, signature;
    while (getline(in, line))
    {
        stringstream linein(line);

        //read the components for this test vector
        ASSERT_TRUE(getline(linein, priv, ':'));
        ASSERT_TRUE(getline(linein, pub, ':'));
        ASSERT_TRUE(getline(linein, msg, ':'));
        ASSERT_TRUE(getline(linein, signature, ':'));

        //the private key should be 128 digits long
        ASSERT_EQ(128U, priv.size());
        //the public key should be 64 digits long
        ASSERT_EQ(64U, pub.size());
        //the signature should be at least 128 digits long
        ASSERT_LE(128U, signature.size());

        //convert the private key to a buffer
        vccrypt_buffer_t priv_hex;
        ASSERT_EQ(0, vccrypt_buffer_init(&priv_hex, &alloc_opts, priv.size()));
        ASSERT_EQ(0,
            vccrypt_buffer_read_data(&priv_hex, priv.c_str(), priv.size()));

        //convert the private hex data to binary
        vccrypt_buffer_t priv_bytes;
        ASSERT_EQ(0, vccrypt_buffer_init(&priv_bytes, &alloc_opts, 64));
        ASSERT_EQ(0,
            vccrypt_buffer_read_hex(&priv_bytes, &priv_hex));

        //convert the public key to a buffer
        vccrypt_buffer_t pub_hex;
        ASSERT_EQ(0, vccrypt_buffer_init(&pub_hex, &alloc_opts, pub.size()));
        ASSERT_EQ(0,
            vccrypt_buffer_read_data(&pub_hex, pub.c_str(), pub.size()));

        //convert the public hex data to binary
        vccrypt_buffer_t pub_bytes;
        ASSERT_EQ(0, vccrypt_buffer_init(&pub_bytes, &alloc_opts, 32));
        ASSERT_EQ(0,
            vccrypt_buffer_read_hex(&pub_bytes, &pub_hex));

        //convert the message to a buffer
        vccrypt_buffer_t msg_hex;
        ASSERT_EQ(0, vccrypt_buffer_init(&msg_hex, &alloc_opts, msg.size()));
        ASSERT_EQ(0,
            vccrypt_buffer_read_data(&msg_hex, msg.c_str(), msg.size()));

        //convert the message hex data to binary
        vccrypt_buffer_t msg_bytes;
        ASSERT_EQ(0, vccrypt_buffer_init(&msg_bytes, &alloc_opts, msg.size() / 2));
        ASSERT_EQ(0,
            vccrypt_buffer_read_hex(&msg_bytes, &msg_hex));

        //convert the signature to a buffer
        vccrypt_buffer_t sign_hex;
        ASSERT_EQ(0, vccrypt_buffer_init(&sign_hex, &alloc_opts, signature.size()));
        ASSERT_EQ(0,
            vccrypt_buffer_read_data(
                &sign_hex, signature.c_str(), signature.size()));

        //convert the signature hex data to binary
        vccrypt_buffer_t sign_bytes;
        ASSERT_EQ(0, vccrypt_buffer_init(&sign_bytes, &alloc_opts, signature.size() / 2));
        ASSERT_EQ(0,
            vccrypt_buffer_read_hex(&sign_bytes, &sign_hex));

        //create a buffer to hold the generated signature
        vccrypt_buffer_t sign_buffer;
        ASSERT_EQ(0, vccrypt_buffer_init(&sign_buffer, &alloc_opts, 64));

        //create the digital signature context
        ASSERT_EQ(0, vccrypt_digital_signature_init(&options, &context));

        //sign the message
        ASSERT_EQ(0,
            vccrypt_digital_signature_sign(
                &context, &sign_buffer, &priv_bytes,
                (const uint8_t*)msg_bytes.data, msg_bytes.size));

        //verify that our generated signature matches the provided signature
        //NOTE: this is an UNSAFE WAY to compare signatures.  Used here only for
        //testing purposes.  Use a constant-time comparison in real code!
        ASSERT_EQ(0, memcmp(sign_buffer.data, sign_bytes.data, 64));

        //verify the signature
        ASSERT_EQ(0,
            vccrypt_digital_signature_verify(
                &context, &sign_bytes, &pub_bytes,
                (const uint8_t*)msg_bytes.data, msg_bytes.size));

        //dispose the digital signature context
        dispose((disposable_t*)&context);

        //dispose all buffers
        dispose((disposable_t*)&priv_hex);
        dispose((disposable_t*)&priv_bytes);
        dispose((disposable_t*)&pub_hex);
        dispose((disposable_t*)&pub_bytes);
        dispose((disposable_t*)&msg_hex);
        dispose((disposable_t*)&msg_bytes);
        dispose((disposable_t*)&sign_hex);
        dispose((disposable_t*)&sign_bytes);
        dispose((disposable_t*)&sign_buffer);
    }


    dispose((disposable_t*)&options);
}

/**
 * Test that we can generate a random keypair, sign a message, and verify the
 * message.
 */
TEST_F(vccrypt_ed25519_ref_test, keygen_sign)
{
    const uint8_t message[] = "foo bar baz";
    vccrypt_digital_signature_options_t options;
    vccrypt_digital_signature_context_t context;

    //we should be able to initialize options for this algorithm
    ASSERT_EQ(0,
        vccrypt_digital_signature_options_init(
            &options, &alloc_opts, &prng_opts,
            VCCRYPT_DIGITAL_SIGNATURE_ALGORITHM_ED25519));

    //create a buffer for the private key
    vccrypt_buffer_t priv;
    ASSERT_EQ(0, vccrypt_buffer_init(&priv, &alloc_opts, 64));

    //create a buffer for the public key
    vccrypt_buffer_t pub;
    ASSERT_EQ(0, vccrypt_buffer_init(&pub, &alloc_opts, 32));

    //create a buffer for the signature
    vccrypt_buffer_t signature;
    ASSERT_EQ(0, vccrypt_buffer_init(&signature, &alloc_opts, 64));

    //create the digital signature context
    ASSERT_EQ(0, vccrypt_digital_signature_init(&options, &context));

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

    //dispose of the options
    dispose((disposable_t*)&options);
}
