/**
 * \file test_vccrypt_ed25519_ref.cpp
 *
 * Unit tests for the reference ed25519 implementation.
 *
 * \copyright 2017-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <fstream>
#include <minunit/minunit.h>
#include <sstream>
#include <string.h>
#include <vccrypt/digital_signature.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

class vccrypt_ed25519_ref_test {
public:
    void setUp()
    {
        //make sure our prng has been registered
        vccrypt_digital_signature_register_ed25519();
        //make sure ed25519 has been registered
        vccrypt_prng_register_source_operating_system();

        malloc_allocator_options_init(&alloc_opts);

        vccrypt_prng_options_init_status =
            vccrypt_prng_options_init(
                &prng_opts, &alloc_opts, VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM);
    }

    void tearDown()
    {
        if (VCCRYPT_STATUS_SUCCESS == vccrypt_prng_options_init_status)
        {
            dispose((disposable_t*)&prng_opts);
        }
        dispose((disposable_t*)&alloc_opts);
    }

    int vccrypt_prng_options_init_status;
    allocator_options_t alloc_opts;
    vccrypt_prng_options_t prng_opts;
};

TEST_SUITE(vccrypt_ed25519_ref_test);

#define BEGIN_TEST_F(name) \
TEST(name) \
{ \
    vccrypt_ed25519_ref_test fixture; \
    fixture.setUp();

#define END_TEST_F() \
    fixture.tearDown(); \
}

/**
 * Verify that vccrypt_prng_options_init executed successfully.
 */
BEGIN_TEST_F(prng_options_init)
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS == fixture.vccrypt_prng_options_init_status);
END_TEST_F()

/**
 * We should be able to get ed25519 options if it has been registered.
 */
BEGIN_TEST_F(options_init)
    vccrypt_digital_signature_options_t options;

    //we should be able to initialize options for this algorithm
    TEST_ASSERT(
        0
            == vccrypt_digital_signature_options_init(
                    &options, &fixture.alloc_opts, &fixture.prng_opts,
                    VCCRYPT_DIGITAL_SIGNATURE_ALGORITHM_ED25519));

    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to create an ed25519 instance.
 */
BEGIN_TEST_F(init)
    vccrypt_digital_signature_options_t options;
    vccrypt_digital_signature_context_t context;

    //we should be able to initialize options for this algorithm
    TEST_ASSERT(
        0
            == vccrypt_digital_signature_options_init(
                    &options, &fixture.alloc_opts, &fixture.prng_opts,
                    VCCRYPT_DIGITAL_SIGNATURE_ALGORITHM_ED25519));

    //we should be able to create an algorithm instance
    TEST_ASSERT(0 == vccrypt_digital_signature_init(&options, &context));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * Test the signature test vectors.
 */
BEGIN_TEST_F(simple_sign)
    vccrypt_digital_signature_options_t options;
    vccrypt_digital_signature_context_t context;

    //we should be able to initialize options for this algorithm
    TEST_ASSERT(
        0
            == vccrypt_digital_signature_options_init(
                    &options, &fixture.alloc_opts, &fixture.prng_opts,
                    VCCRYPT_DIGITAL_SIGNATURE_ALGORITHM_ED25519));

    // By default the file is relative to the project root.
    // You can set TEST_SIGNATURE_FILE to an absolute path to the file to test from anywhere.
    std::string sign_path = "test/digital_signature/sign.input";
    char* test_signature_path = std::getenv("TEST_SIGNATURE_PATH");

    if (test_signature_path != nullptr)
    {
        sign_path = std::string(test_signature_path);
    }

    //read the signature input file
    ifstream in(sign_path);

    //this stream should be valid
    TEST_ASSERT(in.good());

    //iterate through all test vectors
    string line, priv, pub, msg, signature;
    while (getline(in, line))
    {
        stringstream linein(line);

        //read the components for this test vector
        TEST_ASSERT(getline(linein, priv, ':'));
        TEST_ASSERT(getline(linein, pub, ':'));
        TEST_ASSERT(getline(linein, msg, ':'));
        TEST_ASSERT(getline(linein, signature, ':'));

        //the private key should be 128 digits long
        TEST_ASSERT(128U == priv.size());
        //the public key should be 64 digits long
        TEST_ASSERT(64U == pub.size());
        //the signature should be at least 128 digits long
        TEST_ASSERT(128U <= signature.size());

        //convert the private key to a buffer
        vccrypt_buffer_t priv_hex;
        TEST_ASSERT(
            0 == vccrypt_buffer_init(
                    &priv_hex, &fixture.alloc_opts, priv.size()));
        TEST_ASSERT(
            0
                == vccrypt_buffer_read_data(
                        &priv_hex, priv.c_str(), priv.size()));

        //convert the private hex data to binary
        vccrypt_buffer_t priv_bytes;
        TEST_ASSERT(
            0 == vccrypt_buffer_init(&priv_bytes, &fixture.alloc_opts, 64));
        TEST_ASSERT(0 == vccrypt_buffer_read_hex(&priv_bytes, &priv_hex));

        //convert the public key to a buffer
        vccrypt_buffer_t pub_hex;
        TEST_ASSERT(
            0
                == vccrypt_buffer_init(
                        &pub_hex, &fixture.alloc_opts, pub.size()));
        TEST_ASSERT(
            0 == vccrypt_buffer_read_data(&pub_hex, pub.c_str(), pub.size()));

        //convert the public hex data to binary
        vccrypt_buffer_t pub_bytes;
        TEST_ASSERT(
            0 == vccrypt_buffer_init(&pub_bytes, &fixture.alloc_opts, 32));
        TEST_ASSERT(0 == vccrypt_buffer_read_hex(&pub_bytes, &pub_hex));

        //convert the message to a buffer
        vccrypt_buffer_t msg_hex;
        TEST_ASSERT(
            0
                == vccrypt_buffer_init(
                        &msg_hex, &fixture.alloc_opts, msg.size()));
        TEST_ASSERT(
            0 == vccrypt_buffer_read_data(&msg_hex, msg.c_str(), msg.size()));

        //convert the message hex data to binary
        vccrypt_buffer_t msg_bytes;
        TEST_ASSERT(
            0
                == vccrypt_buffer_init(
                        &msg_bytes, &fixture.alloc_opts, msg.size() / 2));
        TEST_ASSERT(0 == vccrypt_buffer_read_hex(&msg_bytes, &msg_hex));

        //convert the signature to a buffer
        vccrypt_buffer_t sign_hex;
        TEST_ASSERT(
            0
                == vccrypt_buffer_init(
                        &sign_hex, &fixture.alloc_opts, signature.size()));
        TEST_ASSERT(
            0
                == vccrypt_buffer_read_data(
                        &sign_hex, signature.c_str(), signature.size()));

        //convert the signature hex data to binary
        vccrypt_buffer_t sign_bytes;
        TEST_ASSERT(
            0
                == vccrypt_buffer_init(
                        &sign_bytes, &fixture.alloc_opts,
                        signature.size() / 2));
        TEST_ASSERT(0 == vccrypt_buffer_read_hex(&sign_bytes, &sign_hex));

        //create a buffer to hold the generated signature
        vccrypt_buffer_t sign_buffer;
        TEST_ASSERT(
            0 == vccrypt_buffer_init(&sign_buffer, &fixture.alloc_opts, 64));

        //create the digital signature context
        TEST_ASSERT(0 == vccrypt_digital_signature_init(&options, &context));

        //sign the message
        TEST_ASSERT(
            0
                == vccrypt_digital_signature_sign(
                        &context, &sign_buffer, &priv_bytes,
                        (const uint8_t*)msg_bytes.data, msg_bytes.size));

        //verify that our generated signature matches the provided signature
        //NOTE: this is an UNSAFE WAY to compare signatures.  Used here only for
        //testing purposes.  Use a constant-time comparison in real code!
        TEST_ASSERT(0 == memcmp(sign_buffer.data, sign_bytes.data, 64));

        //verify the signature
        TEST_ASSERT(
            0
                == vccrypt_digital_signature_verify(
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
END_TEST_F()

/**
 * Test that we can generate a random keypair, sign a message, and verify the
 * message.
 */
BEGIN_TEST_F(keygen_sign)
    const uint8_t message[] = "foo bar baz";
    vccrypt_digital_signature_options_t options;
    vccrypt_digital_signature_context_t context;

    //we should be able to initialize options for this algorithm
    TEST_ASSERT(
        0
            == vccrypt_digital_signature_options_init(
                    &options, &fixture.alloc_opts, &fixture.prng_opts,
                    VCCRYPT_DIGITAL_SIGNATURE_ALGORITHM_ED25519));

    //create a buffer for the private key
    vccrypt_buffer_t priv;
    TEST_ASSERT(0 == vccrypt_buffer_init(&priv, &fixture.alloc_opts, 64));

    //create a buffer for the public key
    vccrypt_buffer_t pub;
    TEST_ASSERT(0 == vccrypt_buffer_init(&pub, &fixture.alloc_opts, 32));

    //create a buffer for the signature
    vccrypt_buffer_t signature;
    TEST_ASSERT(
        0 == vccrypt_buffer_init(&signature, &fixture.alloc_opts, 64));

    //create the digital signature context
    TEST_ASSERT(0 == vccrypt_digital_signature_init(&options, &context));

    //generate a keypair
    TEST_ASSERT(
        0 == vccrypt_digital_signature_keypair_create(&context, &priv, &pub));

    //sign the message
    TEST_ASSERT(
        0
            == vccrypt_digital_signature_sign(
                    &context, &signature, &priv, message, sizeof(message)));

    //verify the signature
    TEST_ASSERT(
        0
            == vccrypt_digital_signature_verify(
                    &context, &signature, &pub, message, sizeof(message)));

    //dispose the digital signature context
    dispose((disposable_t*)&context);

    //dispose all buffers
    dispose((disposable_t*)&priv);
    dispose((disposable_t*)&pub);
    dispose((disposable_t*)&signature);

    //dispose of the options
    dispose((disposable_t*)&options);
END_TEST_F()
