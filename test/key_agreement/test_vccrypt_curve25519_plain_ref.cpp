/**
 * \file test_vccrypt_curve25519_plain_ref.cpp
 *
 * Unit tests for the reference curve25519 "plain" implementation.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include <vccrypt/key_agreement.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

class vccrypt_curve25519_plain_ref_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        //make sure our key agreement algorithm has been registered
        vccrypt_key_agreement_register_curve25519_plain();
        //make sure the prng has been registered
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
 * We should be able to get curve25519 options if it has been registered.
 */
TEST_F(vccrypt_curve25519_plain_ref_test, options_init)
{
    vccrypt_key_agreement_options_t options;

    //we should be able to initialize options for this algorithm
    ASSERT_EQ(0,
        vccrypt_key_agreement_options_init(
            &options, &alloc_opts, &prng_opts,
            VCCRYPT_KEY_AGREEMENT_ALGORITHM_CURVE25519_PLAIN));

    dispose((disposable_t*)&options);
}

/**
 * We should be able to create a curve25519 instance.
 */
TEST_F(vccrypt_curve25519_plain_ref_test, init)
{
    vccrypt_key_agreement_options_t options;
    vccrypt_key_agreement_context_t context;

    //we should be able to initialize options for this algorithm
    ASSERT_EQ(0,
        vccrypt_key_agreement_options_init(
            &options, &alloc_opts, &prng_opts,
            VCCRYPT_KEY_AGREEMENT_ALGORITHM_CURVE25519_PLAIN));

    //we should be able to create an algorithm instance
    ASSERT_EQ(0, vccrypt_key_agreement_init(&options, &context));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
}

/**
 * Simple test case from NaCl distribution
 */
TEST_F(vccrypt_curve25519_plain_ref_test, alice_bob)
{
    const uint8_t ALICE_PRIVATE[] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
    };
    const uint8_t ALICE_PUBLIC[] = {
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
    };
    const uint8_t BOB_PRIVATE[] = {
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
    };
    const uint8_t BOB_PUBLIC[] = {
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
    };
    const uint8_t SHARED_SECRET[] = {
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
    };

    vccrypt_key_agreement_options_t options;
    vccrypt_key_agreement_context_t context;

    //we should be able to initialize options for this algorithm
    ASSERT_EQ(0,
        vccrypt_key_agreement_options_init(
            &options, &alloc_opts, &prng_opts,
            VCCRYPT_KEY_AGREEMENT_ALGORITHM_CURVE25519_PLAIN));

    //we should be able to create an algorithm instance
    ASSERT_EQ(0, vccrypt_key_agreement_init(&options, &context));

    //create buffers for public and private keys
    vccrypt_buffer_t alice_private, alice_public, bob_private, bob_public;
    vccrypt_buffer_t shared;
    ASSERT_EQ(0, vccrypt_buffer_init(&alice_private, &alloc_opts, 32));
    memcpy(alice_private.data, ALICE_PRIVATE, 32);
    ASSERT_EQ(0, vccrypt_buffer_init(&alice_public, &alloc_opts, 32));
    memcpy(alice_public.data, ALICE_PUBLIC, 32);
    ASSERT_EQ(0, vccrypt_buffer_init(&bob_private, &alloc_opts, 32));
    memcpy(bob_private.data, BOB_PRIVATE, 32);
    ASSERT_EQ(0, vccrypt_buffer_init(&bob_public, &alloc_opts, 32));
    memcpy(bob_public.data, BOB_PUBLIC, 32);
    ASSERT_EQ(0, vccrypt_buffer_init(&shared, &alloc_opts, 32));

    //generate the alice-bob shared secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_long_term_secret_create(
            &context, &alice_private, &bob_public, &shared));

    //this should match our precomputed secret
    ASSERT_EQ(0, memcmp(shared.data, SHARED_SECRET, 32));

    //generate the bob-alice shared secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_long_term_secret_create(
            &context, &bob_private, &alice_public, &shared));

    //this should match our precomputed secret
    ASSERT_EQ(0, memcmp(shared.data, SHARED_SECRET, 32));

    dispose((disposable_t*)&alice_private);
    dispose((disposable_t*)&alice_public);
    dispose((disposable_t*)&bob_private);
    dispose((disposable_t*)&bob_public);
    dispose((disposable_t*)&shared);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
}

/**
 * Test of the long-term key derivation.
 */
TEST_F(vccrypt_curve25519_plain_ref_test, alice_bob_short_term)
{
    const uint8_t ALICE_PRIVATE[] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
    };
    const uint8_t ALICE_PUBLIC[] = {
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
    };
    const uint8_t ALICE_NONCE[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    const uint8_t BOB_PRIVATE[] = {
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
    };
    const uint8_t BOB_PUBLIC[] = {
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
    };
    const uint8_t BOB_NONCE[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    const uint8_t SHARED_SECRET[] = {
        0x51, 0x93, 0xa0, 0x81, 0x8b, 0xc2, 0xb1, 0xf0,
        0x94, 0xd8, 0xd3, 0x59, 0x8e, 0x35, 0x54, 0x2a,
        0x27, 0x5f, 0x91, 0x41, 0x2e, 0xa7, 0xd7, 0x59,
        0x7e, 0x9b, 0x36, 0x49, 0x8b, 0x79, 0x09, 0x16
    };

    vccrypt_key_agreement_options_t options;
    vccrypt_key_agreement_context_t context;

    //we should be able to initialize options for this algorithm
    ASSERT_EQ(0,
        vccrypt_key_agreement_options_init(
            &options, &alloc_opts, &prng_opts,
            VCCRYPT_KEY_AGREEMENT_ALGORITHM_CURVE25519_PLAIN));

    //we should be able to create an algorithm instance
    ASSERT_EQ(0, vccrypt_key_agreement_init(&options, &context));

    //create buffers for public and private keys
    vccrypt_buffer_t alice_private, alice_public, alice_nonce;
    vccrypt_buffer_t bob_private, bob_public, bob_nonce;
    vccrypt_buffer_t shared;
    ASSERT_EQ(0, vccrypt_buffer_init(&alice_private, &alloc_opts, 32));
    memcpy(alice_private.data, ALICE_PRIVATE, 32);
    ASSERT_EQ(0, vccrypt_buffer_init(&alice_public, &alloc_opts, 32));
    memcpy(alice_public.data, ALICE_PUBLIC, 32);
    ASSERT_EQ(0, vccrypt_buffer_init(&alice_nonce, &alloc_opts, 32));
    memcpy(alice_nonce.data, ALICE_NONCE, 32);
    ASSERT_EQ(0, vccrypt_buffer_init(&bob_private, &alloc_opts, 32));
    memcpy(bob_private.data, BOB_PRIVATE, 32);
    ASSERT_EQ(0, vccrypt_buffer_init(&bob_public, &alloc_opts, 32));
    memcpy(bob_public.data, BOB_PUBLIC, 32);
    ASSERT_EQ(0, vccrypt_buffer_init(&bob_nonce, &alloc_opts, 32));
    memcpy(bob_nonce.data, BOB_NONCE, 32);
    ASSERT_EQ(0, vccrypt_buffer_init(&shared, &alloc_opts, 32));

    //generate the alice-bob shared secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_short_term_secret_create(
            &context, &alice_private, &bob_public, &alice_nonce, &bob_nonce,
            &shared));

    //this should match our precomputed secret
    ASSERT_EQ(0, memcmp(shared.data, SHARED_SECRET, 32));

    //generate the bob-alice shared secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_short_term_secret_create(
            &context, &bob_private, &alice_public, &alice_nonce, &bob_nonce,
            &shared));

    //this should match our precomputed secret
    ASSERT_EQ(0, memcmp(shared.data, SHARED_SECRET, 32));

    dispose((disposable_t*)&alice_private);
    dispose((disposable_t*)&alice_public);
    dispose((disposable_t*)&alice_nonce);
    dispose((disposable_t*)&bob_private);
    dispose((disposable_t*)&bob_public);
    dispose((disposable_t*)&bob_nonce);
    dispose((disposable_t*)&shared);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
}

/**
 * Test that two randomly generated keypairs produce the same key.
 */
TEST_F(vccrypt_curve25519_plain_ref_test, random)
{
    vccrypt_key_agreement_options_t options;
    vccrypt_key_agreement_context_t context;

    //we should be able to initialize options for this algorithm
    ASSERT_EQ(0,
        vccrypt_key_agreement_options_init(
            &options, &alloc_opts, &prng_opts,
            VCCRYPT_KEY_AGREEMENT_ALGORITHM_CURVE25519_PLAIN));

    //we should be able to create an algorithm instance
    ASSERT_EQ(0, vccrypt_key_agreement_init(&options, &context));

    //create buffers for public and private keys
    vccrypt_buffer_t alice_private, alice_public, bob_private, bob_public;
    vccrypt_buffer_t ab_shared, ba_shared;
    ASSERT_EQ(0, vccrypt_buffer_init(&alice_private, &alloc_opts, 32));
    ASSERT_EQ(0, vccrypt_buffer_init(&alice_public, &alloc_opts, 32));
    ASSERT_EQ(0, vccrypt_buffer_init(&bob_private, &alloc_opts, 32));
    ASSERT_EQ(0, vccrypt_buffer_init(&bob_public, &alloc_opts, 32));
    ASSERT_EQ(0, vccrypt_buffer_init(&ab_shared, &alloc_opts, 32));
    ASSERT_EQ(0, vccrypt_buffer_init(&ba_shared, &alloc_opts, 32));

    //generate alice's keypair
    ASSERT_EQ(0,
        vccrypt_key_agreement_keypair_create(
            &context, &alice_private, &alice_public));

    //generate bob's keypair
    ASSERT_EQ(0,
        vccrypt_key_agreement_keypair_create(
            &context, &bob_private, &bob_public));

    //generate the alice-bob shared secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_long_term_secret_create(
            &context, &alice_private, &bob_public, &ab_shared));

    //generate the bob-alice shared secret
    ASSERT_EQ(0,
        vccrypt_key_agreement_long_term_secret_create(
            &context, &bob_private, &alice_public, &ba_shared));

    //the two shared secrets should match
    ASSERT_EQ(0, memcmp(ab_shared.data, ba_shared.data, 32));

    dispose((disposable_t*)&alice_private);
    dispose((disposable_t*)&alice_public);
    dispose((disposable_t*)&bob_private);
    dispose((disposable_t*)&bob_public);
    dispose((disposable_t*)&ab_shared);
    dispose((disposable_t*)&ba_shared);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
}
