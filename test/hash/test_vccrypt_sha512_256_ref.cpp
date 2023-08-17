/**
 * \file test_vccrypt_sha512_256_ref.cpp
 *
 * Unit tests for the reference SHA-512/256 implementation.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <vccrypt/hash.h>
#include <vpr/allocator/malloc_allocator.h>

/* DISABLED GTEST */
#if 0

class vccrypt_sha512_256_ref_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        //make sure SHA-512/256 has been registered
        vccrypt_hash_register_SHA_2_512_256();

        malloc_allocator_options_init(&alloc_opts);
    }

    void TearDown() override
    {
        dispose((disposable_t*)&alloc_opts);
    }

    allocator_options_t alloc_opts;
};

/**
 * We should be able to get SHA-512/256 options if it has been registered.
 */
TEST_F(vccrypt_sha512_256_ref_test, init)
{
    vccrypt_hash_options_t options;

    ASSERT_EQ(0,
        vccrypt_hash_options_init(&options, &alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512_256));

    dispose((disposable_t*)&options);
}

/**
 * We should be able to create a hash context.
 */
TEST_F(vccrypt_sha512_256_ref_test, context_init)
{
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;

    ASSERT_EQ(0,
        vccrypt_hash_options_init(&options, &alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512_256));

    ASSERT_EQ(0,
        vccrypt_hash_init(&options, &context));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
}

/**
 * We should be able to hash test vector 1.
 */
TEST_F(vccrypt_sha512_256_ref_test, hash_1)
{
    const char INPUT[] =
        "abc";
    const char EXPECTED_HASH[] =
        "\x53\x04\x8e\x26\x81\x94\x1e\xf9\x9b\x2e\x29\xb7\x6b\x4c\x7d\xab"
        "\xe4\xc2\xd0\xc6\x34\xfc\x6d\x46\xe0\xe2\xf1\x31\x07\xe7\xaf\x23";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    ASSERT_EQ(0,
        vccrypt_hash_options_init(&options, &alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512_256));

    ASSERT_EQ(0,
        vccrypt_buffer_init(&md, &alloc_opts, options.hash_size));

    ASSERT_EQ(0,
        vccrypt_hash_init(&options, &context));

    ASSERT_EQ(0,
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    ASSERT_EQ(0,
        vccrypt_hash_finalize(&context, &md));

    ASSERT_EQ(0, memcmp(md.data, EXPECTED_HASH, 32));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
}

/**
 * We should be able to hash test vector 2.
 */
TEST_F(vccrypt_sha512_256_ref_test, hash_2)
{
    const char INPUT[] =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const char EXPECTED_HASH[] =
        "\x39\x28\xe1\x84\xfb\x86\x90\xf8\x40\xda\x39\x88\x12\x1d\x31\xbe"
        "\x65\xcb\x9d\x3e\xf8\x3e\xe6\x14\x6f\xea\xc8\x61\xe1\x9b\x56\x3a";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    ASSERT_EQ(0,
        vccrypt_hash_options_init(&options, &alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512_256));

    ASSERT_EQ(0,
        vccrypt_buffer_init(&md, &alloc_opts, options.hash_size));

    ASSERT_EQ(0,
        vccrypt_hash_init(&options, &context));

    ASSERT_EQ(0,
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    ASSERT_EQ(0,
        vccrypt_hash_finalize(&context, &md));

    ASSERT_EQ(0, memcmp(md.data, EXPECTED_HASH, 32));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
}
#endif
