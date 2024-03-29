/**
 * \file test_vccrypt_sha384_ref.cpp
 *
 * Unit tests for the reference SHA-384 implementation.
 *
 * \copyright 2017-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <string.h>
#include <vccrypt/hash.h>
#include <vpr/allocator/malloc_allocator.h>

class vccrypt_sha384_ref_test {
public:
    void setUp()
    {
        //make sure SHA-384 has been registered
        vccrypt_hash_register_SHA_2_384();

        malloc_allocator_options_init(&alloc_opts);
    }

    void tearDown()
    {
        dispose((disposable_t*)&alloc_opts);
    }

    allocator_options_t alloc_opts;
};

TEST_SUITE(vccrypt_sha384_ref_test);

#define BEGIN_TEST_F(name) \
TEST(name) \
{ \
    vccrypt_sha384_ref_test fixture; \
    fixture.setUp();

#define END_TEST_F() \
    fixture.tearDown(); \
}

/**
 * We should be able to get SHA-384 options if it has been registered.
 */
BEGIN_TEST_F(init)
    vccrypt_hash_options_t options;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to create a hash context.
 */
BEGIN_TEST_F(context_init)
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash an empty buffer.
 */
BEGIN_TEST_F(hash_empty)
    const char EXPECTED_HASH[] =
        "\x38\xb0\x60\xa7\x51\xac\x96\x38\x4c\xd9\x32\x7e"
        "\xb1\xb1\xe3\x6a\x21\xfd\xb7\x11\x14\xbe\x07\x43"
        "\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda\x27\x4e\xde\xbf"
        "\xe7\x6f\x65\xfb\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&md);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 1.
 */
BEGIN_TEST_F(hash_1)
    const char INPUT[] =
        "\xc5";
    const char EXPECTED_HASH[] =
        "\xb5\x2b\x72\xda\x75\xd0\x66\x63\x79\xe2\x0f\x9b"
        "\x4a\x79\xc3\x3a\x32\x9a\x01\xf0\x6a\x2f\xb7\x86"
        "\x5c\x90\x62\xa2\x8c\x1d\xe8\x60\xba\x43\x2e\xdf"
        "\xd8\x6b\x4c\xb1\xcb\x8a\x75\xb4\x60\x76\xe3\xb1";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 2.
 */
BEGIN_TEST_F(hash_2)
    const char INPUT[] =
        "\x6e\xce";
    const char EXPECTED_HASH[] =
        "\x53\xd4\x77\x3d\xa5\x0d\x8b\xe4\x14\x5d\x8f\x3a"
        "\x70\x98\xff\x36\x91\xa5\x54\xa2\x9a\xe6\xf6\x52"
        "\xcc\x71\x21\xeb\x8b\xc9\x6f\xd2\x21\x0e\x06\xae"
        "\x2f\xa2\xa3\x6c\x4b\x3b\x34\x97\x34\x1e\x70\xf0";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 3.
 */
BEGIN_TEST_F(hash_3)
    const char INPUT[] =
        "\x1f\xa4\xd5";
    const char EXPECTED_HASH[] =
        "\xe4\xca\x46\x63\xdf\xf1\x89\x54\x1c\xd0\x26\xdc"
        "\xc0\x56\x62\x64\x19\x02\x87\x74\x66\x6f\x5b\x37"
        "\x9b\x99\xf4\x88\x7c\x72\x37\xbd\xbd\x3b\xea\x46"
        "\xd5\x38\x8b\xe0\xef\xc2\xd4\xb7\x98\x9a\xb2\xc4";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 4.
 */
BEGIN_TEST_F(hash_4)
    const char INPUT[] =
        "\x50\xe3\x85\x3d";
    const char EXPECTED_HASH[] =
        "\x93\x6a\x3c\x39\x91\x71\x6b\xa4\xc4\x13\xbc\x03"
        "\xde\x20\xf5\xce\x1c\x63\x70\x3b\x3a\x5b\xdb\x6a"
        "\xb5\x58\xc9\xff\x70\xd5\x37\xe4\x6e\xb4\xa1\x5d"
        "\x9f\x2c\x85\xe6\x8d\x86\x78\xde\x56\x82\x69\x5e";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 5.
 */
BEGIN_TEST_F(hash_5)
    const char INPUT[] =
        "\x4b\x5f\xab\x61\xe0";
    const char EXPECTED_HASH[] =
        "\xfb\x39\x0a\xa5\xb7\x0b\x06\x8a\x54\xd6\xd5\x12"
        "\x7d\xf6\xa6\x22\x7b\xec\xc4\xd6\xf8\x91\xfd\x3f"
        "\x60\x68\xb9\x17\xa8\x83\xc9\xb6\x6f\x31\x8f\xdd"
        "\xb6\x38\x4d\x10\xbe\x8c\x7a\xf0\xd3\x13\x2f\x03";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 6.
 */
BEGIN_TEST_F(hash_6)
    const char INPUT[] =
        "\xda\xd9\x5a\x4b\x4d\x37";
    const char EXPECTED_HASH[] =
        "\x3a\x2b\x40\xf4\x53\x92\x5b\xc3\xce\x17\xd6\x40"
        "\x75\x7e\xe0\xe8\x99\x39\x0b\x4a\x8d\x98\x4d\x02"
        "\x97\xc1\xba\xe6\xb6\x0b\x9f\x26\x03\xbf\x71\xc3"
        "\x23\xfd\x17\x10\x11\x37\x23\x35\xe5\x70\x2e\x40";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 7.
 */
BEGIN_TEST_F(hash_7)
    const char INPUT[] =
        "\x12\x18\x35\xfe\x37\x00\xb7";
    const char EXPECTED_HASH[] =
        "\x7b\xd0\x6a\x94\xac\xba\x7b\xeb\x3c\x5a\x9b\x9e"
        "\x87\x69\xc3\xda\x66\x91\xc4\x82\xd7\x8b\x1e\x5c"
        "\x76\x19\xb3\x66\x30\xeb\xa4\xe5\x96\xd1\x1c\x41"
        "\x0a\x4c\x87\x00\x6f\x47\x16\xb6\xf1\x7b\xb9\xa0";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 8.
 */
BEGIN_TEST_F(hash_8)
    const char INPUT[] =
        "\xde\x60\x27\x5b\xda\xfc\xe4\xb1";
    const char EXPECTED_HASH[] =
        "\xa3\xd8\x61\xd8\x66\xc1\x36\x24\x23\xeb\x21\xc6"
        "\xbe\xc8\xe4\x4b\x74\xce\x99\x3c\x55\xba\xa2\xb6"
        "\x64\x05\x67\x56\x0e\xbe\xcd\xae\xda\x07\x18\x3d"
        "\xbb\xbd\x95\xe0\xf5\x22\xca\xee\x5d\xdb\xda\xf0";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 9.
 */
BEGIN_TEST_F(hash_9)
    const char INPUT[] =
        "\x8d\x45\xa5\x5d\x5c\xe1\xf9\x28\xe6";
    const char EXPECTED_HASH[] =
        "\xde\x76\x68\x35\x75\xa0\x50\xe2\xeb\x5e\xf9\x5e"
        "\xe2\x01\xf8\x24\x16\x47\x8a\x1d\x14\xbf\x3d\x96"
        "\xd1\xfd\x4e\xfd\x52\xb1\xa2\x8f\xed\x8d\xfe\xe1"
        "\x83\x00\x70\x00\x1d\xc1\x02\xa2\x1f\x76\x1d\x20";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 10.
 */
BEGIN_TEST_F(hash_10)
    const char INPUT[] =
        "\x5c\x7d\xde\x9b\x38\x94\xd7\x3c\xef\xe1";
    const char EXPECTED_HASH[] =
        "\xf3\x1b\x22\x11\x5f\xa7\x17\x8e\x78\x22\x3e\x06"
        "\xaa\xe8\x70\x54\x7a\xb9\x3c\x6e\xb3\xc3\x91\x0b"
        "\x0e\xe1\x6e\x61\x06\xdb\x55\x93\x5d\x6c\x0e\xb8"
        "\x20\x13\x2a\x20\x78\xec\xe1\x06\x7e\xfc\x81\xc3";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 11.
 */
BEGIN_TEST_F(hash_11)
    const char INPUT[] =
        "\x96\x7f\xa3\x4c\x07\xe4\x94\x5a\x77\x05\x1a";
    const char EXPECTED_HASH[] =
        "\xf8\xf2\x4d\x81\xc4\xf8\xf2\x3e\xcb\x42\xd7\x6e"
        "\xd5\xd2\xb3\x4c\x9c\xbc\x1f\x0a\x97\x23\x4d\x11"
        "\x14\x80\x4b\x59\x99\x75\x9f\x31\x31\xc7\x41\xd5"
        "\x76\x8c\xc9\x28\x16\x35\x03\xc5\xf5\x5f\x59\x4b";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 12.
 */
BEGIN_TEST_F(hash_12)
    const char INPUT[] =
        "\x22\x09\x11\x2e\xe7\x79\xbf\x6d\x95\x71\x11\x05";
    const char EXPECTED_HASH[] =
        "\x09\xc5\x4b\xf5\x33\xa2\x6c\x74\x47\xca\xa5\x78"
        "\x3d\xb2\xec\x7e\xf5\xe5\x57\x52\xda\x7f\x2a\x2c"
        "\x4e\x36\x09\x82\xa9\x4e\xc1\xca\x2c\xb6\xa1\x57"
        "\xd3\x4e\xed\x28\xde\x97\x8b\x41\x45\xe1\x7e\xbc";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 13.
 */
BEGIN_TEST_F(hash_13)
    const char INPUT[] =
        "\x20\x44\x2e\x1c\x3f\x3c\x88\x91\x9c\x39\x97\x8b"
        "\x78";
    const char EXPECTED_HASH[] =
        "\x50\xbc\x95\xb0\x36\xe0\xf5\x4d\x83\x30\x32\xa8"
        "\x0d\x45\xc2\xac\x38\xb3\xd2\x9e\x9c\x7f\x72\xa2"
        "\xeb\x14\x78\x1e\x92\x41\xd2\xa4\xb8\xe8\xdb\xa6"
        "\xee\x6f\x4c\x9e\x46\xa7\x58\xd5\x71\x2d\xbd\x39";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 14.
 */
BEGIN_TEST_F(hash_14)
    const char INPUT[] =
        "\x4d\x43\x70\x2b\xe4\xf0\x53\x03\x19\x55\x5d\x7f"
        "\x1a\x33";
    const char EXPECTED_HASH[] =
        "\x83\xc8\xf0\xbb\x76\x28\x01\xeb\x26\xcc\x51\x15"
        "\xab\xeb\xb6\x57\xc1\x8f\xf8\x11\xde\x50\x0b\x32"
        "\xb7\xa5\x68\xa2\x20\xa2\x87\xe9\x00\xb6\xc7\x52"
        "\x24\xfe\x74\x29\x16\x9f\xbd\x53\x4c\xb5\x88\xe1";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 15.
 */
BEGIN_TEST_F(hash_15)
    const char INPUT[] =
        "\x5e\x2a\x79\xa5\x44\xaf\x85\xf1\x50\xf7\xa9\xd2"
        "\x09\xfd\x44";
    const char EXPECTED_HASH[] =
        "\x80\x51\xeb\xc9\xca\xbb\x05\x2c\xab\xe0\x7e\x40"
        "\x23\xe2\x14\x08\x08\xb7\x7d\x25\xb0\x7b\x96\xd2"
        "\xe3\xc2\x23\x93\xf7\x1b\x11\x6c\x1a\x1e\x41\xbf"
        "\x62\xe5\x7f\x73\xff\x67\x87\x1d\xa7\xc9\x3c\xf9";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 16.
 */
BEGIN_TEST_F(hash_16)
    const char INPUT[] =
        "\xe1\xbb\x96\x7b\x5d\x37\x9a\x4a\xa3\x90\x50\x27"
        "\x4d\x09\xbd\x93";
    const char EXPECTED_HASH[] =
        "\x3b\x04\xf9\x69\x65\xad\x2f\xba\xbd\x4d\xf2\x5d"
        "\x5d\x8c\x95\x58\x9d\x06\x9c\x31\x2e\xe4\x85\x39"
        "\x09\x0b\x2d\x7b\x49\x5d\x24\x46\xc3\x1e\xb2\xb8"
        "\xf8\xff\xb3\x01\x2b\xdc\xe0\x65\x32\x3d\x9f\x48";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 17.
 */
BEGIN_TEST_F(hash_17)
    const char INPUT[] =
        "\xbb\x84\xa0\x14\xcd\x17\xcc\x23\x2c\x98\xae\x8b"
        "\x07\x09\x91\x7e\x9d";
    const char EXPECTED_HASH[] =
        "\x85\x22\x7a\xe0\x57\xf2\x08\x2a\xdf\x17\x8c\xae"
        "\x99\x64\x49\x10\x0b\x6a\x31\x19\xe4\xc4\x15\xa9"
        "\x9e\x25\xbe\x6e\xf2\x0b\xa8\xc0\xea\xe8\x18\xd6"
        "\x0f\x71\xc5\xc8\x3f\xf2\xd4\xc5\x9a\xa7\x52\x63";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 18.
 */
BEGIN_TEST_F(hash_18)
    const char INPUT[] =
        "\xc3\x41\x1a\x05\x92\xf1\xf4\xfa\x69\x88\x15\x23"
        "\x89\x97\xdb\x35\x64\x18";
    const char EXPECTED_HASH[] =
        "\x23\x3a\xc4\x41\x70\xd9\xf4\x52\xa1\xa0\x23\x16"
        "\x22\x03\x0b\x15\xc1\x04\xff\x8e\xca\xa3\xfc\xcd"
        "\xb9\xe9\xe5\x03\x1f\xd5\xb4\x22\x01\x86\xa8\xed"
        "\xd0\x32\x84\x9c\x8b\x93\xdc\x18\x3a\x5c\x86\x27";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 19.
 */
BEGIN_TEST_F(hash_19)
    const char INPUT[] =
        "\xe8\x31\xb7\x39\xe8\xeb\x9f\x78\x7f\x63\xc0\xbb"
        "\x07\x1d\xdc\xc9\xf4\x4c\xab";
    const char EXPECTED_HASH[] =
        "\x91\x72\x2d\x4b\x7a\xec\xc2\x11\xbb\x8a\x54\x80"
        "\xc6\x85\x5f\x3b\x71\xbe\x46\x47\xe1\xdd\xe0\x38"
        "\x0c\x23\xaf\xaa\x03\xf4\x5c\x64\x26\x06\xa2\x45"
        "\x06\xe0\x31\x7b\xf5\x15\x06\xa4\x83\xde\x28\xac";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 20.
 */
BEGIN_TEST_F(hash_20)
    const char INPUT[] =
        "\xb8\xa7\xbb\xcc\xde\x46\xe8\x5f\x12\x23\x23\x7d"
        "\x93\x53\xb7\x8c\x3b\x19\x72\x7b";
    const char EXPECTED_HASH[] =
        "\x28\xba\x69\xdc\x05\xe6\xe2\x9d\xe9\x19\x24\x11"
        "\x4d\x6c\x9f\xc7\x61\x2f\x6d\x2a\x68\xb0\x7f\xa0"
        "\x01\xdf\x05\x9b\xcf\x98\xf7\xaa\x85\x38\x9c\xae"
        "\xb9\x66\xea\xa2\x99\xc7\x9f\xe1\xfd\x1e\x40\xe3";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 21.
 */
BEGIN_TEST_F(hash_21)
    const char INPUT[] =
        "\xcf\x39\x1b\x8a\xab\xec\x6f\x81\x28\x8c\x8b\x7b"
        "\x92\x84\x3b\xe2\x3d\x2e\x84\x75\x74";
    const char EXPECTED_HASH[] =
        "\x12\x1e\x5e\xf6\x97\xdf\x49\x1a\x53\xd7\xba\xe1"
        "\x21\x41\x6a\xa6\x53\xd7\x59\xa3\x7d\xb9\xd0\xb9"
        "\x93\x03\x1b\x18\xa0\xef\x16\x0e\xd9\x88\x42\xa2"
        "\x91\xe1\xba\x2c\xea\x8b\x99\x8b\xc5\xee\xe0\xb1";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 22.
 */
BEGIN_TEST_F(hash_22)
    const char INPUT[] =
        "\x9d\x65\xd8\x8b\xff\xed\x76\x4c\x28\x6f\x34\x89"
        "\x4f\x99\x16\x00\xd1\xa6\x7d\x62\x23\x82";
    const char EXPECTED_HASH[] =
        "\x84\xb6\xe0\xd6\xa4\x53\x29\xda\xf4\x7a\x79\x34"
        "\x18\xed\x5d\xbd\xe0\x13\x36\xb4\xb9\x46\x8b\xb6"
        "\x9e\x5d\xa6\x1c\x42\xb6\x91\xe6\x79\x4e\x6e\xd0"
        "\xe8\xfb\x1b\x8e\x7d\x4c\xd3\xcb\xaa\xdc\x52\x0a";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 23.
 */
BEGIN_TEST_F(hash_23)
    const char INPUT[] =
        "\xba\xb6\xea\x46\xfb\x71\x7f\x73\xf0\x62\x81\x32"
        "\xa2\xb9\x6b\xe3\x83\x77\x4f\x1e\x5d\x8b\x6d";
    const char EXPECTED_HASH[] =
        "\xe9\x69\xac\xa1\xb5\x0e\x92\x8c\xad\x29\xa0\xd7"
        "\x56\x45\x7f\x6d\xe8\xd7\xa4\xe5\x89\xfd\x41\xe5"
        "\x3a\x1e\x75\x8c\x3b\x20\xf9\xb8\x1b\x36\xbf\x09"
        "\x8a\x49\x10\x2f\xbf\x86\x96\x51\xca\x9a\x98\xb5";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 24.
 */
BEGIN_TEST_F(hash_24)
    const char INPUT[] =
        "\x88\x53\xb0\x0e\x86\x97\x64\xad\xb5\x27\xa0\x7b"
        "\x07\x3c\x85\xa2\x4e\x6c\x20\x8b\xa4\x7e\xef\x4e";
    const char EXPECTED_HASH[] =
        "\x09\xad\x44\xe8\x5a\xc1\x90\xe2\xd1\xc3\xce\xb4"
        "\xef\xbe\xa1\x0d\xed\x34\xd0\xde\x96\x1f\xe4\xee"
        "\x26\x81\x32\xc4\x8e\x38\x66\x0e\x6c\xf5\x85\xbf"
        "\xff\xb8\xf7\xb0\x0b\x0f\xad\x15\x14\x31\x2b\x63";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 25.
 */
BEGIN_TEST_F(hash_25)
    const char INPUT[] =
        "\x71\xfe\x1b\xa5\xd2\x99\x49\x5d\x2a\x56\x03\x9c"
        "\x64\x03\x2e\xc6\x26\x3d\x43\x7f\x55\xe3\xf5\xbe"
        "\xdb";
    const char EXPECTED_HASH[] =
        "\xb4\x1a\x5d\x3b\x4a\xf6\xd4\xb9\xc3\x49\xe0\x78"
        "\x85\x38\xe9\xa0\x31\x10\x86\x89\x4d\xf7\xb7\x2c"
        "\xf5\xaa\xf4\x09\x1a\x7e\x03\x9e\x4e\x89\xcc\x77"
        "\xa1\x23\x47\x4e\x6d\x1b\xac\x43\x8e\x5e\x9f\x88";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 26.
 */
BEGIN_TEST_F(hash_26)
    const char INPUT[] =
        "\x4e\xbe\x07\xd0\x3c\x93\xe8\x49\xb4\xbb\xfe\x9f"
        "\x2d\x22\x94\xbf\x6c\xca\xb4\x57\xf7\x6d\x3f\x99"
        "\xcb\x64";
    const char EXPECTED_HASH[] =
        "\xbe\xba\x46\x4d\x70\x65\x18\x55\x87\xfa\xd8\x9b"
        "\xfc\xea\x96\x35\xbf\x0a\xb7\x75\xc3\xeb\x8c\x14"
        "\x7b\x5b\x2b\xd8\x60\x1d\xb6\xdb\xa0\x59\x0b\x50"
        "\xdd\x10\x68\x73\x3f\x20\xdc\x68\xe0\x04\xa0\x90";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 27.
 */
BEGIN_TEST_F(hash_27)
    const char INPUT[] =
        "\x91\x8a\xc0\xa9\x7e\xc1\x63\x29\x08\x48\x9e\x52"
        "\x42\xba\x28\x4b\xc8\x11\xaa\x71\x97\x24\x2c\xf7"
        "\x22\x6f\xcd";
    const char EXPECTED_HASH[] =
        "\xc4\xba\xf6\x39\x7a\x4c\x6e\x26\x49\x2b\x63\xa4"
        "\xaa\xb7\xdf\xfd\xd0\x05\x1d\x8f\x51\x93\x8a\xc2"
        "\x4c\xfd\x8d\xae\x2f\x7a\xfe\xd1\xa4\xaa\x24\x30"
        "\xd7\xae\xb0\xbe\x2a\x72\xb2\x1a\x6c\x50\x19\x8c";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 28.
 */
BEGIN_TEST_F(hash_28)
    const char INPUT[] =
        "\x97\x47\x7f\x72\x72\xd8\xa8\x9e\x38\xe7\x96\xc5"
        "\x33\xe9\xf8\xa8\xae\x4c\x92\xcc\xaa\x5d\x90\x7e"
        "\xd2\x6a\x1a\x15";
    const char EXPECTED_HASH[] =
        "\xd1\xad\x52\x4e\xbe\x90\x8d\x7c\x5a\xff\x50\xe6"
        "\xcb\x78\x0f\xd3\xa7\x0e\x87\xc9\x14\xa3\x6b\x93"
        "\xc4\xe3\x5f\x5b\x2c\xb0\x38\x50\xb1\x22\xb4\x80"
        "\xef\x85\x87\xd4\xa4\x4f\x22\x46\x7f\x4c\x48\x0c";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 29.
 */
BEGIN_TEST_F(hash_29)
    const char INPUT[] =
        "\x71\x8e\x0c\xfe\x13\x86\xcb\x14\x21\xb4\x79\x9b"
        "\x15\x78\x8b\x86\x2b\xf0\x3a\x80\x72\xbb\x30\xd0"
        "\x23\x03\x88\x80\x32";
    const char EXPECTED_HASH[] =
        "\x6d\x8b\x8a\x5b\xc7\xea\x36\x5e\xa0\x7f\x11\xd3"
        "\xb1\x2e\x95\x87\x2a\x96\x33\x68\x47\x52\x49\x5c"
        "\xc4\x31\x63\x6c\xaf\x1b\x27\x3a\x35\x32\x10\x44"
        "\xaf\x31\xc9\x74\xd8\x57\x5d\x38\x71\x1f\x56\xc6";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 30.
 */
BEGIN_TEST_F(hash_30)
    const char INPUT[] =
        "\xd3\xb0\x7f\x0f\xd5\xd4\xcd\x31\x88\xae\xad\x8d"
        "\xc8\x33\x8d\xe4\x20\x56\xe2\xe8\x48\x7e\xca\x51"
        "\xec\x37\xef\x2d\xaf\x27";
    const char EXPECTED_HASH[] =
        "\xad\xcc\x2e\x95\x4c\x91\xdb\x3d\xb2\xd7\x1d\x0d"
        "\xee\x1f\x03\x0e\x72\x3b\xee\x1a\x23\x81\x6f\xe0"
        "\x03\xac\x5d\xc8\x62\xa0\x87\x2e\xf5\x1f\xf3\x86"
        "\xc1\x8b\xe6\xeb\xca\xa4\x93\xf3\x2d\x11\x95\xb9";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 31.
 */
BEGIN_TEST_F(hash_31)
    const char INPUT[] =
        "\x69\x5b\x9e\xfe\x18\x09\xab\xd5\xd4\x4e\xae\x95"
        "\x7d\xdf\x9c\x2c\xd3\xc7\x5f\xae\x2f\x52\x28\x55"
        "\x71\x2a\x07\xc6\x39\xc0\xb9";
    const char EXPECTED_HASH[] =
        "\x3b\xb9\x5d\x16\x4d\x94\x59\x5a\x11\x87\xf7\x7f"
        "\xc2\x6c\x28\x0f\xfb\xb0\x8e\x74\xec\x79\x47\xaa"
        "\x3e\x5b\x38\xbe\xc7\xc6\xf8\x11\x5c\x4d\x88\x07"
        "\x88\xc2\x40\x2d\xbb\x3e\x5b\x94\xaf\xd1\x30\xee";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 32.
 */
BEGIN_TEST_F(hash_32)
    const char INPUT[] =
        "\xbe\x01\xe5\x20\xe6\x9f\x04\x17\x4c\xcf\x95\x45"
        "\x5b\x1c\x81\x44\x52\x98\x26\x4d\x9a\xdc\x49\x58"
        "\x57\x4a\x52\x84\x3d\x95\xb8\xba";
    const char EXPECTED_HASH[] =
        "\xc5\xcf\x54\xb8\xe3\x10\x5b\x1c\x7b\xf7\xa4\x37"
        "\x54\xd9\x15\xb0\x94\x7f\x28\xb6\xdc\x94\xa0\x19"
        "\x18\x29\x29\xb5\xc8\x48\xe1\x14\x41\xc9\xe4\xe9"
        "\x0c\x74\x49\xf4\xc3\xcd\x12\x95\x4f\x0f\x5d\x99";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 33.
 */
BEGIN_TEST_F(hash_33)
    const char INPUT[] =
        "\x98\xef\x73\x01\xf9\x57\xd7\x3d\x4e\x82\x1d\x58"
        "\x73\xe8\xa9\xb5\x97\x0f\xbd\x21\x9d\x5c\xf7\x4e"
        "\xc2\x29\x1b\x83\x81\x18\x13\x91\xb4";
    const char EXPECTED_HASH[] =
        "\xb2\x56\x4b\xbb\x15\x9c\x3a\xea\xdb\xae\x0e\x4a"
        "\x44\x37\xf7\xc5\x11\x10\x20\xe9\xad\x0f\x4e\xb5"
        "\x08\x14\x7a\x96\x1a\xc2\x2a\x01\xe1\xa2\x6d\xf0"
        "\x46\xb1\x4e\xe5\xe8\xa4\x9d\x9e\xd2\x2b\x8c\xd1";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 34.
 */
BEGIN_TEST_F(hash_34)
    const char INPUT[] =
        "\x87\x3b\xa7\xf8\xb7\x15\x17\xec\x50\x29\x7b\x21"
        "\xcf\x94\xcd\xb7\xa5\x8a\xbb\xb8\x82\x92\x06\xf0"
        "\xd3\xf3\x28\xff\x8a\x69\x39\xac\x1d\x1d";
    const char EXPECTED_HASH[] =
        "\x74\x05\xfd\xd5\x57\xd2\xb5\xd4\xf6\x5e\x9e\x85"
        "\xf5\x08\xd3\x79\x14\x95\xf1\x82\x0d\x37\xca\xbf"
        "\xc8\xdb\xb7\x4d\x7b\x41\xdf\x86\x13\xd9\x95\xc6"
        "\x12\xd3\x78\xdd\x88\x33\x7e\x00\x95\x1d\x02\x80";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 35.
 */
BEGIN_TEST_F(hash_35)
    const char INPUT[] =
        "\xe3\xbd\x4b\xc3\xa6\x0c\xdd\xd2\x6c\x20\xaa\x86"
        "\x36\x4b\xd4\x4f\x4a\x07\xf3\x30\x28\x25\xad\x0a"
        "\xc1\x27\x88\x1d\xe4\xea\xfb\xcc\xf9\x88\xcb";
    const char EXPECTED_HASH[] =
        "\x19\x9d\x54\x23\xa0\xe2\x64\x38\xf4\xce\xa0\x08"
        "\x1a\x89\xe0\xb6\xc8\x4c\xa9\x3f\x7c\x31\x20\xc8"
        "\x10\x4b\x51\xc6\xed\xc0\x4e\x0f\x6a\x20\x3b\xb7"
        "\x7d\x59\x97\x3a\x74\x11\xa0\xef\xbe\x93\xa0\x9d";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 36.
 */
BEGIN_TEST_F(hash_36)
    const char INPUT[] =
        "\x87\x16\xe4\xb8\x6d\xef\xf9\xda\x2a\x8e\xd5\x5b"
        "\xaa\x43\x58\x2a\x75\x86\xec\x9c\xd3\x8a\xc3\xa9"
        "\x33\x15\x61\x58\xcd\x8e\x5b\x78\x87\x58\x5e\x91";
    const char EXPECTED_HASH[] =
        "\x0d\x23\x06\xd9\xc0\xa8\xce\x57\xbc\x78\x69\xb4"
        "\x39\x37\x6c\x07\xce\x35\x2a\x41\xd8\x6a\xb6\xcf"
        "\x4a\x56\x54\xcc\xcd\x5c\x72\x4f\xe1\xb6\x2b\x2c"
        "\x11\x01\xc9\x86\x22\x2f\x52\x64\xab\x3f\xdd\x66";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 37.
 */
BEGIN_TEST_F(hash_37)
    const char INPUT[] =
        "\xf8\xa5\x03\xaa\xa2\x5e\xf2\xce\xa2\x5e\x31\x93"
        "\x0c\x3a\x90\xdb\x46\x8c\xd3\xa8\x62\xf4\xa9\x3a"
        "\xab\x5d\xe2\x77\x7e\x82\xdc\x90\x5c\xb0\x3e\xe2"
        "\x3c";
    const char EXPECTED_HASH[] =
        "\x77\x3e\xe9\x58\xfe\x93\xdf\xd1\xb7\x3a\xf2\x4d"
        "\x27\xdd\xce\x33\x14\x4a\x92\x49\xd5\xa6\x71\x68"
        "\x2a\x56\xdf\x30\xd0\xbb\xf9\x2b\x93\x27\x13\x00"
        "\x22\x07\x51\x85\xd3\x96\xde\x75\x29\x59\x30\x4f";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 38.
 */
BEGIN_TEST_F(hash_38)
    const char INPUT[] =
        "\x66\x90\x25\x17\x5e\xa9\x17\xcd\xd7\xa7\x1f\xf4"
        "\xec\x0c\x45\xbf\x12\x46\xd2\xa6\xf0\x31\xc0\x0b"
        "\x71\xde\x70\x1e\x17\x93\x9b\xfe\x92\x12\x8b\x21"
        "\x91\x1e";
    const char EXPECTED_HASH[] =
        "\x9f\xf6\xbe\x3f\x02\xc7\xc5\xd0\x20\x6f\x4b\x94"
        "\x4c\x08\x43\xcb\x68\xbe\xa8\xf9\xb7\xc8\xcc\x0b"
        "\x72\x95\x03\xdb\x50\x05\xc7\xcd\x5c\xb1\x4e\x34"
        "\x57\xd8\xf5\xea\xbf\x73\x3f\xca\x90\x84\xf1\x6b";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 39.
 */
BEGIN_TEST_F(hash_39)
    const char INPUT[] =
        "\xb3\x5f\xb2\x26\x2e\xdf\xa1\x49\x38\xa0\xfb\xa0"
        "\x3e\xb2\xa2\x5d\x37\x79\x74\xb1\x1f\x55\x64\x91"
        "\xa7\x81\xd0\xba\x2b\x3c\x0f\xf3\xe4\x27\x49\x92"
        "\x5f\xef\x8b";
    const char EXPECTED_HASH[] =
        "\x83\x5b\x05\xa4\xbf\x00\xc2\x59\x4c\x3c\x8c\x13"
        "\xda\x6c\x27\x3a\x0d\x9e\xfd\xea\x0d\xa7\x2b\x71"
        "\xb1\x9d\x32\x6b\xf5\xce\x96\x8c\x2e\x57\x7a\x7d"
        "\x99\xfc\x0f\x98\x5a\xfd\x23\xb4\x64\x23\x12\x9d";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 40.
 */
BEGIN_TEST_F(hash_40)
    const char INPUT[] =
        "\x9d\x86\xb4\x5d\xf8\xd7\xda\xe0\xcf\x6b\x0b\xc2"
        "\x08\x66\x6e\xe1\x16\x3a\x39\xe6\x11\x6d\x6d\x24"
        "\x0c\x9d\xc1\xc3\xa3\xc1\xdb\x1d\xd3\xb1\xc6\x68"
        "\x0f\xe9\xa1\x96";
    const char EXPECTED_HASH[] =
        "\xa8\x4c\x46\x9c\x24\x69\x6f\x81\xd7\xdf\x4e\xe8"
        "\xcd\x76\xaa\x58\x4f\x8c\x99\x60\xea\xa9\x90\x8d"
        "\x3e\x3e\xbc\x5e\xea\x7d\x0b\x50\xaf\xdd\xed\x39"
        "\xde\xb9\x4f\xd5\x93\x23\xa2\x1a\x65\x39\xe9\x3f";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 41.
 */
BEGIN_TEST_F(hash_41)
    const char INPUT[] =
        "\x41\x4f\x56\x19\xf6\xdf\xd4\x58\x53\xbb\xab\xd2"
        "\x24\xcc\x30\x5d\x77\x35\x0a\xd2\x53\x35\x89\x10"
        "\xa7\x4f\x3a\x43\x81\xa9\xb8\x66\x80\xb3\xc4\x06"
        "\x8c\x08\x98\x49\xc4";
    const char EXPECTED_HASH[] =
        "\x84\x8d\x48\x1e\x3b\xbf\x5d\xd7\x26\xf6\x25\xcf"
        "\x6a\x44\x4d\x99\x5b\x36\x26\x2c\x9f\x80\xd5\x83"
        "\xb7\x7a\xcc\xf1\x70\x7e\x3f\x49\xbb\x3d\xc4\x80"
        "\xa5\x60\x69\x4d\x76\x9a\xa1\xce\x65\xd6\x94\x28";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 42.
 */
BEGIN_TEST_F(hash_42)
    const char INPUT[] =
        "\xe2\x65\x83\x24\x82\x1a\xe7\xb0\xfa\xa0\xcd\xd6"
        "\x3e\xe9\xef\xb9\xfc\xbe\x82\x09\x2d\x04\x69\x6f"
        "\xeb\x3d\xa9\x2c\x82\x52\x1d\xfd\xc9\x8f\x6b\x41"
        "\xb3\xef\x36\x5d\x21\x9a";
    const char EXPECTED_HASH[] =
        "\x3e\xa5\xd0\x79\x9f\x1a\x4d\xca\xb9\x14\x9a\x40"
        "\xab\x74\xbe\xc9\xc8\xd7\x6d\x8e\x39\x2c\x1e\x63"
        "\xe0\x80\xdd\xec\x2e\xc5\x35\xf8\x0b\xe9\xf0\x09"
        "\x27\xbe\x28\x1e\xc9\x7a\xc0\xc8\x82\xbb\x0b\xbf";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 43.
 */
BEGIN_TEST_F(hash_43)
    const char INPUT[] =
        "\x7e\x80\x27\x1b\xb5\xf2\xcc\x7d\xda\xe4\x15\x86"
        "\x58\xe4\xe8\xd0\x6e\x04\xa3\x93\x85\xda\x0e\xca"
        "\xc1\xcb\x8e\x91\xd6\x8a\x9b\xd2\x1d\xdb\x73\x20"
        "\xe7\x9d\x10\xe3\x11\x07\x58";
    const char EXPECTED_HASH[] =
        "\xfa\x00\xbc\x03\x59\xa6\x42\xdc\xb3\x55\x96\x56"
        "\x09\x4e\xb2\xfd\x4f\x63\xbc\x57\xf0\xd3\x4a\xbf"
        "\xf2\x6d\xf5\xc5\x4c\xc6\x3d\xbe\xb4\xea\xc7\x59"
        "\x05\x29\x6e\x7f\xb6\x9f\x87\x1e\x13\x40\x83\xf6";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 44.
 */
BEGIN_TEST_F(hash_44)
    const char INPUT[] =
        "\x43\xd2\x82\x8e\x86\xf7\x85\x6b\x78\xc6\x6c\xfa"
        "\x3d\x60\x23\x87\xc2\x90\x97\x5a\xfd\x02\x1a\x8b"
        "\x76\xaf\x09\x18\x06\x9c\xac\x35\xde\xc4\x5d\xe3"
        "\xcc\x52\xed\xc4\xba\x14\x43\x2e";
    const char EXPECTED_HASH[] =
        "\x6c\x9e\x36\x7e\x06\x60\x32\xce\x47\xba\x25\x75"
        "\x56\x59\x32\x00\x2c\xc7\x86\xf5\x33\xc5\x55\x16"
        "\x56\xab\xfe\x73\x91\xe7\xdc\xb5\xf9\xd9\xe0\x47"
        "\xad\xac\xe2\x3d\x32\xf8\xac\xed\xfd\x0c\xaf\xc5";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 45.
 */
BEGIN_TEST_F(hash_45)
    const char INPUT[] =
        "\x3f\x49\xbb\x64\x5c\xce\xd7\x53\x0b\x8b\x82\xe6"
        "\xcf\x07\xfb\xf6\x70\xf7\xef\x0b\xa0\x58\x3d\x16"
        "\xde\xba\xfc\x63\x9b\xdf\xbf\xc9\x9b\x84\x17\x24"
        "\x9f\x7f\x5a\x05\x41\x0a\xa3\xa7\x1f";
    const char EXPECTED_HASH[] =
        "\x2b\x30\x1a\x14\x64\x7a\x67\x42\x9c\xc3\xe7\xda"
        "\x02\xc4\x09\x3a\x73\x96\x40\xf7\xb4\x7a\x30\x52"
        "\x51\xd2\x85\x5e\x75\xe0\x9e\x60\xe2\x62\xb2\x79"
        "\xa0\x73\x07\x7d\x1f\xb6\xd0\xf0\x47\x88\xf2\xb8";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 46.
 */
BEGIN_TEST_F(hash_46)
    const char INPUT[] =
        "\x31\xaa\xc0\x6a\x59\xb7\x4b\xf4\x78\x61\x7c\x16"
        "\x37\xfa\x6c\x55\x93\xdf\x16\x8b\x8d\x58\xb1\xe9"
        "\x23\xbf\x3e\x3d\x80\xe5\x5d\x71\x70\xb1\x64\x54"
        "\x16\x0a\xb2\x9e\xe1\xf7\x41\x2e\xbc\x05";
    const char EXPECTED_HASH[] =
        "\xdd\xd2\x45\xc9\xb2\x9c\xea\xc6\x05\x06\xfb\x6b"
        "\xd6\xe8\x03\x78\x89\xcb\x73\xd6\xec\xc6\x69\xfd"
        "\x12\x90\x60\xa8\xa8\xf5\x89\x71\xac\x57\x2d\x3e"
        "\xc9\xb4\x44\x04\xf8\x13\x81\xd0\xfd\x35\xa6\x49";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 47.
 */
BEGIN_TEST_F(hash_47)
    const char INPUT[] =
        "\xc1\x0b\x28\x52\x05\x4d\x80\x34\xe0\x79\x06\xc7"
        "\xfc\xe3\xce\x99\x40\x23\x21\xa6\x48\xbb\x88\x1f"
        "\x13\xfb\x27\x6a\xfc\x22\x4c\x6a\xec\xc6\x48\x00"
        "\xcd\x76\x7e\xd2\x42\x9d\xb9\x4b\x95\xa9\xc3";
    const char EXPECTED_HASH[] =
        "\xa4\x46\x40\xfb\x4c\xe6\xdf\xd4\xa1\x02\x90\xa0"
        "\xae\xcd\xb4\x53\x05\x4a\x9b\x54\xf2\x58\x3e\x97"
        "\xbb\x7d\xc2\xb0\x05\xe5\xfa\x2b\x4f\xda\x17\xb1"
        "\xf7\x59\x02\xf5\x1c\x18\xc0\xca\xad\x35\x83\x3c";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 48.
 */
BEGIN_TEST_F(hash_48)
    const char INPUT[] =
        "\xb1\xee\xef\x32\x4b\x49\x9f\x19\xeb\xa3\x22\x21"
        "\x5f\xe3\xce\x19\xc9\xf0\x00\xb6\x98\xd2\xb2\xda"
        "\xb7\x14\x50\x15\x04\x6c\xc8\x6d\x04\x9e\xe1\x5a"
        "\xd5\x9d\xcd\x15\x64\xf3\x01\x12\xe0\x64\x44\xcb";
    const char EXPECTED_HASH[] =
        "\x38\x74\x2d\x18\xbf\xa6\xe9\x18\xb8\x88\xd6\x8d"
        "\x10\x34\xe6\x1f\x65\xde\xc0\x75\x91\x72\xc2\xdb"
        "\xf0\x8c\xf1\xe1\x32\xb2\x17\xea\xf4\xec\x29\xe1"
        "\x5d\xb7\xf4\xb0\x7e\x08\xa7\x0c\xc5\x66\x20\x12";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 49.
 */
BEGIN_TEST_F(hash_49)
    const char INPUT[] =
        "\x79\x0d\xbb\xa0\x99\x65\xc9\x77\x4d\xd6\x0a\x32"
        "\xe0\x10\xc5\x0d\x6d\x51\x89\x68\xa2\x20\x14\x1d"
        "\xc3\x3e\x74\x10\xf2\xda\x6c\x08\xad\x04\x19\xbd"
        "\x98\x64\xd5\x32\x7d\x2c\x5c\x44\x91\x4b\x2e\x83"
        "\xf9";
    const char EXPECTED_HASH[] =
        "\x91\x74\x95\x8b\xc8\xf4\xed\x47\x31\xec\xed\x99"
        "\x9b\xea\x2f\x63\x03\x2f\x52\xbc\x8c\x46\xbc\xd9"
        "\x03\x23\x2f\x3f\xbc\x50\x46\xf0\xd6\xc2\x03\xd4"
        "\x3a\x07\x8b\x82\x2f\xc0\x51\x01\x40\x4f\x26\x35";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 50.
 */
BEGIN_TEST_F(hash_50)
    const char INPUT[] =
        "\xf7\xb5\x77\xf1\x39\x6b\x23\xc2\x7e\xb6\x37\xe5"
        "\x3d\x3d\x92\x46\x02\x70\xb0\x01\xcc\x61\x2f\xd3"
        "\xb4\xd6\x8b\xcd\xd0\x9c\x2d\x50\x57\x1e\xa4\x35"
        "\x06\x36\x32\x4c\xc2\x42\x8a\x08\x7e\x7b\xd8\x78"
        "\x5f\x82";
    const char EXPECTED_HASH[] =
        "\x80\xaf\xe1\x11\xe4\x4a\xd9\xaf\xf9\xe3\x9c\x4c"
        "\xf9\xe6\xb4\xc5\x20\x07\x2b\x45\x50\xe6\x2b\x17"
        "\x40\x16\x0a\x04\xf8\xd5\x30\x61\x2d\xc0\x98\x91"
        "\x7a\x55\x6b\x44\x97\x7d\x0e\x73\xdf\x51\x8b\xee";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 51.
 */
BEGIN_TEST_F(hash_51)
    const char INPUT[] =
        "\x73\x70\xd9\xb4\x53\x93\x69\x55\xb9\xc9\xd3\x36"
        "\xf4\xb2\x83\x23\x79\x86\x23\x2d\xe0\x07\xbf\x41"
        "\x2f\xb4\x26\xff\x5b\x40\x93\xc8\x0c\x42\x8c\x19"
        "\xa1\x2e\x0b\x18\x74\x84\xdc\x6d\x5f\x47\x46\x53"
        "\x7f\xb1\xed";
    const char EXPECTED_HASH[] =
        "\x6c\xd2\x91\x59\x82\x0d\x34\xe5\x70\x6d\xd8\x67"
        "\xe6\x36\x37\x58\xd3\x12\x66\x0d\x4d\xac\xa8\xd2"
        "\xab\xf6\x77\xf2\x34\x74\x6e\x97\xa0\xa6\x22\x4e"
        "\xb0\x54\x06\x6a\x0b\x74\xe1\x8c\x70\x96\x53\x68";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 52.
 */
BEGIN_TEST_F(hash_52)
    const char INPUT[] =
        "\xe8\x62\x01\x70\xf0\xf3\x93\x28\xbd\xf8\x88\x81"
        "\x48\xcf\xd1\x77\x30\xf3\x14\xea\x68\xd8\xfe\xa0"
        "\x2d\x16\xd9\x8a\x3c\xca\x61\x48\x41\x39\xd3\xee"
        "\x92\xb7\x48\x09\x1d\xc8\x41\xdd\xa0\x84\x83\xf1"
        "\x18\x40\x25\xce";
    const char EXPECTED_HASH[] =
        "\x29\xc4\x08\xa6\xa5\x04\x5f\x39\x7b\x56\xdf\xb5"
        "\x29\x2c\x7c\x16\x02\x8c\x63\xf0\x68\xe6\x99\xb8"
        "\x6a\x89\x1f\xf8\x50\x12\x08\xec\x93\x98\xdb\xaf"
        "\x46\x3c\x00\xf3\x9a\xf7\xb2\xcb\xe4\x5b\xac\x15";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 53.
 */
BEGIN_TEST_F(hash_53)
    const char INPUT[] =
        "\x75\xd4\x21\x6b\xad\x77\x94\x3b\xfe\x82\xbe\x21"
        "\x61\x57\x84\x3b\x0d\xa0\xfd\x16\xee\xee\x84\x71"
        "\x53\xa0\x0b\x43\xe7\x07\xb2\xff\xe2\xc8\x98\x16"
        "\x80\x81\xf0\xbd\xb3\xaf\x58\xf2\x14\xcf\x67\xb9"
        "\x20\xc3\x85\xac\xa1";
    const char EXPECTED_HASH[] =
        "\x01\x70\x35\x73\x85\xa2\x08\x65\xa8\xd3\x0c\x2d"
        "\xf3\x94\x06\x90\x3f\xf8\x8c\x7f\x70\xfa\x1a\x7a"
        "\x5a\xaa\x86\x71\x1d\x64\x04\x6c\x43\x2a\x1b\x13"
        "\x96\x68\xae\x5a\xbe\xd6\x37\xd1\xdc\x41\x07\xb7";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 54.
 */
BEGIN_TEST_F(hash_54)
    const char INPUT[] =
        "\x2f\xa9\x0c\x22\x10\xe3\x09\x6c\xae\xd1\x22\xb7"
        "\x4e\xb9\x55\x99\x77\x12\x0e\x5d\x9a\x97\xee\xb3"
        "\xf9\x9b\xcb\xa6\xc1\x9c\xf8\xcf\x79\x1a\xc6\xc8"
        "\xa0\xa9\x4a\xe4\x92\x46\x61\x1d\xac\xe7\xf2\x4e"
        "\xb0\x56\x73\xa3\x6b\x3e";
    const char EXPECTED_HASH[] =
        "\x6c\x2c\xed\x3f\xae\x94\xdb\xd9\x2f\x41\x70\xb6"
        "\x3f\x1f\xf6\xfc\xd8\x19\x4f\x60\x93\x7b\x22\xb4"
        "\xf3\xc9\x5f\xc9\xe1\x04\xb7\x71\x48\xf9\xbc\x6c"
        "\x16\xa8\x90\xde\x86\xd9\xef\x15\x54\xc9\x6f\xa0";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 55.
 */
BEGIN_TEST_F(hash_55)
    const char INPUT[] =
        "\xa8\xde\x55\x17\x0c\x6d\xc0\xd8\x0d\xe3\x2f\x50"
        "\x8b\xf4\x9b\x70\x46\xae\xea\x4b\x97\x5a\x51\x1b"
        "\x5e\xa3\xdc\x85\x3b\xfa\x4b\x1e\x01\x38\x20\x2d"
        "\x67\x85\xf6\xb3\x01\x79\x14\xa8\x6f\x82\x42\x88"
        "\xd5\x86\xdc\x0e\x8b\xc9\x24";
    const char EXPECTED_HASH[] =
        "\x2b\xc3\xb1\x0c\x14\x82\x00\xf7\x91\x9b\x57\xaf"
        "\xe1\xd7\xdb\x77\x3f\xfd\x23\x5e\x04\xfe\xc6\x89"
        "\x7d\xd9\x4f\x13\xad\x9c\x43\x7e\xf5\x09\x00\xa4"
        "\x09\x37\xf8\x2a\x39\xda\xf2\xaa\x2b\x3d\xfd\x68";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 56.
 */
BEGIN_TEST_F(hash_56)
    const char INPUT[] =
        "\xac\xcd\x9d\x05\xfb\x7e\xf3\x04\x34\x70\x83\x61"
        "\x37\x55\x4a\xf1\x17\x44\x0b\x3c\xcc\xa7\xa2\x80"
        "\x28\x54\x94\xf9\x0d\xfa\xea\x60\xdc\xbf\x40\xb2"
        "\x30\x27\x19\x32\xcd\x38\x75\xb1\xd3\xdc\xa6\x0d"
        "\x38\x86\x5f\xf8\x74\x18\x0e\xfa";
    const char EXPECTED_HASH[] =
        "\xb9\xe0\x2d\xf9\x3e\x92\x54\x18\x0d\x6a\x15\x28"
        "\x8d\x77\x08\x8b\x5a\x5c\xe5\x17\x64\x41\x09\xb4"
        "\xe2\x53\x2b\xe3\x15\xf0\x8d\xee\x43\x49\x16\x08"
        "\xa1\x12\x7d\xcd\xf6\x93\x97\x40\x6e\x23\xd2\x31";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 57.
 */
BEGIN_TEST_F(hash_57)
    const char INPUT[] =
        "\x32\xb8\x35\xc1\x80\xcc\x40\x06\xc1\x1a\x61\xc6"
        "\x5b\x03\xc0\x99\x51\x0e\x1d\x4f\x0a\x94\xb6\x3d"
        "\x54\xbd\x6b\xd5\xa8\xab\x20\x7a\xb0\xf4\x63\x92"
        "\x06\x56\x4e\xdc\x3f\xa6\xaf\x03\x28\x0a\x67\x74"
        "\x4f\x68\x10\x6d\xc5\x1e\xe3\x57\x23";
    const char EXPECTED_HASH[] =
        "\xdf\x97\xa1\xc5\xdd\xa6\xf9\xdd\xe7\x49\xf2\x13"
        "\xe4\x29\xdb\x84\xf0\xdc\xd4\x81\xd4\x3b\xf5\x8e"
        "\x61\x42\x96\x8d\x62\x9e\xcf\x05\xb2\x62\x83\x0a"
        "\x7d\xac\x87\xf6\x7f\x43\x83\x97\x5f\x3e\x82\x1d";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 58.
 */
BEGIN_TEST_F(hash_58)
    const char INPUT[] =
        "\x94\x09\xf9\xef\xad\xbf\x19\x0b\x25\x33\x67\x62"
        "\x9f\x8f\x36\x8c\x9d\x5a\xc2\x62\xe9\x4a\xb8\x6f"
        "\x35\x59\xf9\xa1\xfe\x1a\x9b\x44\xb6\x4e\x31\x31"
        "\x21\xb3\x4d\x43\x00\x1c\x43\x0b\xed\xc6\x2f\xc5"
        "\x86\xea\x39\x8a\xcd\x8f\x17\xc7\xcf\xa2";
    const char EXPECTED_HASH[] =
        "\xe1\xa6\x93\x88\xee\x6b\x6d\x23\x41\x08\xec\x29"
        "\x40\x2c\xd0\xaf\xd7\x49\x57\xd9\x90\xc7\xbd\xb5"
        "\x44\xcf\x11\xe8\xeb\x2c\xcd\x17\x0b\x6b\x5a\x74"
        "\x43\x1b\xe7\x03\x64\xd7\xa3\x1b\x92\x6f\xf5\x3c";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 59.
 */
BEGIN_TEST_F(hash_59)
    const char INPUT[] =
        "\x28\x95\x86\xba\xf8\xda\xce\xd5\x0d\xb1\x4c\x93"
        "\x65\x29\xa0\xa6\x43\x8e\xb5\xda\x8d\x3d\x46\x91"
        "\x72\xb6\xa0\x6f\x4f\xf3\xa9\x56\xd4\xf9\x21\x95"
        "\x63\xac\x28\x5c\xb8\xe7\x00\x74\xcf\xcc\x15\x2c"
        "\x02\x59\x3a\x97\x73\x3c\x36\xf4\xa9\xe9\x7f";
    const char EXPECTED_HASH[] =
        "\x50\x9e\x99\x6c\x1e\x11\x61\x1c\x24\x30\x21\xb8"
        "\xb7\x8f\x2a\xd9\x0c\x5a\x92\x63\xbb\xf3\x59\x10"
        "\xdb\x7c\x8e\xc1\x02\xaa\x7c\x51\x80\x66\xff\xf8"
        "\xce\x88\x56\x2f\xec\x2c\xd6\xdf\xe0\x40\x56\xae";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 60.
 */
BEGIN_TEST_F(hash_60)
    const char INPUT[] =
        "\x15\x65\x30\xcd\x6e\xd3\xba\xf1\xfd\x72\x32\xc7"
        "\xff\x20\x4f\x3c\x7d\x4d\x10\x60\x16\xaf\xa3\xbd"
        "\xff\x37\x86\xe8\x48\x43\xec\x55\x61\x15\x62\x6f"
        "\xdc\x84\xb2\xe8\x74\xf1\x07\x4e\x4f\x7d\x53\xe0"
        "\x80\x79\xee\x9f\xd0\x1f\x80\xa8\xbe\x7f\x20\xc0";
    const char EXPECTED_HASH[] =
        "\x7b\x8a\x59\x80\x29\xca\x0e\xd4\x75\xa7\x2c\x06"
        "\x44\xac\x81\xc6\x3d\x72\xfd\x51\x30\x5d\xad\xa0"
        "\x7b\x0a\xb4\xa2\x9e\x47\x42\x2f\x59\xe1\x26\x43"
        "\x17\x92\x69\xca\x3d\x7d\x10\x44\x6b\x37\x2b\x2c";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 61.
 */
BEGIN_TEST_F(hash_61)
    const char INPUT[] =
        "\x30\x65\x5a\x6b\x5a\x59\x65\xdb\x99\x2e\x72\x48"
        "\xd2\x41\x41\x05\x5e\x98\x8d\x72\x6a\xbb\x8e\x72"
        "\x9d\xc5\xc2\x1f\xfc\xba\xed\xbc\x0b\x1b\x5f\xea"
        "\x35\xb8\x75\x1f\x6e\xc6\x62\x55\x17\x31\x2f\xff"
        "\x22\x34\x01\x41\x76\x26\x9b\x60\x95\x97\x23\x78"
        "\x7c";
    const char EXPECTED_HASH[] =
        "\xcf\xaf\x44\x3e\x95\xde\xeb\x3c\xc1\x91\x07\x71"
        "\xa2\xc0\x69\x2a\x54\xb1\x8b\x36\x33\xdc\x54\x14"
        "\xe7\x1a\xe0\x88\x77\xf0\x80\x48\x18\xf6\x7f\x71"
        "\x96\xc5\x2e\x26\xb7\x62\xdd\x12\xbb\x7a\x86\xca";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 62.
 */
BEGIN_TEST_F(hash_62)
    const char INPUT[] =
        "\x34\x5c\x3c\x02\x2e\x20\x14\x4e\x13\x56\x04\x07"
        "\x87\x62\xef\x5c\x8a\x8f\x03\x8c\xf1\xb1\xd6\xa9"
        "\x17\x09\xb5\x9d\xd0\x68\x39\x6a\x9e\x97\x1a\xb6"
        "\x28\xf7\x48\x86\xe7\x65\x38\x4a\x23\x60\x7c\x1a"
        "\x1e\x6e\x97\x3f\x8f\xbb\x0f\xf5\x51\x04\xc4\x6f"
        "\x5d\xb3";
    const char EXPECTED_HASH[] =
        "\xbf\xb1\xd5\xee\x3a\x0b\x62\x90\x58\xec\xc5\x21"
        "\xc7\x06\xc2\xf9\x24\x1c\x48\xcd\xa3\xdc\xfd\xba"
        "\x66\x0a\x26\x01\xd8\x32\xa7\xa8\x72\xa2\xbb\x84"
        "\x0f\x3b\x98\xd2\x1c\x37\xe2\x8f\x90\x41\xa5\xb2";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 63.
 */
BEGIN_TEST_F(hash_63)
    const char INPUT[] =
        "\x0b\x94\xa0\xf4\x3a\x92\x40\x89\x63\xa5\x9d\xed"
        "\x01\xa9\x33\x82\x83\xa6\xff\x1b\xfb\xac\xd9\x05"
        "\x1a\x01\x04\x44\x5c\x7f\x04\x1e\x80\x37\xaf\xde"
        "\x3b\x5a\x87\xd2\x2d\x5a\x47\x96\x14\x4c\xbc\x94"
        "\x40\x91\xd6\xcc\x47\xb5\xff\xd1\xf9\x97\xab\x14"
        "\x96\xca\x31";
    const char EXPECTED_HASH[] =
        "\x07\xa0\x45\xc9\x59\x0e\x99\x01\xd0\x59\x8e\x60"
        "\x4c\x46\x49\x55\x4a\x82\x3d\xe9\x96\xfa\x43\x8c"
        "\xc8\x1a\x63\x43\x44\xee\xb9\x8e\x5f\x3c\x0c\x23"
        "\x4b\xa3\x0e\x22\x85\xa4\xd7\xab\x56\x8f\x26\x10";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 64.
 */
BEGIN_TEST_F(hash_64)
    const char INPUT[] =
        "\x93\x03\x5d\x3a\x13\xae\x1b\x06\xdd\x03\x3e\x76"
        "\x4a\xca\x01\x24\x96\x1d\xa7\x9c\x36\x6c\x6c\x75"
        "\x6b\xc4\xbc\xc1\x18\x50\xa3\xa8\xd1\x20\x85\x4f"
        "\x34\x29\x0f\xff\x7c\x8d\x6d\x83\x53\x1d\xbd\xd1"
        "\xe8\x1c\xc4\xed\x42\x46\xe0\x0b\xd4\x11\x3e\xf4"
        "\x51\x33\x4d\xaa";
    const char EXPECTED_HASH[] =
        "\x8d\x46\xcc\x84\xb6\xc2\xde\xb2\x06\xaa\x5c\x86"
        "\x17\x98\x79\x87\x51\xa2\x6e\xe7\x4b\x1d\xaf\x3a"
        "\x55\x7c\x41\xae\xbd\x65\xad\xc0\x27\x55\x9f\x7c"
        "\xd9\x2b\x25\x5b\x37\x4c\x83\xbd\x55\x56\x8b\x45";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 65.
 */
BEGIN_TEST_F(hash_65)
    const char INPUT[] =
        "\xbf\xb9\x4d\xfb\xe0\xd9\xa5\x09\xb7\x8d\x16\x4a"
        "\x72\x20\x50\x05\x4d\xad\x91\xc9\xa8\xe2\x60\x54"
        "\x5d\x03\x7e\xb4\x50\x32\x1a\xac\x48\xed\x44\x59"
        "\xfd\xd8\xa4\x15\x72\xbd\x6c\x9c\x84\xd1\x8b\x6e"
        "\xc3\x39\x24\x74\x82\xcc\x3e\xe5\x2a\x1b\xbd\x6b"
        "\xd4\xae\x91\x82\x16";
    const char EXPECTED_HASH[] =
        "\x13\xaf\x0b\xe0\x29\x86\xea\x31\x76\xe8\xc6\x55"
        "\x34\xec\x9f\x32\xc2\x3b\x53\xc9\x3a\x73\xb1\x5c"
        "\x26\xb9\xec\xbd\x8a\x11\x81\xae\x18\x4a\x37\x2e"
        "\x9f\x5e\x05\x96\xcd\x66\x06\x84\x9a\xea\xe8\xe0";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 66.
 */
BEGIN_TEST_F(hash_66)
    const char INPUT[] =
        "\x1c\x89\x24\xa1\x6f\xa7\xc6\x02\xaf\xf5\xee\x96"
        "\x17\x98\xbd\x44\xfe\x53\x79\x8b\xf4\x4c\x3d\x6b"
        "\x0d\x13\xef\x83\x7d\xe0\x73\x77\x65\x1c\x1e\x94"
        "\xed\x23\x6e\xb7\x93\x49\xf8\x6a\xc3\x1b\xa1\x51"
        "\xa7\xe7\x11\xc5\x40\x7e\x65\xbe\xb6\x38\x24\xf6"
        "\xec\x39\x75\x4b\x58\xf3";
    const char EXPECTED_HASH[] =
        "\x5b\xe6\x48\x28\x51\xdd\xaf\xde\x58\x2f\x28\x04"
        "\x07\x1a\x70\x2a\xe3\x9b\xac\xb6\x88\x74\x1b\x7c"
        "\x37\xbb\xae\x99\x82\x1c\xe4\xd3\xf4\x7d\x5b\x09"
        "\x7f\xd8\xee\xfa\x0e\xf9\x24\x8a\x34\xf5\xd3\xce";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 67.
 */
BEGIN_TEST_F(hash_67)
    const char INPUT[] =
        "\x18\x42\x15\x14\x5d\xa4\x9d\xb4\x17\xe8\xbd\xd5"
        "\x73\xd6\x28\x2d\xe0\x73\xe6\x74\xc3\xde\xa8\x6b"
        "\x6c\x78\x59\x1d\x49\x47\xf5\x65\x5a\x9d\x9e\xb0"
        "\xe5\xf4\xed\x04\x6b\x1d\x86\x42\xda\x9a\xef\xa8"
        "\x04\x48\xa2\x99\x50\x41\x60\xa1\xb0\x00\xc9\xb4"
        "\xd3\xc6\x2a\xb6\x9b\x3d\x96";
    const char EXPECTED_HASH[] =
        "\x89\x95\xcd\x7f\xc0\x95\x6e\x12\x40\x75\x44\x06"
        "\x86\xbe\xec\xe1\x7a\x62\x56\xb2\x82\xe7\x98\x8a"
        "\x0c\x99\x8f\x79\x0e\x39\x95\xc9\x74\x38\x31\x79"
        "\x89\x34\x77\xbc\xc3\x2d\x1f\x11\x41\x29\xb4\x96";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 68.
 */
BEGIN_TEST_F(hash_68)
    const char INPUT[] =
        "\xca\x7a\x63\xad\xf4\x1f\x4d\xa3\x31\x42\x91\x0c"
        "\x96\x77\x06\xb5\xc8\xa0\x93\x35\x0e\xb3\xe6\xd3"
        "\xaa\xbe\x69\xa4\x6a\x28\x72\xf4\x7a\x39\xbb\xe7"
        "\x7c\xdc\x11\x60\xda\xa4\x50\x22\x5b\x0e\x8e\x36"
        "\xf5\x06\x97\x8c\xe3\xac\x9a\xe5\xf7\x57\x21\xef"
        "\x30\xda\x46\xb2\x8f\x07\x24\x2c";
    const char EXPECTED_HASH[] =
        "\xb8\x9c\xc1\x2b\x11\xe3\xaf\xa5\x89\x08\x58\x0c"
        "\x47\xb2\x54\x07\xab\xbf\x58\x4f\x8e\x8d\x4b\x56"
        "\x31\xe9\xf4\x50\x46\x4c\x7e\x53\xcf\xd7\xe9\xf9"
        "\xd3\xcf\x35\xe5\x87\xa6\xf0\x29\x57\xce\x4c\x28";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 69.
 */
BEGIN_TEST_F(hash_69)
    const char INPUT[] =
        "\x1d\xa4\x1a\x0a\xf2\x02\xb0\x79\x52\x1d\xeb\x61"
        "\x09\xe3\x12\xc2\xad\xe4\x85\x44\xd2\xb4\x98\xc0"
        "\x7e\x91\xa1\x02\xdd\x46\x50\xce\x35\x4f\x3f\x20"
        "\x1b\x3e\xca\xb8\xe8\x5e\x21\xd6\x67\x95\x9b\x43"
        "\xd0\x8f\x4e\x90\xfa\x18\xdc\xa2\xcc\xca\x8f\x6f"
        "\xf5\xe9\xa9\x02\xdc\x8b\xf5\xc5\xda";
    const char EXPECTED_HASH[] =
        "\x5c\x29\x7e\x20\xc3\x07\xaa\xb7\xf3\x25\x93\x9f"
        "\xd4\xe2\x88\x3b\x03\x4f\xd5\x47\xf1\xdd\x17\xfb"
        "\x6b\x97\xad\xe8\xb1\x48\xe0\x6e\xbb\xf3\xff\x60"
        "\xcb\xf4\x69\xe4\x93\x3d\x5f\x48\xf0\x16\x6c\xb7";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 70.
 */
BEGIN_TEST_F(hash_70)
    const char INPUT[] =
        "\xde\xce\x42\xc8\x84\x9b\xe4\x0c\x78\xb8\xde\x6d"
        "\xa9\x6c\x2a\x8d\x7e\x94\x05\x45\xb9\xf3\xf3\x9a"
        "\xa1\xca\x03\xec\x60\xa8\x54\x71\xaa\x84\xd8\xe2"
        "\x9f\x09\x58\x74\xf3\x31\xb9\x0a\x4c\x15\x7d\xa9"
        "\xeb\x04\x8d\x2c\x8f\xd2\x35\x39\x96\x72\x70\x73"
        "\x66\xc7\x66\xf1\x0b\xb8\x33\xf0\x21\x83";
    const char EXPECTED_HASH[] =
        "\xbb\x50\x9e\x33\xe9\xff\xcc\x4c\x01\x23\x31\x46"
        "\x22\x6e\xe9\x36\x4c\xda\xc5\x65\x81\x32\x46\x0a"
        "\x76\xed\xf6\x17\xa0\x35\xb1\x97\xc8\x64\x34\xee"
        "\x88\x94\x38\x58\x14\x58\x10\x26\x18\x76\x93\x82";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 71.
 */
BEGIN_TEST_F(hash_71)
    const char INPUT[] =
        "\x95\x20\x08\xeb\xde\xdd\x48\x04\x49\xbb\x96\xa0"
        "\x25\x57\x6c\x5f\x61\x7b\xbb\x83\x07\x95\x8a\x01"
        "\x07\x67\xe0\xd7\x36\xff\xe5\xa1\x96\xea\x44\x67"
        "\xd8\xa5\xd3\xba\x1f\x54\x76\xff\x07\xb6\x41\x0a"
        "\xe6\x59\xdc\xef\x52\x0a\x2c\x14\xe3\x90\x2f\x8b"
        "\x39\x9a\x28\x9f\x41\xf5\xfd\xad\xb5\x02\xdd";
    const char EXPECTED_HASH[] =
        "\x9b\x63\xd9\x14\x5b\xc7\x14\xa8\x25\x3d\xcd\xb8"
        "\x34\x1b\x2f\x57\x14\xeb\x58\xb9\xd4\xb2\x2c\xe4"
        "\x5a\xae\x07\xf5\x12\x97\xa3\xdc\x9c\x5b\x69\x1a"
        "\x8a\x3c\xd4\x38\xdc\x5b\xd1\x8b\xe4\x00\xaf\x21";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 72.
 */
BEGIN_TEST_F(hash_72)
    const char INPUT[] =
        "\x10\x01\x32\xc3\x15\xbf\xc9\xc4\xfb\x93\x02\x3f"
        "\x5d\x35\x00\xd7\x20\x8a\x68\xac\xb4\xd2\xc6\x30"
        "\x96\x23\x2c\x36\x1a\x16\x1c\x4c\x67\xc0\xa7\x4b"
        "\xc3\xe4\xd7\x2c\x11\x66\x4b\x1d\x97\x03\x21\xd4"
        "\x05\x40\x19\x24\xb3\xa0\xf6\xce\x2b\x1a\x28\x99"
        "\xe7\xca\xa9\xa5\x5c\xe7\x25\xfc\x37\xf5\x5d\x6a";
    const char EXPECTED_HASH[] =
        "\xb6\xca\x04\x46\x7e\xd3\xe6\x23\xdb\xa3\x6f\x2e"
        "\x02\x48\xce\xfb\xe1\x34\xcf\x55\x5f\xdc\x14\x73"
        "\x11\x75\xea\xaf\x08\xe2\x44\xab\x0b\x15\xfc\xa2"
        "\xf1\x73\xa0\xec\x98\xfe\xaf\x35\x9f\xb8\x4a\x11";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 73.
 */
BEGIN_TEST_F(hash_73)
    const char INPUT[] =
        "\x99\xcb\xa4\x01\x9f\x54\x78\x78\x9e\x67\x4e\x08"
        "\xfe\x5d\x6c\xea\xdd\x69\x8b\x07\x57\xca\x39\xc6"
        "\x05\x45\x7c\x22\xc3\xd3\xb8\xff\xb7\x97\xd2\xbe"
        "\x8f\x12\x96\x0f\x09\x9a\x56\x06\xb9\x08\xd4\x72"
        "\x07\xb2\x63\x6a\x77\x99\x48\x28\x2d\xe3\x66\x1b"
        "\xb0\x8b\x1b\x37\xee\x57\x65\x90\x80\x0a\x49\x27"
        "\x30";
    const char EXPECTED_HASH[] =
        "\xe5\x37\x8c\x7c\x25\x1a\xe9\x6f\x03\x59\xa3\x0b"
        "\x31\x34\xfd\x77\xd6\x1d\x0d\xb6\x8c\x42\xa1\xa2"
        "\xaa\xc2\x93\x19\x5a\x59\x6d\xf4\x2f\x67\x7e\x6c"
        "\xb9\x8a\xbe\xc9\x0d\x67\x22\xba\xac\x63\xfc\x86";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 74.
 */
BEGIN_TEST_F(hash_74)
    const char INPUT[] =
        "\xbb\x32\x7a\x0b\xcb\x25\x74\xdf\x47\x08\x0e\x8c"
        "\x0d\x8a\x45\xee\x1c\x04\x24\xae\x04\x14\xdc\x0a"
        "\x9b\x87\x17\xd9\xf2\x7d\x8a\xc9\x87\xc7\xc9\xec"
        "\xbc\x94\x60\x73\x88\x4d\x1f\xb9\x6d\xbd\xb5\x83"
        "\xaa\x75\x81\x86\xb1\x6f\xa4\x29\xdb\xf1\x5b\x8d"
        "\x5b\xb4\x8c\xca\x71\x46\x9e\x7c\xe0\xad\x8e\x7f"
        "\xa1\x4d";
    const char EXPECTED_HASH[] =
        "\x0f\x75\xe6\x5f\xf8\x49\x4a\xe2\x8d\x9a\x0a\x2e"
        "\x65\x95\x96\x53\x27\x5f\xc3\x4b\x2f\xa2\x7b\x9e"
        "\x10\xfa\xaf\xff\x07\xc4\x5a\xdd\xef\x3b\x8f\x25"
        "\x95\x3d\x5a\x2e\x54\xe3\x1e\xbe\x6d\x42\x9d\x26";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 75.
 */
BEGIN_TEST_F(hash_75)
    const char INPUT[] =
        "\x7f\xd9\xee\xb5\xff\x36\x80\x40\xd2\x99\xfd\x17"
        "\xa9\x43\xb2\x1d\x65\xde\xb2\xec\xcf\x61\x28\xd1"
        "\x8a\x33\xeb\x17\x46\x93\x53\x89\x35\x37\x4c\x32"
        "\xc3\x33\xa8\x67\x82\x1d\xba\x08\x63\x6f\x20\x02"
        "\x2c\x2c\xe0\x18\x26\xc7\xb7\xe4\x16\x40\xad\x18"
        "\x6f\x90\xed\x0a\xc6\x47\xd4\x70\x86\x74\x48\x67"
        "\xe5\xc5\x4b";
    const char EXPECTED_HASH[] =
        "\x00\x72\x51\xa2\xa5\x77\xad\xd0\x48\xb1\xed\xc7"
        "\x9d\x96\xc7\xdf\x8f\xd5\xb5\xfa\x0d\x72\x64\xf1"
        "\x22\xe4\xcb\x54\xc5\x0b\xc3\x16\xa8\xbc\x5f\x4f"
        "\x9d\xfd\x44\x69\xe2\x9e\x9b\x03\x0f\x56\x3a\x6d";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 76.
 */
BEGIN_TEST_F(hash_76)
    const char INPUT[] =
        "\x7c\xa9\xe3\x69\xe8\x21\x86\x98\x4d\x5f\xc7\x29"
        "\xe1\x11\xa7\xe5\xd8\xec\x19\xc5\xd7\x4e\x13\xb5"
        "\xab\x22\xe4\x99\x3b\x05\xc8\x8e\xbb\xa6\xba\x72"
        "\x23\x73\x89\xa6\xe0\x72\x2e\x12\xc9\x6c\x5d\x6a"
        "\x54\x51\x5a\xb0\x0a\xd8\x0e\xfb\x38\x66\x5a\x76"
        "\xe8\x31\xab\xab\x0f\xa5\xcf\x02\x08\x07\x07\x84"
        "\x41\x58\x5d\xe5";
    const char EXPECTED_HASH[] =
        "\x3e\xe8\xc4\x18\x4d\xe9\xce\xae\xcd\x0d\x3a\xea"
        "\x16\x27\x18\x35\xf3\xd4\x5c\x87\x33\x58\xc9\x3a"
        "\x51\x55\x39\xc3\x8e\x81\x94\x14\xea\x63\xb0\x8d"
        "\x0a\x10\x93\x46\x79\x3d\x5e\x0f\x70\x31\x25\xeb";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 77.
 */
BEGIN_TEST_F(hash_77)
    const char INPUT[] =
        "\x5b\x4d\x94\x5d\x55\xde\xa2\x2e\x37\x82\x1e\xc3"
        "\x96\x47\x6a\x4b\xfb\x61\x7d\x2f\x39\x2a\xd9\x3a"
        "\xfe\x67\xbc\xfd\xa9\xcd\x9b\x72\x5b\xc4\xcc\xdf"
        "\x51\x6a\x83\xfd\x71\xdb\xff\x5a\x22\xb0\x05\xfc"
        "\x61\xc5\x8e\x47\x12\x40\xbd\x21\x93\xce\x13\x53"
        "\x97\x30\xe6\x32\x32\xf7\x0f\x80\x30\x8b\xe4\x8d"
        "\xab\x72\x66\xa1\xdd";
    const char EXPECTED_HASH[] =
        "\xdf\x82\xd2\x42\xe4\xcd\xc2\xeb\x40\xbf\x3d\xb6"
        "\xa5\x6e\x1a\xa0\xa6\x6e\x55\x3f\x19\x14\xbe\xdc"
        "\x65\xc8\xcc\x6a\xd9\x56\x4b\x6e\x85\xdf\x59\xf4"
        "\xc4\x43\xcb\xe4\xe0\xae\xe0\x59\x86\xf7\xd6\x90";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 78.
 */
BEGIN_TEST_F(hash_78)
    const char INPUT[] =
        "\xe8\x65\xf4\xa4\x2b\xbb\xd0\xb7\x3f\xe2\x75\xb8"
        "\xab\x90\xd3\xa9\xfb\x74\xec\x50\x70\x19\x2d\x38"
        "\xf6\x0e\xfe\xf9\x56\x44\x98\xb9\xad\xb7\x16\xf3"
        "\x1d\x50\xcf\x77\xc2\x0a\xe4\xb2\xe8\x55\x15\x30"
        "\x7b\xb8\xd9\x5f\xbe\xb9\xad\x96\x40\x01\xac\x55"
        "\x0d\xbc\x60\xcf\x21\x3f\xd8\xa5\x22\xed\xfa\xf5"
        "\x4e\x5b\x1b\x93\xb2\xb2";
    const char EXPECTED_HASH[] =
        "\x09\x1f\xa9\xae\x21\x84\xe2\x26\x8e\xf9\xef\x23"
        "\xc7\xc8\x09\xef\xad\x24\x45\x36\xe0\x0a\xa9\xe8"
        "\xb3\xa6\xc2\x28\xd9\x0e\x31\xda\x05\x1b\x40\xf2"
        "\x68\xa1\x3b\xd6\xf6\x2e\x69\xc9\x1a\xe8\xcd\x2d";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 79.
 */
BEGIN_TEST_F(hash_79)
    const char INPUT[] =
        "\x1d\x40\x8c\x7b\x68\xe1\x68\xf4\x1b\xb4\x6f\x9b"
        "\x2e\x9c\x8b\x04\xf9\x68\xe4\x08\x02\x52\x54\x68"
        "\x14\xcc\x1c\xb2\x91\x7d\xd5\x69\x08\x86\xa9\x60"
        "\x0a\x09\xc2\x67\x3a\xec\x03\x29\xa4\xda\xf6\x55"
        "\x50\x8b\x06\xfc\x16\x46\xef\x3b\xb3\xa4\x72\x19"
        "\x1d\x96\x4d\xb2\x14\xa9\x6a\x96\xfa\x89\x57\x6c"
        "\xe4\xc4\xf6\xdb\xf1\xd1\x76";
    const char EXPECTED_HASH[] =
        "\x7e\x23\x47\x2c\x03\x43\x19\x25\xf3\xb4\x55\x9d"
        "\x88\x6e\x8d\x5d\x83\x7b\x3d\x39\xb8\xef\xe1\xb7"
        "\xa9\x1e\x61\xa1\x38\x10\xc4\xdb\xc2\x43\x96\x34"
        "\xd7\xc6\xab\xab\xfc\x66\xe9\xb1\x8e\x65\x41\xdb";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 80.
 */
BEGIN_TEST_F(hash_80)
    const char INPUT[] =
        "\x54\xae\x03\x0a\x4e\x27\xa0\x5c\x1e\xa4\xa1\x2e"
        "\x69\xc6\x75\x44\xaf\x9b\x40\x44\xcf\x15\x7d\xc8"
        "\xce\xbb\xe8\xb2\xd4\x9f\x9b\xc0\x77\x90\x77\x60"
        "\x3c\x90\xc5\xc5\x5b\x89\x1d\x3a\xc3\x3b\x87\xb6"
        "\x5e\x79\xe1\xb1\x96\x95\x81\x37\x18\x19\x1b\x3b"
        "\xd8\xb7\xe4\x2d\x55\x83\xf7\xcf\x1e\x60\xf8\x44"
        "\x95\xb8\xf8\x69\xf3\x71\x99\x69";
    const char EXPECTED_HASH[] =
        "\xcb\x65\xf8\x23\x58\x57\x73\xcb\x88\x02\xb6\x33"
        "\x91\x82\xf1\x37\x52\xa8\x28\x64\xc8\x98\xb4\x45"
        "\xbe\x5a\x11\xa9\x69\x65\x7a\xc2\xdc\x4a\x3b\xbe"
        "\xb8\x7a\xc0\xab\xb2\x32\xa2\xb1\x24\x17\x10\x96";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 81.
 */
BEGIN_TEST_F(hash_81)
    const char INPUT[] =
        "\xf7\x3c\xd3\x86\xf7\x3d\x0c\x6a\xde\x05\x77\x1b"
        "\x33\x11\x71\x17\xc6\x02\xe5\x26\x93\xf0\x5b\x47"
        "\xe9\x00\x32\xea\xcc\x39\x29\x5f\x97\x93\x25\x8f"
        "\xe6\x51\x2e\xea\xb2\x91\xba\xa0\xbe\x22\x2e\x14"
        "\x32\x95\xa2\x8e\x86\x97\xe4\x2f\xa2\x7e\xc0\x2b"
        "\x44\x21\x7f\x32\xa1\xed\xae\x2f\x4f\x35\x21\x35"
        "\x62\xca\x37\xb6\xd6\xcc\x5e\xf7\x2d";
    const char EXPECTED_HASH[] =
        "\xf6\x65\xc4\xd1\x7a\x83\xd6\x5a\x7f\xf1\x6b\xfc"
        "\xe2\x79\xb5\x85\x58\x25\x0d\x76\xaf\x68\xb8\xeb"
        "\x94\x37\x53\xe4\x11\xa5\x7c\xeb\x31\xc1\xa1\x31"
        "\xe5\x4b\xcb\x76\x72\x58\x44\x16\xe3\xd5\x71\x9e";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 82.
 */
BEGIN_TEST_F(hash_82)
    const char INPUT[] =
        "\x1d\x25\x96\x12\xe6\x86\x7e\x7d\x78\x8c\x71\xd0"
        "\x3c\x51\x36\x86\x4a\xd6\xd8\x4f\x24\xea\xf9\x13"
        "\xa3\x4e\x69\x33\x31\x16\xf8\x12\x39\x52\x88\xd4"
        "\xdc\xee\x66\x65\xe6\xd7\xda\xbd\x00\x5f\xfc\x63"
        "\x27\xe3\xca\x30\x5c\xab\x78\x56\x9d\x11\x07\xa1"
        "\x15\xe6\x19\xfc\x90\x11\x04\x36\x31\x79\x25\x06"
        "\x67\x26\x77\x4d\x1d\xa3\x63\x9c\x31\xa6";
    const char EXPECTED_HASH[] =
        "\x5d\xcf\x51\x2e\x2b\x93\xd6\xec\xdf\x7c\x33\x04"
        "\x53\x45\x54\xea\x79\xd2\x23\x92\xe5\x9b\xbe\x90"
        "\xdf\x21\xe9\x78\xc9\xfa\x3b\x34\xff\x82\xe6\xdc"
        "\xfe\x8f\xe2\x23\x6a\xa4\xaf\x4e\x66\x2e\x2a\x9d";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 83.
 */
BEGIN_TEST_F(hash_83)
    const char INPUT[] =
        "\xda\x87\x34\x41\x4c\x45\xfc\x1d\x5a\x75\xa3\xcb"
        "\xac\xad\xb1\xbf\xb5\x23\xd6\xfc\x39\x1f\x88\x2d"
        "\x0d\xb0\xee\xf2\x1f\x9f\xfd\x78\xb6\xa1\xe1\x4c"
        "\xfa\xd0\x9e\x71\xb6\x5c\xf7\xb0\x5d\x7e\x8f\x2f"
        "\x4b\xae\x4e\x45\x4e\x16\x06\x8d\x65\x46\x56\x39"
        "\xc7\x29\xcf\xa9\x27\x38\x56\x3d\x37\xed\xc9\x67"
        "\x6b\x7b\xe6\x04\xff\xbc\x68\xec\x3b\x6b\x72";
    const char EXPECTED_HASH[] =
        "\x8b\x32\x8a\x31\xad\xf6\x7d\xc7\xae\xb8\x64\xa3"
        "\x59\x62\x84\x10\xd5\x81\x4a\x2f\x0c\xc6\x83\x30"
        "\x3f\x61\x43\x2c\xe3\x21\x77\xe1\xf5\x38\xfe\xea"
        "\xd7\xe5\x00\x03\x43\x91\x6c\x70\x42\xf8\xb3\xcd";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 84.
 */
BEGIN_TEST_F(hash_84)
    const char INPUT[] =
        "\xb2\x28\xc7\x59\x03\xd8\x0f\xbc\x6d\x1c\xf6\x29"
        "\xff\x1d\x14\xa9\x2e\xc4\xbf\x0e\x12\x1f\xd9\x7b"
        "\xd3\x06\xed\x26\x5e\xfe\x7a\x5d\x5c\x5d\x8f\xc7"
        "\x64\xaf\x98\xed\x6f\x59\x78\xf8\x8d\x7c\xd8\xbc"
        "\xd7\x1c\xbe\xf6\xa5\x82\x61\xd2\x01\xde\x3c\xb1"
        "\x5b\x31\x61\x28\x7e\x6a\x10\x4c\xc2\xcf\x88\x2d"
        "\x83\x9f\x1d\xa0\xd3\xf6\x8b\x42\x6c\xf0\x8a\xb9";
    const char EXPECTED_HASH[] =
        "\xfc\x92\xba\x4e\xac\x9a\x1b\xf1\x20\xa7\xb6\xc2"
        "\xcc\x30\x33\x5b\x96\x15\xb1\xa9\x8e\x55\xd1\x48"
        "\x54\xff\x87\x29\x66\xe7\x10\x40\x73\x74\x01\xc6"
        "\xbc\x08\xdb\x58\x42\xce\xac\xe1\x4c\xb7\xe7\xea";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 85.
 */
BEGIN_TEST_F(hash_85)
    const char INPUT[] =
        "\xc9\x0d\x47\x3a\x6f\xd3\x0b\xe9\xa9\x8b\xf4\x42"
        "\xa9\xad\x65\xa6\x97\xd4\x62\x9c\x33\xcd\x51\x7d"
        "\xbb\xed\x02\x71\x0f\xa8\xee\x99\x13\x60\xbc\x8e"
        "\x55\x7b\x0a\x0b\xf0\xb8\x69\xe6\xb0\xc3\xa9\x45"
        "\x76\x07\x58\x0e\xde\xc3\x85\x9f\x20\x60\xc9\xc0"
        "\x34\x02\x89\xd5\x3a\x5d\x75\x59\x18\xca\x54\x87"
        "\x65\x99\x04\x5a\x86\xa9\xbc\xb8\x16\x37\x95\xea"
        "\x8c";
    const char EXPECTED_HASH[] =
        "\x80\x75\x82\xb2\x52\x0e\x99\x0c\xfb\x74\x36\x73"
        "\x43\x26\x8b\x91\x48\xb2\x51\x9b\x9e\x7c\xd9\x18"
        "\x2e\xdb\x3d\xb9\xae\x7a\xfe\xbe\xdf\xe8\xca\x11"
        "\x81\x30\xe2\xef\x9d\x31\xaf\x90\x81\xda\x82\x22";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 86.
 */
BEGIN_TEST_F(hash_86)
    const char INPUT[] =
        "\x6d\xf8\xc5\xc2\x8d\x17\x28\x97\x5a\x0b\x76\x6c"
        "\xd7\xde\x63\xbb\xe7\xf4\x8c\x3d\xb3\xe6\xfd\x5a"
        "\x4b\x8d\xf6\xe3\x90\x5c\xef\x03\x51\xf3\xd9\x73"
        "\xb4\xf2\xa7\xee\xd8\x0b\x0d\xe5\xb8\x5c\x87\x73"
        "\x53\xfb\x9e\x93\x0a\xd2\x67\x91\x49\xad\x4c\xbe"
        "\x69\x91\x0e\x68\xd5\x50\x0b\x09\x6c\x5a\xbd\xbf"
        "\x27\xd6\x84\xfc\xfc\xf1\xa5\x7f\x02\x76\x92\x83"
        "\xd5\xa0";
    const char EXPECTED_HASH[] =
        "\x7b\xda\x57\xd2\x1a\x44\x34\xaa\xda\x67\x58\xe2"
        "\x82\xe6\x12\xa4\xc0\xf4\x1b\x24\x2f\x9c\x79\x08"
        "\x04\xd5\xbe\xe2\x5b\x81\xa8\x21\xdc\x6f\x2a\x0b"
        "\xa5\x6f\x1b\x37\x04\x80\x2c\x9a\x6e\x15\x3d\x85";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 87.
 */
BEGIN_TEST_F(hash_87)
    const char INPUT[] =
        "\x2c\xfc\x76\xf8\x8c\xb6\xfb\x90\x92\x7b\x69\x52"
        "\x6a\xd5\xf0\x3d\x6b\xd3\x35\xf4\xf7\x5b\x52\xb6"
        "\xa3\xc2\x1e\x8f\x98\x9a\xb0\xd0\x3a\xcb\x1e\xbe"
        "\x07\xe6\x8a\x87\xc1\xb5\x60\x7a\xcf\x17\xd9\x76"
        "\xe1\x0a\xc4\xa3\xd3\x0a\x85\x61\xd4\x9a\x5e\x7e"
        "\xc7\x20\xed\xac\xe9\xf5\xf6\x32\xb4\xbd\x63\xe1"
        "\x04\xf4\x89\x4a\x79\xca\xad\x2e\x1c\x31\xc7\x36"
        "\x45\x34\x85";
    const char EXPECTED_HASH[] =
        "\xe1\x66\x70\xea\x83\x7c\x25\x9e\x41\x8d\x3c\x0e"
        "\x1e\xaa\xd4\x94\x8c\x34\x57\xe1\x5b\x15\x73\x05"
        "\x6e\x24\xda\x25\xbf\xf5\xc6\x6b\x7e\x95\xd2\x4c"
        "\x6b\xc1\xb8\xd6\xc2\xb8\x12\xf6\x4a\xdc\x95\x53";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 88.
 */
BEGIN_TEST_F(hash_88)
    const char INPUT[] =
        "\x3f\x05\x10\x8c\x2f\x33\xd3\x9b\x3a\xa9\xe7\x3e"
        "\xfb\xad\x4b\x01\x1b\x4e\x9e\x9f\xba\x40\x9b\x76"
        "\x11\xe7\xe0\x39\x56\xb2\xf3\xe5\xe0\xaa\x86\xf6"
        "\x8c\x4b\xfa\xda\x5f\x92\x23\xa6\x6d\x57\x4b\x08"
        "\xf9\xdd\x79\x7c\xdd\xa8\xf3\xc3\x2d\x8e\x01\x92"
        "\x17\x11\xf4\x87\x0d\xec\x67\x60\x27\xec\xc5\x6f"
        "\xc2\x01\x0b\x49\x6e\x95\xcf\xbf\x07\x1c\x82\x0f"
        "\x21\xed\xf2\x5b";
    const char EXPECTED_HASH[] =
        "\xb2\x72\xba\xb6\x80\xf3\xab\x27\xde\x72\xd9\x4d"
        "\xf3\x84\x32\x3f\x85\x55\xf1\xd1\x7f\xac\xd2\x58"
        "\x8a\xc8\x64\x8d\xef\x24\x51\xf8\x2f\x9b\x99\xc0"
        "\x5e\xad\x83\x16\xfd\x18\x1a\x2c\xfb\x97\x48\x3a";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 89.
 */
BEGIN_TEST_F(hash_89)
    const char INPUT[] =
        "\x1f\xfb\xe1\xaf\xf0\xa1\xe7\xfa\x3e\x68\xbe\x31"
        "\xa7\x46\x12\xa1\x51\x9b\x59\x39\x7e\x70\x07\xef"
        "\x61\xfc\x01\x5f\x31\x6d\x55\xb5\x7b\xe5\x28\xce"
        "\xbc\xc2\xf0\x9a\x2f\x22\xe3\xc5\xe4\xa6\xae\x96"
        "\x12\x77\x6b\x17\xae\x87\xcd\x76\x3c\x1a\x9e\xab"
        "\xe6\x84\x6c\x5b\xcb\x34\x7f\xfc\x99\xf1\x0e\x3b"
        "\x5e\x64\xb2\x9a\x9b\xd7\x1a\x5e\x9b\x3c\x01\xa8"
        "\x02\x71\x5d\xe2\xa9";
    const char EXPECTED_HASH[] =
        "\xf0\x8b\xda\x9d\x67\x62\x60\x75\x19\xd5\x3f\xec"
        "\xb0\xbf\xfb\xfd\x3f\xf2\x92\x48\x54\x83\x3a\x75"
        "\x9d\x63\x1e\x91\x0c\x42\xca\x86\x74\x1f\xc2\xe2"
        "\x90\xaf\x42\xe9\x4b\x94\x89\x86\x09\xb9\x13\x90";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 90.
 */
BEGIN_TEST_F(hash_90)
    const char INPUT[] =
        "\xf7\x55\xd6\xb5\x64\x23\x78\xf2\x84\x78\x93\x90"
        "\x1d\x9a\xa9\x1c\x54\xa4\xb7\xab\xb9\x7c\x5c\x71"
        "\x84\x06\x3e\x8f\x1e\x97\xaa\x2d\xe4\xad\x7a\xc9"
        "\x27\xdd\x3c\xce\x77\x0c\x90\x69\x21\xe2\xd2\x98"
        "\xf6\x7c\xf9\x84\x4e\x61\xbf\x10\x4d\xb8\x03\xb2"
        "\x65\xb8\x6b\x82\x1c\x5f\x4d\x90\x10\x67\xd0\x7b"
        "\x38\x76\x4e\x3f\x6c\x95\xfd\x4f\x28\xe3\xcf\xe4"
        "\x8d\x8a\x96\x94\xa8\xf3";
    const char EXPECTED_HASH[] =
        "\xf8\x5e\x98\xea\x05\x44\x55\x24\x22\x80\x85\x4e"
        "\x97\xc4\xed\x39\x9b\x85\xee\x7b\xc5\xc5\xfc\x3d"
        "\x62\x91\x0a\x76\xf3\xa9\x60\x0c\x3d\x90\x4c\x83"
        "\x2b\x70\xb5\x8d\x7d\x99\x8d\xb8\xdc\x97\x81\x35";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 91.
 */
BEGIN_TEST_F(hash_91)
    const char INPUT[] =
        "\x77\x35\x77\xf3\xa6\x42\xc4\xf1\x3b\x1c\xb1\xf4"
        "\x10\x3e\x9f\x6b\x2d\xa8\x62\x68\xa5\x2f\x44\x9c"
        "\xbb\x17\x4c\x83\x49\xe3\xc0\xdc\x63\x6c\xe8\x5c"
        "\x37\x31\x15\xa3\x37\xee\xe2\x6f\x7b\x70\xba\x10"
        "\x60\xa7\x9a\x1c\x76\xfd\x18\x63\x99\xe6\xa5\x25"
        "\x5d\xb8\x0f\x83\xb0\xbe\x4a\x34\xba\x87\x6f\x79"
        "\x08\x84\x05\x53\xea\xd3\x80\xf3\x19\x55\x07\x72"
        "\x9d\x06\x7a\xc2\xee\x8e\xb4";
    const char EXPECTED_HASH[] =
        "\xcc\x27\x86\x9c\xd7\xe6\x36\x95\xd1\x90\x82\x44"
        "\x6b\x06\x8b\x77\xdd\xe4\xe8\x60\x4f\x8c\x0e\x9c"
        "\xe2\x0a\x1b\x71\xaa\x9e\xff\x14\x60\xf3\x2d\x5a"
        "\x54\x47\x62\x75\xbd\xee\x8e\x76\x21\x49\x1f\x46";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 92.
 */
BEGIN_TEST_F(hash_92)
    const char INPUT[] =
        "\x65\x15\x89\x92\x7e\x17\xe1\xae\xf7\x80\x69\x0f"
        "\x31\x00\xa3\x77\xf0\x17\x9b\x18\xb3\x1f\xd5\xb4"
        "\x41\x8c\x84\x03\x85\x73\xfc\x55\x9b\x49\x6a\x78"
        "\x2b\xee\xc3\xdc\xf6\xe9\xfa\xf5\xae\xf6\x76\xe1"
        "\x0b\xbe\xc3\x4b\x1b\xe5\x88\x8f\xda\x49\xb9\x1e"
        "\x02\x89\x0d\x25\x24\xc5\xb3\x69\xf8\xa5\x41\x75"
        "\xf2\x9d\xed\xf8\x15\x6f\xff\x69\x0c\xf1\x86\xec"
        "\x77\x10\x4a\x79\x83\x15\x03\x3b";
    const char EXPECTED_HASH[] =
        "\xda\x84\x60\x42\xfb\x90\x8e\xee\x5f\x5d\xef\xd1"
        "\x05\x5f\xf3\xe5\x71\x03\x70\x82\x78\xd3\x79\xa8"
        "\x68\x1f\x58\xbe\xdc\x6e\xf8\x96\x70\xb9\xf9\x57"
        "\xc4\xe0\xed\xca\xa4\x2d\xfd\x8c\xd4\x9d\xf6\xea";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 93.
 */
BEGIN_TEST_F(hash_93)
    const char INPUT[] =
        "\x67\x86\x52\x60\x0e\xee\x42\x58\x0f\x73\x62\x34"
        "\x12\xe9\xc0\x11\xcc\x02\xde\xc4\xd4\xcc\x1b\x79"
        "\xb2\x7b\x6f\x99\x39\x69\x5b\xf2\x18\x5b\x20\x12"
        "\xab\x06\x30\xf3\x17\xd2\xe2\xde\x95\xdd\x69\x89"
        "\x0e\x43\x07\x83\xe9\x9d\x7e\xd1\x21\xc7\xc8\xda"
        "\x9a\xe7\x07\x80\xb5\xaa\xbf\x90\x22\xd1\x43\x5c"
        "\xf5\xed\x6d\xa6\xfc\x66\x92\xc0\x50\xc2\xb5\xf2"
        "\x2b\x24\xfb\x1c\xf9\x13\x5f\x9c\xb2";
    const char EXPECTED_HASH[] =
        "\x8a\x6a\xe4\x1c\x9b\xcc\xc1\x6e\xac\x48\x60\xbd"
        "\x5f\xa9\x12\x05\xa8\x6f\xbf\xd0\x96\x92\x57\x8f"
        "\x7f\x36\xb3\xc1\x35\xd9\x6f\x9e\x90\x01\xc1\x92"
        "\xdb\xed\xa9\x75\xf7\x37\x5b\xd4\x3a\x23\xba\x68";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 94.
 */
BEGIN_TEST_F(hash_94)
    const char INPUT[] =
        "\x41\x6d\x3f\xb7\xb4\x01\xfa\x5e\x78\xcd\x96\xd4"
        "\x79\xd8\x86\x0d\xf1\x47\xee\xf0\x3a\xdf\x13\xfc"
        "\xe1\xc6\x11\x31\xfb\x89\xcc\x2e\xbc\x63\x28\x97"
        "\x45\xbd\x7d\xb9\xbe\xf1\x45\x71\xa5\x53\x18\x49"
        "\x65\x72\xdb\xe5\x2b\x9b\x34\x9e\xf5\x9f\x40\x6c"
        "\xec\xd6\x89\x09\xf3\x64\x32\x53\x80\xbb\x75\xf3"
        "\xaa\x62\x50\x3c\x84\xf4\x7a\x55\xaa\x6b\x9c\x9b"
        "\x19\x9e\xbe\x41\x44\x09\xff\x39\x64\xcd";
    const char EXPECTED_HASH[] =
        "\xc5\xf2\x05\x42\xe0\xc0\xac\x1e\xb4\x33\xde\x62"
        "\x29\xfe\x5b\xac\xcf\xd4\x50\x2e\x2c\x22\x75\x43"
        "\x93\x85\xef\xda\x63\x74\xa1\xd0\xfc\x50\xcd\x9b"
        "\xba\x42\x33\xd4\x70\xad\x91\xa3\x35\x6e\xa3\x15";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 95.
 */
BEGIN_TEST_F(hash_95)
    const char INPUT[] =
        "\x6f\x09\xe8\x76\xc0\xb8\x3c\x99\x34\xff\xb7\x77"
        "\xf0\x06\x33\x8c\x51\x42\xa3\x13\x75\xe9\xb2\x1c"
        "\xfe\xa9\xa7\xde\x12\x99\x8c\x4e\xa6\x70\x8f\xf1"
        "\xfd\xf5\xa8\xee\x6b\xb6\x7c\x67\x5f\xfd\x82\x09"
        "\xa1\x00\x64\xe2\xd7\x58\xa8\x73\x4e\xb4\x8f\x07"
        "\xf7\xcf\x3d\x43\xb0\x9f\x1b\xfd\xc5\xd0\x7a\x52"
        "\xb7\x70\x79\xf2\x3c\xec\x28\xbf\x86\x3b\xed\x97"
        "\xc8\x59\x27\x6d\xf7\xf7\x12\x9f\xce\x71\xeb";
    const char EXPECTED_HASH[] =
        "\xb3\xc9\x68\xf3\x02\x5f\x87\xdb\xd5\xcd\x3d\x36"
        "\x4b\xf6\x73\xe6\x28\x27\xc3\x58\x89\x53\x24\x31"
        "\xbe\xcd\x87\xcf\xbe\x2c\xc7\x5b\x7e\xf4\x56\x96"
        "\xd1\x9c\xd3\x45\x2d\x0e\x7c\x2b\x69\xd0\x95\x44";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 96.
 */
BEGIN_TEST_F(hash_96)
    const char INPUT[] =
        "\x0d\xc2\xb2\x26\xb3\x43\x1c\x69\xa7\x6a\xdd\xc0"
        "\x18\xfc\xbd\xa2\x2b\xd7\x2c\x8f\xf0\x1e\xd6\x54"
        "\x95\x96\x79\x8b\xd9\x50\xf3\x61\xc4\x89\xa0\x9c"
        "\x95\xce\xe2\xdc\xfd\x64\x01\x20\x8a\xe6\x36\x8d"
        "\x66\x30\x02\x6b\x41\x7c\xc4\x71\x8c\xcb\x8b\x42"
        "\xe8\x87\x29\x37\xde\x66\x89\x5f\xd0\x91\x42\xc4"
        "\x2f\x06\x6b\xf0\xef\x3a\xb2\xb0\x38\x03\xa8\x18"
        "\x5f\xb6\x5f\xc7\x14\x8c\x37\x6d\xdd\x4b\xf5\x8a";
    const char EXPECTED_HASH[] =
        "\xaa\x64\x5a\x4f\x8f\x60\x24\x11\x26\x0a\xce\x24"
        "\xd3\x81\xf3\xf5\xdf\xf0\x00\x0c\x24\x63\x43\xeb"
        "\x52\x8e\x3d\xd0\x27\xcd\x74\x38\x15\x73\x79\x06"
        "\xac\x5c\x74\xea\x83\xc2\x75\x5e\x56\xb9\x95\x09";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 97.
 */
BEGIN_TEST_F(hash_97)
    const char INPUT[] =
        "\x8d\xc7\x1c\x84\xc8\x77\x27\x53\xc8\x6a\xb6\xaf"
        "\xd8\x0e\x8d\x1d\xf9\xb0\xd7\xe8\xd6\x9e\xbe\x67"
        "\xfa\x88\x3a\x82\x41\x2c\x26\x73\x8c\x33\x99\xca"
        "\xb9\x55\x73\xb4\xd3\xc4\x36\x7c\x85\xc8\x18\x52"
        "\xd5\xa6\x56\x4c\x0f\xc7\xca\xaa\xfe\x16\xc0\x5e"
        "\x62\xaa\x06\xcc\x9f\xa5\x42\xce\xb3\x5c\x88\xfb"
        "\x6a\xb8\x2c\x29\xd5\xdc\xd5\x30\xf8\x07\xd3\xf1"
        "\xc3\xbc\xb3\x97\x44\x21\x10\x1d\x1a\xa6\xac\x11"
        "\x2d";
    const char EXPECTED_HASH[] =
        "\x12\x23\x98\x13\x09\x71\x24\xe6\x24\x8e\x7d\xbe"
        "\xc9\x85\xa6\xa2\x5f\x62\x2b\x1d\x07\x29\x5c\xfc"
        "\xfb\xaf\xf3\x3b\x84\x7d\xf7\xfd\x94\x26\x5e\x43"
        "\x9f\xa5\x35\xf3\xbe\xcb\xdb\x57\x69\x22\xac\x41";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 98.
 */
BEGIN_TEST_F(hash_98)
    const char INPUT[] =
        "\x3d\xf3\xed\xd9\xfc\x93\xbe\x99\x60\xb5\xa6\x32"
        "\xe2\x84\x7b\x30\xb1\x01\x87\xc8\xf8\x3d\xe5\xb4"
        "\x5f\xcb\x2e\x3e\xd4\x75\x56\x9a\x8b\x2e\xd0\x78"
        "\x43\x48\xf9\xda\xcc\xe7\xb3\x23\xc6\xb6\x50\x71"
        "\xab\xd8\xb3\x2d\x10\x22\xb1\xe1\x27\x87\xbd\x49"
        "\x89\xd3\xc5\xac\x32\x9d\x57\x6c\xcd\x76\x08\xdd"
        "\x33\x67\x16\x53\x2e\x9b\x4c\x7f\x82\x58\x26\xfb"
        "\x2e\x34\x36\x23\xef\x85\xc6\x27\x06\x19\xbf\x5e"
        "\x3b\x27";
    const char EXPECTED_HASH[] =
        "\xf3\x65\x90\xf5\x21\x1a\x9c\xf8\x4e\xeb\x0a\x3b"
        "\x2e\x5d\xc1\x16\x4e\x81\x31\x91\xcd\xa7\xcb\x88"
        "\x3f\x3f\x4a\x07\x46\x05\xce\x67\x80\xcf\x2f\x1a"
        "\x10\x56\x58\x70\x6f\xbd\x28\x29\xdb\x8a\x2a\x58";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 99.
 */
BEGIN_TEST_F(hash_99)
    const char INPUT[] =
        "\xce\xd0\xec\x65\x00\xcb\x89\x1e\x64\x33\xd1\x04"
        "\xba\x5b\x1c\x1e\xbc\xa3\x97\xf3\xa5\xee\xea\xa0"
        "\xf0\x56\x17\x29\x62\x1e\xa5\x0d\x4a\xe7\xff\x1d"
        "\x08\x27\x17\x8d\xcc\xd8\x4e\x4c\xa0\x6d\x98\x91"
        "\xa9\x0a\xdb\xb7\xa9\xf4\x99\x4a\xc9\x47\xcf\x62"
        "\x96\xe7\x1d\x2f\x49\xb8\x26\xd6\x4b\x12\x3a\x7b"
        "\xf8\x6f\x33\x9f\xa4\x67\x9c\xad\xdb\xdf\x19\xcf"
        "\xed\x7d\x02\x06\xaa\x5f\x52\x7a\x6b\x0c\xc0\x0f"
        "\x52\xaa\x2b";
    const char EXPECTED_HASH[] =
        "\xc2\xc2\xd7\xd6\x5d\x0b\x91\x08\x64\x8e\x32\x33"
        "\xd1\x5f\xc4\xe4\xcb\x62\xed\x8f\xee\x9c\xdd\x18"
        "\xab\x44\xb8\x48\x6e\x21\x00\xfb\xe4\x5d\xdc\xf7"
        "\x4f\x46\xc1\x5e\xb7\x7f\xb1\xc8\x93\xc1\x22\x02";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 100.
 */
BEGIN_TEST_F(hash_100)
    const char INPUT[] =
        "\xaf\xa4\xa2\xc4\xfb\xaf\xfe\x83\x8d\xd1\x49\xc7"
        "\x8e\xa7\x85\x1e\xa9\x39\x63\x04\xb4\x18\x06\xa0"
        "\x93\xa9\x0a\xae\x59\xc0\xc5\xbd\xb1\x70\xcc\x9a"
        "\x7d\x22\xb9\x0c\xbc\xe5\x2c\xc1\xb1\x05\x10\x89"
        "\x42\xdf\x20\xc2\x9e\xf3\xa9\x13\x22\x3b\x91\x5e"
        "\x7e\xbc\x98\xef\x13\x5a\xde\xfa\xa0\xf0\xa6\x44"
        "\x1e\xa0\x59\x20\xe8\x68\xce\x9d\x1f\xf6\xc8\xfe"
        "\x4d\xbe\xc0\x6a\x48\x49\xe5\xe5\x5a\xd0\x62\x7f"
        "\x9e\x09\xdf\xcb";
    const char EXPECTED_HASH[] =
        "\xcf\x6e\xf9\x1d\x85\x67\x41\x4f\x5c\x7f\x0b\x1f"
        "\x4a\xd0\x9a\x97\x6a\xfc\x7c\x83\x27\xa3\x82\xfc"
        "\xa9\x0f\x5a\x13\x6b\x19\xbe\x33\x10\x0a\x66\x43"
        "\x90\xa3\x77\xf8\xd8\xa3\x01\x5f\xb8\x82\x12\x5b";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 101.
 */
BEGIN_TEST_F(hash_101)
    const char INPUT[] =
        "\x00\xf6\x5a\x48\x5b\xfd\x38\x11\x13\xd6\xe7\x9b"
        "\xf9\xe0\xd5\xe5\x18\xc8\x91\x98\x8c\x07\x3b\xa1"
        "\x98\xac\x3a\x20\xf2\x5c\x2c\x81\x61\x97\x23\xe8"
        "\x8a\x3c\x0e\xd3\x07\x50\x75\xfb\xba\xfb\x6a\x7b"
        "\x61\xd3\xbc\x33\x6a\x5e\x6d\x6f\x08\xd1\x66\xc4"
        "\x86\x1e\x6a\x3b\xdc\x2e\x49\xb2\x80\x6b\x56\x7e"
        "\x7e\x82\x1a\x55\xcb\x67\x4a\x6c\xd6\x99\xf7\xdc"
        "\x61\xa7\x05\x4a\x8f\xf3\xde\xc7\x3e\xb6\x67\xf5"
        "\x96\x44\x34\x6b\xe2";
    const char EXPECTED_HASH[] =
        "\x80\x9c\x6b\x5d\x41\xda\x7c\xd1\x0d\xf9\x0b\x02"
        "\xb1\x93\xac\x7d\x40\xcf\x2e\x46\xc1\x39\xe9\xdb"
        "\xd2\x08\xa9\x88\xda\x2b\x25\x00\x2c\xdb\xad\x1d"
        "\xb2\xec\xc1\x32\x2d\xa2\x0b\x7d\x05\x4e\x5f\xe6";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 102.
 */
BEGIN_TEST_F(hash_102)
    const char INPUT[] =
        "\xb9\xce\x38\x2e\x1e\x82\xa8\x73\xcc\x44\x42\x48"
        "\xa3\x00\x8c\x2c\xf6\x4d\x18\x75\x90\x57\xab\xe8"
        "\xf9\x1c\x9d\x87\xf5\xdc\x83\xaa\x4e\xca\x0c\x51"
        "\xd3\x08\x29\xb9\xa1\xd2\x71\x2d\xa1\xfa\xc3\x1f"
        "\x52\x94\x2d\x77\xc9\xf2\x0c\x2b\xf6\xd3\x75\x10"
        "\x28\xd7\xd4\xf0\xd3\x36\xd3\xdc\x92\xb2\x7e\xc3"
        "\x68\xca\xa4\x44\x4b\x31\x80\xc1\xe3\x7e\x98\xb5"
        "\x8f\x25\xe6\x47\xa9\xa6\x36\x1f\x0b\x04\xcf\x78"
        "\xd1\x79\x55\x76\x61\x68";
    const char EXPECTED_HASH[] =
        "\x18\xcd\x10\xb3\xea\x90\x7b\x37\x70\xe8\xeb\x91"
        "\xc9\x74\x66\x6e\x2d\xa2\x52\x5a\xfe\x70\x20\xb8"
        "\x72\xb3\xec\x66\x89\xe5\xe1\xcd\x00\x59\xdd\x4f"
        "\xd4\x9c\xe4\x4d\x75\xdc\x4c\x84\x30\xc3\x22\xd6";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 103.
 */
BEGIN_TEST_F(hash_103)
    const char INPUT[] =
        "\x67\x78\xd8\x2f\x3a\x98\xee\xcd\xfa\xc5\x5d\xde"
        "\xeb\xc5\x24\x76\xa0\x70\x09\x4f\xbd\x65\x83\x18"
        "\x01\xfd\xd6\x0f\x83\x7d\x80\xd2\x3b\x90\xd4\x72"
        "\xc5\xf4\xe5\xca\x62\x73\xa5\x0f\x40\x15\x4e\xa8"
        "\xfb\x94\x01\x3f\x63\x10\xad\x18\x80\x04\x33\xa1"
        "\xd3\x79\xc8\x4b\xdf\x79\x9a\x99\xe8\xc7\xb6\x76"
        "\xfb\xcd\x29\xcc\x2e\xd6\x65\x52\x29\x7d\xe7\xa6"
        "\xe5\x65\x17\x9b\xb4\x2b\x70\xd4\x82\x99\xe0\x92"
        "\x5a\x1d\x72\xca\x2c\x79\x2a";
    const char EXPECTED_HASH[] =
        "\x71\xf0\x8d\x93\x33\xdf\x5c\xb8\x85\xfd\x23\xd6"
        "\xcb\xb1\xdb\x84\xf9\xb5\x59\x08\xd0\x69\xdf\x50"
        "\xfa\x47\x95\xcc\x71\x3a\x18\x43\x9b\xca\xb8\xda"
        "\xca\x07\x83\x56\xf5\xc7\x5a\x61\x9f\x2f\x87\x82";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 104.
 */
BEGIN_TEST_F(hash_104)
    const char INPUT[] =
        "\xba\x3a\x54\xa7\x7d\x7c\x2b\x8c\xce\xc6\xd5\x31"
        "\x36\xcd\x48\x82\x7c\x87\xac\xdd\x1c\xd8\x6a\xd1"
        "\xf5\x6e\x86\x26\x42\xea\x2e\x1d\xcb\x40\x93\xf8"
        "\x5d\x60\xf7\xbd\x77\x16\x07\x38\x46\x2e\x6c\x3f"
        "\xd3\xdd\x9d\x3a\x7c\x5c\xf7\xe2\xa1\xd6\x0f\x48"
        "\x9f\x84\x47\x19\x02\x17\x9f\x21\xf6\x56\xce\x0f"
        "\xff\x08\x92\x78\xea\x14\x44\x1e\x04\xe7\xaf\x71"
        "\x89\x16\x22\x56\x5f\x44\xc4\x28\x04\x47\x28\xfc"
        "\xc6\x86\x21\x2a\x32\xa5\xd8\x09";
    const char EXPECTED_HASH[] =
        "\x3c\xc1\x54\xf0\x54\x2d\x8e\x3c\xac\xf9\xd7\x9f"
        "\x23\x14\x16\x81\x61\x78\xa7\xef\x22\x75\xfb\x25"
        "\x7a\x48\xa2\xf7\x63\xff\xa2\xe1\x5a\x33\xc2\x7b"
        "\x97\x0a\x41\x6a\x05\x79\x25\xaa\x04\x12\xd2\x68";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 105.
 */
BEGIN_TEST_F(hash_105)
    const char INPUT[] =
        "\x7e\xec\x4f\x4f\x49\x1b\x4e\xea\xeb\x1c\xdb\xdb"
        "\x95\xe9\x51\x1c\x28\x72\x37\x2b\xf6\x4a\x1f\x61"
        "\xcd\xa1\xcd\x80\x32\x72\x9c\x8b\xea\xfd\x1e\xda"
        "\xbf\x78\x03\x6d\x80\x02\x3c\x81\x4a\xd8\x60\x61"
        "\x06\xcb\x4e\x7f\x33\xf2\x14\xc3\xe6\x9c\x0f\x23"
        "\x0e\x88\x54\x74\xfd\x59\x4f\x7f\x24\x44\xaa\x58"
        "\x1e\x0c\x70\xeb\xf1\x30\x73\xd8\x90\x63\xeb\x81"
        "\xa4\x3c\x5f\x60\x8b\x2f\xc9\x9f\xa1\xbc\xf5\xe2"
        "\xbf\xe6\x2a\x68\x02\xe7\x0c\x52\xce";
    const char EXPECTED_HASH[] =
        "\x2f\x8c\x56\x82\xa0\x74\x38\x04\x3e\x55\xf0\xb7"
        "\x75\x9f\xe7\xee\xa5\xd9\xbd\xfc\x8b\x0f\x89\x80"
        "\x0e\xbc\xf7\x77\xbc\x05\xa9\x41\xea\x7f\x3c\xac"
        "\x45\xd4\x65\x9d\xe0\xf5\x05\xd8\x14\x59\x0b\x6b";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 106.
 */
BEGIN_TEST_F(hash_106)
    const char INPUT[] =
        "\xf3\x71\x5b\x9e\x3d\xdd\x78\x62\xe1\x5e\xe8\x7a"
        "\xa2\x3f\x1a\xaa\x05\x80\x59\x1e\x55\xcf\xf3\xfe"
        "\xe9\xb4\x9b\x42\xaa\x0c\x0c\xc8\xcf\xb8\xef\xa3"
        "\xeb\x96\xff\xb7\x2a\xb0\x6b\x83\xd7\xb4\x7b\x3d"
        "\x22\xa5\x77\x24\x21\xcf\xc5\x12\x14\x00\x51\x50"
        "\xed\xf5\x32\xaf\x10\x13\x8a\xd4\x57\x58\xad\xd4"
        "\x59\x90\x86\x01\xec\xcc\x37\x03\xe8\x10\x00\x2a"
        "\x2e\x4c\x62\x02\xe9\x8d\x84\x28\x14\x75\xd5\x5d"
        "\x3d\xe9\xf3\xd9\x88\x09\xcc\xe1\xf6\x65";
    const char EXPECTED_HASH[] =
        "\x04\xe7\xd5\x5b\x0e\xb4\xbc\x3d\x3a\x21\xcf\xd2"
        "\x94\x1d\xbb\x4d\xc4\x47\x06\x58\x89\x67\x18\x6b"
        "\x40\xda\x54\x90\x2a\xee\xa9\x7b\x26\x2c\x97\xf7"
        "\x5e\x37\xeb\xe3\xcd\x60\xa8\x04\xe7\xb9\xfe\xca";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 107.
 */
BEGIN_TEST_F(hash_107)
    const char INPUT[] =
        "\xdf\xd7\xd7\x92\xe1\x62\xbf\x7a\x88\x91\x09\x55"
        "\x0a\x0f\xc4\xc4\x15\x23\x2a\xf0\xc0\xd7\x2d\xcb"
        "\xc2\x59\x52\x99\xe1\xa1\xc2\xae\xae\x54\x9f\x79"
        "\x70\xe9\x94\xc1\x5e\x0a\xb0\x2f\x11\x3d\x74\x0d"
        "\x38\xc3\x2a\x4d\x8e\xc0\x79\xcd\x09\x9d\x37\xd9"
        "\x54\xab\x7e\xf2\x80\x09\x02\xcd\xf7\xc7\xa1\x9f"
        "\xb1\x4b\x3c\x98\xaa\xf4\xc6\xad\x93\xfe\x9a\x9b"
        "\xc7\xa6\x12\x29\x82\x8e\x55\xad\x4d\x62\x70\xd1"
        "\xbd\xbc\xa9\x97\x5d\x45\x0f\x9b\xe9\x1e\x56";
    const char EXPECTED_HASH[] =
        "\x08\xe5\xef\x57\xd0\xc2\xaa\x23\xed\xfc\x75\xcf"
        "\xae\x39\xe6\xbc\x1a\x43\xb5\xdb\x08\xb2\xe2\x7b"
        "\xc9\x82\x31\x14\xed\xf7\x60\x36\x7d\xb9\xcf\x3c"
        "\xd9\xc3\x77\x97\x55\xf6\xd3\x9e\x21\x9b\x70\x79";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 108.
 */
BEGIN_TEST_F(hash_108)
    const char INPUT[] =
        "\xff\xbc\x7c\x47\xf5\x2e\x69\xf5\xc6\x67\xf4\xed"
        "\x57\x8b\x46\xff\x45\x92\x04\x8f\x78\x90\x81\xf3"
        "\xfb\x39\x32\x1d\x0a\xa4\x62\x7a\x6d\x4f\x26\x19"
        "\x05\x64\x94\x10\xa5\x3a\x30\x1c\x23\x1f\xa7\x87"
        "\xae\x55\xc0\x4f\x61\x5a\x8f\x84\x19\x6c\xec\xf2"
        "\x84\x4d\x23\x00\x7b\x44\xed\xd8\x92\x64\x9f\xc8"
        "\xed\x10\xa2\xe8\x55\xbf\x23\xfe\x8a\xfd\x0b\x9e"
        "\xdb\xb3\x32\x96\xf5\xa7\xcf\x89\xf9\x46\x34\xd9"
        "\xd1\xa2\xb8\xca\xc3\xb7\xf4\xe5\x46\xf2\x32\x9b";
    const char EXPECTED_HASH[] =
        "\xbe\x10\xc7\xba\xf9\x46\x08\x40\x8a\x0a\xcc\xfb"
        "\xc8\xce\x95\xe1\x59\xd0\x8d\x8c\xa7\x5d\xd6\xc2"
        "\x73\xf9\x35\x94\x7a\x7e\xc3\x46\x3e\x10\xa5\x8d"
        "\x3c\xea\xa0\xb2\x19\x8b\x08\x87\xa3\xa2\x4a\x29";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 109.
 */
BEGIN_TEST_F(hash_109)
    const char INPUT[] =
        "\xa3\x9f\x20\x2d\x86\x6e\x8e\x96\x76\x5f\xbb\x53"
        "\xb6\x77\x25\x37\xde\xc0\x43\x32\x2f\x4a\x74\x75"
        "\x24\x70\x36\xd7\x49\x5c\x98\x78\x50\xce\xf2\xa4"
        "\x62\x18\xd3\xfa\xb3\x6e\x3b\xcd\x59\x5c\x0a\xca"
        "\x5e\x98\xb9\xdb\x14\xfa\x48\x4c\xa8\xc9\x77\x2d"
        "\xfa\x38\x39\xf7\xac\x30\x66\x72\x7a\x50\xb0\xd5"
        "\xc9\x33\xd8\x2f\x82\xf1\x22\x07\x20\xe8\x06\x3f"
        "\x08\xbc\x28\x3f\x19\x9c\x8a\x4f\x85\xc7\x00\x43"
        "\xdf\x4f\xe5\x5e\x75\x1d\x0d\x71\xdf\x36\xfa\x43"
        "\xd8";
    const char EXPECTED_HASH[] =
        "\x3b\x26\x64\xcc\xb5\x55\xa1\xb1\xf3\xec\x99\x68"
        "\x60\x14\x6e\xa7\x5e\xf7\xf3\xbd\x62\x02\x8a\x19"
        "\xc2\x6f\x63\x33\x93\x99\xf4\x27\x5a\x07\xf3\xc0"
        "\x64\xd3\x47\x66\xeb\xe8\xe4\xdd\x53\x2f\x66\x29";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 110.
 */
BEGIN_TEST_F(hash_110)
    const char INPUT[] =
        "\xb2\xc8\x26\x18\x53\xe2\x21\x8d\xfa\x13\x5c\xb5"
        "\x38\x78\x10\x35\x2b\x89\x62\xe9\x4e\x9f\xdc\x86"
        "\x95\xb4\x1e\x7d\xba\x6a\xd1\x22\xd1\x4f\xdd\x0d"
        "\x23\x60\xdc\xc0\x39\xcc\xce\x8b\x37\xfa\x0e\xad"
        "\x6c\xcc\x85\xbc\x26\x26\x1d\x47\xcb\xaa\x78\xb9"
        "\x25\xc6\xe3\x80\xfe\xf1\x85\x6f\xed\x31\xdc\x61"
        "\x6f\xe1\x6b\x20\x39\xb1\xac\x85\xcd\xee\x4c\xe0"
        "\x4c\x04\x97\x99\x8b\x41\x32\x18\x68\xdb\x08\xe3"
        "\x5f\x35\x86\x06\x58\x5e\x0b\xb8\xc3\xda\x9a\x3b"
        "\xe7\xa6";
    const char EXPECTED_HASH[] =
        "\x45\xb2\x86\xf4\x9f\xd0\x5c\x45\xc9\x21\xb7\xbf"
        "\xdb\xe2\xcb\x02\x44\x41\xc3\x72\xe0\x73\x94\xdc"
        "\xcc\xae\x0d\xe8\x34\xcd\x54\x1f\x13\xa7\x9d\xbb"
        "\x3e\x50\x78\x89\x6e\x88\x43\x85\x42\xbd\x2f\x12";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 111.
 */
BEGIN_TEST_F(hash_111)
    const char INPUT[] =
        "\xa0\x4f\x39\x0a\x9c\xc2\xef\xfa\xd0\x5d\xb8\x0d"
        "\x90\x76\xa8\xd4\xb6\xcc\x8b\xba\x97\xb2\x7b\x42"
        "\x36\x70\xb2\x90\xb8\xe6\x9c\x2b\x18\x72\x30\x01"
        "\x1c\x14\x81\xac\x88\xd0\x90\xf3\x91\x54\x65\x94"
        "\x94\xdb\x5e\x41\x08\x51\xc6\xe8\xb2\xb8\xa9\x37"
        "\x17\xca\xe7\x60\x37\xe0\x88\x19\x78\x12\x4f\xe7"
        "\xe1\xa0\x92\x9d\x88\x91\x49\x1f\x4e\x99\x64\x6c"
        "\xc9\x40\x62\xdc\x82\x41\x1f\xa6\x61\x30\xed\xa4"
        "\x65\x60\xe7\x5b\x98\x04\x82\x36\x43\x94\x65\x12"
        "\x5e\x73\x7b";
    const char EXPECTED_HASH[] =
        "\xe7\x08\x9d\x72\x94\x5c\xef\x85\x1e\x68\x9b\x44"
        "\x09\xcf\xb6\x3d\x13\x5f\x0b\x5c\xdf\xb0\xda\xc6"
        "\xc3\xa2\x92\xdd\x70\x37\x1a\xb4\xb7\x9d\xa1\x99"
        "\x7d\x79\x92\x90\x6a\xc7\x21\x35\x02\x66\x29\x20";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 112.
 */
BEGIN_TEST_F(hash_112)
    const char INPUT[] =
        "\xf4\x19\x49\x4c\x3c\x6d\x07\x27\xb3\x39\x5a\x48"
        "\x3a\x21\x67\x18\x2a\x72\x52\xf4\xfd\x09\x9c\x2d"
        "\x4b\x71\xb0\x53\xf9\x4b\xb8\xb3\xad\xf3\xb5\x1e"
        "\x84\x60\xcf\xec\x08\x4c\xe9\x41\x5c\x95\x79\x8f"
        "\xba\xe4\x97\x5c\x20\x8c\x54\x46\x45\xb5\x4c\x44"
        "\xd2\xb9\x7f\x2e\xcf\xce\x5c\x80\x5b\xe6\x1f\x5b"
        "\xa1\xd3\x5d\xcc\x07\xaf\xdd\x51\xa8\x7b\xaa\x99"
        "\x05\x06\x66\x8c\xf7\x10\xe1\x8b\xe9\xb0\xeb\xf9"
        "\x43\xf3\x66\xfa\x29\xc6\x9f\x7a\x66\x16\xde\x72"
        "\xa3\x35\x3b\x66";
    const char EXPECTED_HASH[] =
        "\xae\xad\x86\x88\xc5\x8c\x6b\xa4\xe9\xca\xdb\x47"
        "\x56\xb4\x65\xdc\xe0\xfb\x06\xf1\xcf\xaa\x47\x81"
        "\x97\xf2\xea\x89\x41\x4e\x47\xe9\x57\x20\x34\xad"
        "\xfe\xd1\x60\x70\x3c\x79\xb8\x2b\x3f\xd7\xab\x78";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 113.
 */
BEGIN_TEST_F(hash_113)
    const char INPUT[] =
        "\xaa\xf7\x58\x4d\x53\x00\x6c\xbf\x2d\x20\x40\xe5"
        "\x1b\x7f\xee\xbd\x2b\xbf\x1e\x9f\x6d\x81\x7c\xd8"
        "\x06\x2a\x6a\x96\x80\xe7\xf1\x04\x64\xee\xfe\xb5"
        "\x0b\x07\xcb\x46\xb1\x4b\x9b\x3f\xcb\x2c\xaa\x3b"
        "\x9a\xb6\x64\x49\x01\x15\xd5\x91\x94\x56\x61\x3b"
        "\xf1\x72\xb5\x8c\x53\x88\xfd\x52\x64\x6a\x57\x83"
        "\x53\x5b\x88\x21\x27\x17\xef\x60\x53\x14\xb7\x0b"
        "\x8a\x08\x50\x24\xd4\xab\x1f\xcb\xe2\xbe\x74\x60"
        "\x9e\x4c\xbd\xec\x07\x30\xfa\xbd\x3c\xd7\x71\x51"
        "\xd6\x47\xa3\x76\x7b";
    const char EXPECTED_HASH[] =
        "\xe6\xe7\x9d\x8c\x61\xd0\xea\x9f\xc7\x0d\xd4\xde"
        "\xc1\xfa\x43\x28\x49\xc3\x39\x6e\x71\x7b\x17\x0b"
        "\xad\xbd\x87\xa4\xc7\x97\x4e\xfc\x59\x0a\xb8\xc1"
        "\x18\x3a\x62\x32\xbe\xff\x14\x53\x4f\x00\x4b\x02";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 114.
 */
BEGIN_TEST_F(hash_114)
    const char INPUT[] =
        "\xa4\x67\xf7\x73\x69\x73\x02\x01\xf2\x81\x22\x04"
        "\xfd\x63\xad\x0d\x27\x57\xbe\x58\x0d\x93\x7d\xfe"
        "\xb2\x21\xa0\x6b\x21\xed\x32\x13\x53\x1d\x93\x61"
        "\x52\xa0\xc1\xf0\x9f\x0a\xd5\xfe\xd1\x9f\xd1\x1e"
        "\x80\xad\x98\x2c\x61\x20\x3e\x86\xb2\x50\x82\x79"
        "\xd9\x1d\x99\xfa\x48\x3e\x2e\x97\xa3\xd6\xa6\xad"
        "\x25\x48\xa8\xda\x40\x4d\xdd\xb5\x83\x44\xf4\xbd"
        "\xc1\xc9\xea\x90\x70\x88\x88\x5e\x4f\x53\x2d\x9c"
        "\x4c\x73\xcd\xfd\xa4\x3c\x3a\x9e\x4c\xe5\xa2\x80"
        "\x90\x96\x59\x3c\xfa\xc1";
    const char EXPECTED_HASH[] =
        "\x5a\x75\x08\xc2\xcc\x09\x6b\xf6\x5a\x4d\x4d\x33"
        "\x7a\xea\x22\x00\x8e\xdb\x9a\x3b\xae\x86\x9f\x94"
        "\xe0\x9f\xb5\x26\xa5\x2c\x33\x68\xe9\xb2\x85\x76"
        "\xfb\x95\x0f\x07\x8b\x7e\x43\xb5\x56\x21\x20\xe6";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 115.
 */
BEGIN_TEST_F(hash_115)
    const char INPUT[] =
        "\x01\xab\xc9\x0e\x91\x80\xfc\x9b\xb8\xea\x67\xa4"
        "\x05\x07\x3e\xd6\x84\x8b\xf3\x30\x48\x07\x65\x66"
        "\x47\x6c\x55\x83\x6b\xcb\x19\xd3\xe5\x5e\x94\x00"
        "\xc5\xcc\x65\x7b\xc7\xa9\x5f\x1d\x70\x3c\x39\x0f"
        "\x5a\x86\x87\xe7\xcd\x7f\xe9\x13\x8e\xa3\x83\x7b"
        "\xfc\xad\xad\x62\x58\xa3\xeb\x8d\x65\x12\x1f\xa8"
        "\x31\x9b\xfd\xe5\x32\xae\xc0\xe6\x94\x96\x1b\xdd"
        "\xd2\xb6\x73\xf2\x84\x12\x4b\xe5\x78\x11\x00\xf4"
        "\x03\x81\xb6\xff\x99\xdb\x92\xea\x9c\xc8\x2a\x43"
        "\x72\xe5\x39\x24\xda\xc3\x98";
    const char EXPECTED_HASH[] =
        "\x96\xb2\x09\xd7\xcb\x2c\x20\x33\xb3\x83\x50\x74"
        "\x47\x67\xfa\x5c\x25\x3e\x1b\xfd\xb9\x9f\xe8\x41"
        "\x8b\xff\x83\x80\x4d\xf0\x22\x48\x14\x0f\xe3\xb7"
        "\x7b\x0b\xfd\x4a\x79\xb5\x1f\x70\x40\x5a\x43\x4b";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 116.
 */
BEGIN_TEST_F(hash_116)
    const char INPUT[] =
        "\xb5\x55\xd9\x90\x56\x36\x2b\xfc\x2b\xac\x2a\x1b"
        "\xbb\x71\xba\x11\x2d\x64\x4e\x50\xb8\x2b\x01\x5e"
        "\x5a\x1c\xe3\xd9\xcd\x5e\x90\xb8\xb7\x4b\x08\xd3"
        "\x21\x19\xba\xa6\x2a\xba\xe2\x51\xfc\x00\x15\xe4"
        "\x00\x05\x1a\xda\x4e\xca\xfc\xe3\x68\x1e\x5d\xe7"
        "\x27\xc2\x0d\x47\xf5\xca\xdc\x66\x3d\x46\xac\x68"
        "\x20\x22\xca\x39\x6a\x4b\x7e\xd1\xc4\x13\xe0\xb7"
        "\x2b\xd7\xee\xc4\xa0\xdf\xdc\x2a\x21\x85\xab\xb5"
        "\xd9\x9a\xfd\x50\x94\x05\x28\xca\x75\xad\x89\xda"
        "\xeb\x9a\x1b\x61\xe1\x57\x47\xf0";
    const char EXPECTED_HASH[] =
        "\xab\xd3\x9f\x79\xd7\x2c\x6c\xd2\xe8\xe1\x30\xf3"
        "\x60\x30\x32\xfe\x3c\xef\x41\x77\xc3\x56\x39\x30"
        "\x09\x6d\xf1\xf1\x0b\x87\xe7\x9c\xd4\xe2\x05\x9c"
        "\xf1\xb9\xf8\x25\x21\x84\xbb\x26\xf6\x59\xa5\xda";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 117.
 */
BEGIN_TEST_F(hash_117)
    const char INPUT[] =
        "\x14\xfb\x01\xae\x9d\x60\x15\xec\xb3\xe5\x6d\x6e"
        "\xcd\xfa\x4b\xc0\x53\x31\x86\xad\xf8\x45\x7f\x5e"
        "\x4a\x5c\x57\xc6\x87\x89\x5f\x3d\xb3\x95\xd0\x6a"
        "\xe7\xff\xbd\x67\xec\x41\x45\x20\x09\x55\x0d\xfc"
        "\x18\x78\xee\xc0\xdf\x2e\xea\xb0\x9e\x86\x65\xf7"
        "\xe5\x9f\x91\x48\xa8\x6b\x2b\xc6\x95\xb3\x65\x21"
        "\xa5\x5b\x23\x02\xf2\xe8\x69\xaa\xc8\x3f\x14\xd6"
        "\xfe\xaf\xc9\xe5\x87\x32\x2c\x3c\x44\xf0\x52\xea"
        "\x1c\x05\x78\x88\x4f\x84\xf5\x63\x07\xbc\x6d\xde"
        "\x31\xba\x48\x11\x8a\x0f\x62\xb6\xfd";
    const char EXPECTED_HASH[] =
        "\xfc\x9b\x9a\x95\xa8\xce\x1c\x15\x77\x20\xcb\x63"
        "\x10\x1a\x75\x94\xdf\x24\xf4\xcc\x74\xba\xf7\x35"
        "\xb0\xcc\xf6\xab\xb9\x25\x47\x8a\xd5\x07\xcd\x04"
        "\x8d\x30\xcd\xe1\xc7\x88\x80\x6f\x43\xed\x3a\x81";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 118.
 */
BEGIN_TEST_F(hash_118)
    const char INPUT[] =
        "\x11\xae\x0c\xbf\xee\x7b\xb3\xdf\x90\xce\x58\x5f"
        "\x09\xb9\xcf\x8f\xf5\xbe\xa6\x9a\x68\xee\xb6\xc2"
        "\x25\x53\xf8\xed\x11\x8c\x9a\x61\xe7\xb7\x52\xcc"
        "\x2c\x94\xf3\x87\x66\xe6\x3e\x1b\x89\x1d\xfa\x05"
        "\xb2\x33\x47\xb6\x17\xd4\x2f\xde\x3e\xc1\x7e\xea"
        "\x6e\x76\xd3\xcb\x64\x0b\xf8\xfa\x46\x58\x6f\xb9"
        "\xdd\x5c\x4d\x9b\xfe\xe0\x4c\x46\x49\x57\x1b\x78"
        "\x17\x09\xf8\x48\xad\x70\x81\xaf\xb6\xe2\xc7\x46"
        "\xf0\x71\xa5\x51\x25\x10\x50\xfd\x5d\xf7\x2e\xe6"
        "\x52\x48\xec\xdc\x24\xf2\xcb\xe7\x4e\xd5";
    const char EXPECTED_HASH[] =
        "\x32\x14\xb5\xfe\xec\x92\x50\x59\x14\x9f\xa8\x52"
        "\xe3\xae\x28\x5a\x6e\xb3\x77\xdf\x92\x65\x04\xe2"
        "\xf8\x24\x57\x2a\x3a\xeb\xd2\x05\x0a\x20\x14\x4e"
        "\x7b\xed\xe7\xe7\xfe\x23\x8e\xe8\x3e\x69\xf7\x2c";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 119.
 */
BEGIN_TEST_F(hash_119)
    const char INPUT[] =
        "\xa5\xc4\xa4\x7a\x04\xf4\x71\x42\x69\xd5\xd9\x22"
        "\xba\x46\x94\x06\x0a\xa2\xdf\x49\x19\x37\x20\xc8"
        "\x19\xfa\xc9\x3b\xb8\x78\x7e\xc5\x5a\x10\x7a\xc9"
        "\xa6\x60\x2f\x00\x45\xfd\x2c\xc8\xe6\x67\x44\xbf"
        "\x86\x3c\xed\x91\xee\xab\xe6\x0e\x7d\x2c\x1d\x80"
        "\x27\x6e\xcf\x3b\xbe\x91\xf1\x75\x70\x96\xcf\x58"
        "\x92\x14\xf3\x56\x9c\x2c\x48\xbd\x74\xbe\x7f\x8b"
        "\xef\xdd\xb2\x83\x95\x81\x47\x80\xa4\x7c\x18\x0a"
        "\x58\xb0\xd0\x27\x6a\x7e\x98\x73\xd6\x82\xf4\x73"
        "\xe2\x7d\xe7\x27\x5c\x92\x5e\xde\x23\xb6\xcc";
    const char EXPECTED_HASH[] =
        "\x6b\xd9\xe1\x30\x35\x79\xd8\x15\xf5\x8e\x8c\x6c"
        "\x98\x55\x85\x01\x33\x25\x17\x78\xa6\x32\xf7\xb3"
        "\x12\xc4\xb3\x16\x3b\x29\xb5\xef\x6c\xb9\x51\x1a"
        "\x08\xa3\x1a\x23\x7d\x9a\x76\x04\xaf\xbf\xa0\x56";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init( &md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 120.
 */
BEGIN_TEST_F(hash_120)
    const char INPUT[] =
        "\x75\x26\x47\x74\xaf\x69\xec\x7e\xe3\x12\x5e\x20"
        "\x5b\xd6\xd1\xcb\x8f\xdb\x22\xf7\xea\x6d\xbe\x72"
        "\xd1\xf2\xc0\xf7\xe2\x20\x59\x02\x79\x6d\x75\xe3"
        "\x79\xc7\x9b\x11\x49\x86\x15\xc2\x1c\x9f\x52\xb8"
        "\x76\x1a\x88\x5e\xec\xc6\x9d\x13\x2b\x2b\x48\xc6"
        "\x3b\xc0\x74\xc3\x05\x5e\xe5\xcc\x13\xf5\x1d\x6c"
        "\x98\x7e\x81\x88\xb0\x30\xb8\x37\xe8\xf7\x54\xd4"
        "\x01\x22\xb4\x51\xf1\x5b\x28\xcd\x2b\xdd\x57\x69"
        "\x20\xe1\xde\x58\x06\x59\x3a\x36\xd8\xe1\xe8\x9b"
        "\x9e\xf3\xca\xef\xee\x5a\xcd\x80\xb3\xe9\xc9\xd1";
    const char EXPECTED_HASH[] =
        "\xff\xa9\xe4\xe8\x56\xd0\x62\x27\xc1\xcc\xb9\x59"
        "\xbe\x55\x83\x09\xcc\x10\x63\x31\x73\xf4\xb6\x6c"
        "\xeb\x38\x29\x23\xb5\x2b\x91\x50\xac\xfb\x08\xa7"
        "\x39\x35\x00\x47\x7a\x6e\xe4\x42\x5a\x82\x7e\x76";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 121.
 */
BEGIN_TEST_F(hash_121)
    const char INPUT[] =
        "\x79\x1a\x36\xd7\x48\x69\x5e\x62\xdb\x50\x03\xa8"
        "\xad\x36\x7d\xf1\xf0\x51\xc1\xac\x6a\x21\xd7\x11"
        "\x82\x3e\x8e\x06\x9b\x54\x6e\x3f\xa0\x6c\xee\xaa"
        "\xe0\x6d\xe7\x0a\x1d\xe2\x49\xe1\xdf\xfd\x0d\x94"
        "\x0e\xdc\x6a\xca\xc0\x0c\x4c\x15\x50\x4c\x02\xd4"
        "\xb0\x93\x36\x58\x00\x54\x23\x45\x5f\x00\x02\x3b"
        "\x01\xcd\xc5\xb6\x81\xb6\x08\x33\x79\xc2\x45\x95"
        "\x51\x8a\x47\xc6\x54\xf5\xe1\xa1\x09\x47\xdf\x10"
        "\xc0\x5a\x3d\x71\x6b\x2a\x97\x3f\xaf\x98\xe1\xee"
        "\x3b\x67\x58\x16\x59\x8b\xb8\xd4\xc2\xa3\xb0\x6e"
        "\xb7";
    const char EXPECTED_HASH[] =
        "\xf8\xd3\x33\x69\x68\x05\x24\xed\x6c\x6a\x71\x6d"
        "\x4c\x50\x2d\xe3\xea\xc8\x91\xf3\x40\xf4\x0e\x82"
        "\xe3\x75\x01\xbe\x1a\x90\xfb\x61\xd2\x6e\x5d\xaa"
        "\xfe\x92\xbc\x6e\xf5\xec\x0a\xe4\x31\x16\x88\x42";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
        == vccrypt_hash_digest(
                &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 122.
 */
BEGIN_TEST_F(hash_122)
    const char INPUT[] =
        "\x74\xcd\x86\xbb\xed\x14\xd8\x95\x30\x1d\x8a\x54"
        "\xb2\x95\x6b\x1c\x5c\xd1\x45\x1e\xeb\xab\x62\x0b"
        "\x97\x8d\x4e\xce\xf2\xcb\xdf\x7a\x14\x36\x73\x81"
        "\xf5\xee\x79\x28\x1a\x77\x33\x37\x74\x0f\xb9\xf5"
        "\x85\x3f\x42\x53\xc4\xb1\x9f\x68\x43\x41\x08\x1d"
        "\x8f\x56\x1b\x2a\xd7\x73\x22\x41\x51\x09\x95\x88"
        "\xda\x90\xe0\x4d\xdd\xd5\x65\xf6\x75\x96\xc5\x36"
        "\xd6\x4c\x5b\x87\xe9\x48\x0a\xd4\x36\x01\x39\x75"
        "\x07\xad\x1b\x61\xca\x0e\x34\x9f\xb8\x8f\x19\xfe"
        "\xb4\x8f\x77\x06\x76\xfd\x56\x2e\xe8\x25\x9f\x50"
        "\xd0\xc9";
    const char EXPECTED_HASH[] =
        "\x73\xee\x8d\x29\xc3\x08\x21\xdc\xdf\xa4\x44\x16"
        "\x39\xf0\x37\xfb\x6b\xa3\xa9\xca\x59\x6d\xc4\x34"
        "\x28\x04\x37\x85\x75\x66\x08\xf6\x20\x7d\x80\xb7"
        "\xf7\x8e\x57\x31\x74\xfb\x9d\xfd\x42\xf0\xb8\xcd";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 123.
 */
BEGIN_TEST_F(hash_123)
    const char INPUT[] =
        "\x46\x61\x2e\x1a\x4d\x01\x6c\x41\x70\x0a\x3b\x5c"
        "\xcb\x38\x32\x33\x53\xbd\x8d\xa5\xb9\x94\x2c\x9c"
        "\x92\x12\xdf\x40\xb4\xbe\xe0\x6b\xe3\x62\xa1\x5d"
        "\xad\x62\xc8\xb2\x92\x4d\x78\x91\x68\xb2\xd3\x25"
        "\xfe\x35\xbd\x51\x00\xe1\xe2\x9f\x1a\xc0\xfa\x7a"
        "\x60\xa9\x4c\x9e\xee\x5a\x70\xcc\xcb\xc7\x5a\xc2"
        "\x14\xb1\x94\x6a\x56\x79\xcb\x52\x3b\x37\x8d\x5c"
        "\x69\x07\x51\xb7\xa7\xa3\xb8\x0d\x41\x37\x12\xfe"
        "\xae\x70\x24\xce\x71\xd6\x29\x5a\x3d\x5d\x16\x51"
        "\x5c\x36\x22\xa0\x52\xeb\x86\x2e\xbd\xab\x81\xca"
        "\x7f\xe3\xa0";
    const char EXPECTED_HASH[] =
        "\xca\xc1\x3a\x37\x84\x22\x5b\xe0\x3d\x52\x6f\x9a"
        "\xbc\x1e\xb5\x0a\x76\x2e\x72\xc0\xe0\x11\x72\xa1"
        "\x5d\x57\x88\x01\x08\x9e\x5c\x9f\x26\xe5\x3c\xc0"
        "\x0f\xf7\x55\x90\x94\x53\xe2\x96\x4d\x7d\xf8\x38";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 124.
 */
BEGIN_TEST_F(hash_124)
    const char INPUT[] =
        "\x1a\x85\x7c\x1f\x10\x5d\x06\x8c\xea\xb0\xb1\xe1"
        "\x24\x94\x89\x0e\xc1\x96\x36\x2a\x48\xb0\x20\x0a"
        "\x0d\x75\xd7\x12\xb1\x8f\xb1\x4b\xec\x6b\xb5\xb6"
        "\x8a\x33\xb7\xe0\xb4\xfd\xc5\xb7\x71\x42\xc2\x9c"
        "\x6d\x91\x51\xb9\xf8\x84\xf5\x95\x51\xf4\x76\xe5"
        "\x25\x69\x86\xa6\x53\xd4\xa4\x68\xf2\x81\x41\xed"
        "\x95\x47\x21\xf2\xcd\x02\x05\x4d\xf0\x43\x87\x38"
        "\x19\x45\x45\xed\x70\x23\x41\x73\xac\x49\x88\xb7"
        "\xd6\x28\x12\xde\x4f\x2f\xea\xda\x14\xf6\x8e\x3b"
        "\x41\xbc\x99\x48\xd4\x13\x9f\x4f\xb4\xda\x59\x39"
        "\xf2\x6c\x02\x61";
    const char EXPECTED_HASH[] =
        "\xb7\x5d\x92\xb5\xcd\x37\x72\x84\x6f\x7b\x68\x06"
        "\x4a\x35\x67\xae\x43\xe5\x01\x00\x99\xf2\xb6\x49"
        "\xf3\x50\x87\xe7\x59\x2a\xee\xc1\x76\x64\x6f\xc8"
        "\xc2\x62\x92\x88\x94\x42\x61\xcd\x35\xb5\xfc\xba";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 125.
 */
BEGIN_TEST_F(hash_125)
    const char INPUT[] =
        "\x9d\x36\x81\x8d\x0c\x5a\x00\x8b\xe7\x90\x4d\x19"
        "\x17\xaa\x3e\xcc\xb5\xef\x4f\x38\xce\xcb\x8c\x4e"
        "\x63\xc4\xb2\xe9\xb4\xb0\x91\xa3\xbf\x25\xb4\xed"
        "\x03\x32\x44\x5f\x89\x4c\x2a\x4c\x25\x8b\x74\x9a"
        "\xfa\x17\xfa\xd0\x3c\xdd\x41\x71\x3a\x86\x9f\x89"
        "\x9b\xa9\xa0\x85\xe7\x3f\xa9\x47\x4a\x58\xdb\x7a"
        "\x95\x0d\x3a\x23\x86\xb6\x0f\x79\x49\x5d\x8b\xf7"
        "\x3e\x72\xac\xaf\xfd\xbf\x65\xe1\x98\x9f\xf9\xcc"
        "\x20\x6b\xa8\xc4\x6a\x36\x8d\x85\x12\xba\xc7\xc7"
        "\xc1\x91\xd7\x13\xac\xa9\x49\xd4\x5d\xf2\x97\xb1"
        "\xb6\x59\x4a\x1a\x33";
    const char EXPECTED_HASH[] =
        "\xa8\x8d\xa8\x44\x57\x9f\x3e\x37\x25\xd0\x0d\xaa"
        "\x8e\x1e\x28\x7d\xa4\xbf\xbb\x2d\x93\x1e\xbe\x8d"
        "\x3b\x16\x02\x11\x54\xbe\x50\x33\x41\xd6\x37\x1d"
        "\x38\x2a\xda\x74\x4f\x86\xf5\xbb\xb5\x6c\xdc\xfa";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 126.
 */
BEGIN_TEST_F(hash_126)
    const char INPUT[] =
        "\x4a\xe5\x0e\xd6\x26\xee\x60\xdc\x5e\xa5\x56\xe3"
        "\xce\x0d\x3c\x18\xb9\xe6\x22\x5b\x56\x20\x81\x4e"
        "\x8b\x96\x21\xac\xf8\xf9\x39\xdd\x37\x0a\xd9\xc7"
        "\x62\x0d\x85\xe6\xd6\x7a\x22\x9f\x37\xf5\x17\xd1"
        "\xb5\x80\xac\xae\x8d\xf0\xb5\xc9\xd2\x9d\x75\x6f"
        "\x6d\x5e\xbd\x3b\x63\xb5\x54\xe5\x56\x46\x9b\x5b"
        "\x4f\x8e\x71\x13\xba\xd1\x55\x9f\xb2\x54\xca\x82"
        "\x7f\xcd\x00\x42\x5d\x18\xb0\xbe\x7f\x2b\x48\xc2"
        "\x54\x4c\x48\xd9\x09\x82\xec\x62\x4f\x49\x0b\xe6"
        "\x5e\x89\x3f\xa9\x3a\xc9\x46\x7f\x35\xa0\xa8\xe1"
        "\xb5\x6d\x9a\x40\x37\x48";
    const char EXPECTED_HASH[] =
        "\xf8\xcd\x94\x3f\x42\x93\x33\xc7\xc8\xd3\x0a\x85"
        "\x76\x82\x7f\x92\xc9\x2a\xe1\x8e\x0d\xbc\xae\x77"
        "\x06\x01\xb7\x96\x87\xbc\xcf\x8c\x23\xe9\xe5\x89"
        "\xdf\xeb\x45\xc3\xb9\xbc\xaf\xdd\x54\x5e\x45\xe7";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 127.
 */
BEGIN_TEST_F(hash_127)
    const char INPUT[] =
        "\xdb\xed\x76\x12\x44\x8d\x46\xcb\xe0\xa3\x84\xd1"
        "\xc9\x32\x33\xf0\x2f\xfd\x1c\x98\x4b\xa7\x65\x29"
        "\x95\x18\x65\x6d\x37\x23\xb7\x66\xc1\x65\x8d\x4b"
        "\x1e\x70\x47\xcd\xc7\x29\x45\x9e\x36\x6e\xf9\x34"
        "\x9e\xfc\x40\xcb\xd9\x90\xf2\xa9\xa2\x4d\xb7\xa5"
        "\x04\x5e\x1d\xea\x12\xdc\xe8\xf9\xd9\xf2\xaa\xed"
        "\x93\x3f\x93\x03\x1e\x7b\x89\x59\xac\x5e\x7b\xf6"
        "\xbb\xbd\xf3\x0b\x48\xf7\xeb\x78\x3f\x8f\xe2\x92"
        "\x37\x1a\x2f\x24\x5c\x5c\x94\xb4\xac\xae\x16\x07"
        "\x67\xa2\x0c\xe7\xc0\xea\x77\x23\xd9\x76\x91\xd8"
        "\xee\xdd\xa9\xef\xd1\xfe\x2d";
    const char EXPECTED_HASH[] =
        "\xfb\x53\x1a\x1e\xd1\x81\xc7\x32\x31\x1e\x56\xf4"
        "\xb5\x6e\xd9\x1d\xca\xcc\x0d\xd6\xbf\x1e\xb4\xa4"
        "\x4b\xe6\xf8\x7d\xd7\xcb\x1e\xf9\xdf\xb0\x31\x0f"
        "\x4a\x79\xea\xaa\x3f\x32\xbf\x39\x14\xd8\x62\x4e";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 128.
 */
BEGIN_TEST_F(hash_128)
    const char INPUT[] =
        "\x3b\xf5\x2c\xc5\xee\x86\xb9\xa0\x19\x0f\x39\x0a"
        "\x5c\x03\x66\xa5\x60\xb5\x57\x00\x0d\xbe\x51\x15"
        "\xfd\x9e\xe1\x16\x30\xa6\x27\x69\x01\x15\x75\xf1"
        "\x58\x81\x19\x8f\x22\x78\x76\xe8\xfe\x68\x5a\x69"
        "\x39\xbc\x8b\x89\xfd\x48\xa3\x4e\xc5\xe7\x1e\x13"
        "\x14\x62\xb2\x88\x67\x94\xdf\xfa\x68\xcc\xc6\xd5"
        "\x64\x73\x3e\x67\xff\xef\x25\xe6\x27\xc6\xf4\xb5"
        "\x46\x07\x96\xe3\xbc\xe6\x7b\xf5\x8c\xa6\xe8\xe5"
        "\x55\xbc\x91\x6a\x85\x31\x69\x7a\xc9\x48\xb9\x0d"
        "\xc8\x61\x6f\x25\x10\x1d\xb9\x0b\x50\xc3\xd3\xdb"
        "\xc9\xe2\x1e\x42\xff\x38\x71\x87";
    const char EXPECTED_HASH[] =
        "\x12\xb6\xcb\x35\xed\xa9\x2e\xe3\x73\x56\xdd\xee"
        "\x77\x78\x1a\x17\xb3\xd9\x0e\x56\x38\x24\xa9\x84"
        "\xfa\xff\xc6\xfd\xd1\x69\x3b\xd7\x62\x60\x39\x63"
        "\x55\x63\xcf\xc3\xb9\xa2\xb0\x0f\x9c\x65\xee\xfd";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(
        0
            == vccrypt_hash_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_HASH_ALGORITHM_SHA_2_384));

    TEST_ASSERT(
        0 == vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 == vccrypt_hash_init(&options, &context));

    TEST_ASSERT(
        0
            == vccrypt_hash_digest(
                    &context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 == vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 48));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()
