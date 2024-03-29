/**
 * \file test_vccrypt_sha512_ref.cpp
 *
 * Unit tests for the reference SHA-512 implementation.
 *
 * \copyright 2017-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <string.h>
#include <vccrypt/hash.h>
#include <vpr/allocator/malloc_allocator.h>

class vccrypt_sha512_ref_test {
public:
    void setUp()
    {
        //make sure SHA-512 has been registered
        vccrypt_hash_register_SHA_2_512();

        malloc_allocator_options_init(&alloc_opts);
    }

    void tearDown()
    {
        dispose((disposable_t*)&alloc_opts);
    }

    allocator_options_t alloc_opts;
};

TEST_SUITE(vccrypt_sha512_ref_test);

#define BEGIN_TEST_F(name) \
TEST(name) \
{ \
    vccrypt_sha512_ref_test fixture; \
    fixture.setUp();

#define END_TEST_F() \
    fixture.tearDown(); \
}

/**
 * We should be able to get SHA-512 options if it has been registered.
 */
BEGIN_TEST_F(init)
    vccrypt_hash_options_t options;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to create a hash context.
 */
BEGIN_TEST_F(context_init)
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash an empty buffer.
 */
BEGIN_TEST_F(hash_empty)
    const char EXPECTED_HASH[] =
        "\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80\x07"
        "\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c\xe9\xce"
        "\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87\x7e\xec\x2f"
        "\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a\xf9\x27\xda\x3e";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&md);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 1.
 */
BEGIN_TEST_F(hash_1)
    const char INPUT[] =
        "\x21";
    const char EXPECTED_HASH[] =
        "\x38\x31\xa6\xa6\x15\x5e\x50\x9d\xee\x59\xa7\xf4\x51\xeb\x35\x32"
        "\x4d\x8f\x8f\x2d\xf6\xe3\x70\x88\x94\x74\x0f\x98\xfd\xee\x23\x88"
        "\x9f\x4d\xe5\xad\xb0\xc5\x01\x0d\xfb\x55\x5c\xda\x77\xc8\xab\x5d"
        "\xc9\x02\x09\x4c\x52\xde\x32\x78\xf3\x5a\x75\xeb\xc2\x5f\x09\x3a";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 2.
 */
BEGIN_TEST_F(hash_2)
    const char INPUT[] =
        "\x90\x83";
    const char EXPECTED_HASH[] =
        "\x55\x58\x6e\xbb\xa4\x87\x68\xae\xb3\x23\x65\x5a\xb6\xf4\x29\x8f"
        "\xc9\xf6\x70\x96\x4f\xc2\xe5\xf2\x73\x1e\x34\xdf\xa4\xb0\xc0\x9e"
        "\x6e\x1e\x12\xe3\xd7\x28\x6b\x31\x45\xc6\x1c\x20\x47\xfb\x1a\x2a"
        "\x12\x97\xf3\x6d\xa6\x41\x60\xb3\x1f\xa4\xc8\xc2\xcd\xdd\x2f\xb4";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 3.
 */
BEGIN_TEST_F(hash_3)
    const char INPUT[] =
        "\x0a\x55\xdb";
    const char EXPECTED_HASH[] =
        "\x79\x52\x58\x5e\x53\x30\xcb\x24\x7d\x72\xba\xe6\x96\xfc\x8a\x6b"
        "\x0f\x7d\x08\x04\x57\x7e\x34\x7d\x99\xbc\x1b\x11\xe5\x2f\x38\x49"
        "\x85\xa4\x28\x44\x93\x82\x30\x6a\x89\x26\x1a\xe1\x43\xc2\xf3\xfb"
        "\x61\x38\x04\xab\x20\xb4\x2d\xc0\x97\xe5\xbf\x4a\x96\xef\x91\x9b";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 4.
 */
BEGIN_TEST_F(hash_4)
    const char INPUT[] =
        "\x23\xbe\x86\xd5";
    const char EXPECTED_HASH[] =
        "\x76\xd4\x2c\x8e\xad\xea\x35\xa6\x99\x90\xc6\x3a\x76\x2f\x33\x06"
        "\x14\xa4\x69\x99\x77\xf0\x58\xad\xb9\x88\xf4\x06\xfb\x0b\xe8\xf2"
        "\xea\x3d\xce\x3a\x2b\xbd\x1d\x82\x7b\x70\xb9\xb2\x99\xae\x6f\x9e"
        "\x50\x58\xee\x97\xb5\x0b\xd4\x92\x2d\x6d\x37\xdd\xc7\x61\xf8\xeb";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 5.
 */
BEGIN_TEST_F(hash_5)
    const char INPUT[] =
        "\xeb\x0c\xa9\x46\xc1";
    const char EXPECTED_HASH[] =
        "\xd3\x9e\xce\xdf\xe6\xe7\x05\xa8\x21\xae\xe4\xf5\x8b\xfc\x48\x9c"
        "\x3d\x94\x33\xeb\x4a\xc1\xb0\x3a\x97\xe3\x21\xa2\x58\x6b\x40\xdd"
        "\x05\x22\xf4\x0f\xa5\xae\xf3\x6a\xff\xf5\x91\xa7\x8c\x91\x6b\xfc"
        "\x6d\x1c\xa5\x15\xc4\x98\x3d\xd8\x69\x5b\x1e\xc7\x95\x1d\x72\x3e";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 6.
 */
BEGIN_TEST_F(hash_6)
    const char INPUT[] =
        "\x38\x66\x7f\x39\x27\x7b";
    const char EXPECTED_HASH[] =
        "\x85\x70\x8b\x8f\xf0\x5d\x97\x4d\x6a\xf0\x80\x1c\x15\x2b\x95\xf5"
        "\xfa\x5c\x06\xaf\x9a\x35\x23\x0c\x5b\xea\x27\x52\xf0\x31\xf9\xbd"
        "\x84\xbd\x84\x47\x17\xb3\xad\xd3\x08\xa7\x0d\xc7\x77\xf9\x08\x13"
        "\xc2\x0b\x47\xb1\x63\x85\x66\x4e\xef\xc8\x84\x49\xf0\x4f\x21\x31";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 7.
 */
BEGIN_TEST_F(hash_7)
    const char INPUT[] =
        "\xb3\x9f\x71\xaa\xa8\xa1\x08";
    const char EXPECTED_HASH[] =
        "\x25\x8b\x8e\xfa\x05\xb4\xa0\x6b\x1e\x63\xc7\xa3\xf9\x25\xc5\xef"
        "\x11\xfa\x03\xe3\xd4\x7d\x63\x1b\xf4\xd4\x74\x98\x37\x83\xd8\xc0"
        "\xb0\x94\x49\x00\x9e\x84\x2f\xc9\xfa\x15\xde\x58\x6c\x67\xcf\x89"
        "\x55\xa1\x7d\x79\x0b\x20\xf4\x1d\xad\xf6\x7e\xe8\xcd\xcd\xfc\xe6";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 8.
 */
BEGIN_TEST_F(hash_8)
    const char INPUT[] =
        "\x6f\x8d\x58\xb7\xca\xb1\x88\x8c";
    const char EXPECTED_HASH[] =
        "\xa3\x94\x1d\xef\x28\x03\xc8\xdf\xc0\x8f\x20\xc0\x6b\xa7\xe9\xa3"
        "\x32\xae\x0c\x67\xe4\x7a\xe5\x73\x65\xc2\x43\xef\x40\x05\x9b\x11"
        "\xbe\x22\xc9\x1d\xa6\xa8\x0c\x2c\xff\x07\x42\xa8\xf4\xbc\xd9\x41"
        "\xbd\xee\x0b\x86\x1e\xc8\x72\xb2\x15\x43\x3c\xe8\xdc\xf3\xc0\x31";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 9.
 */
BEGIN_TEST_F(hash_9)
    const char INPUT[] =
        "\x16\x2b\x0c\xf9\xb3\x75\x0f\x94\x38";
    const char EXPECTED_HASH[] =
        "\xad\xe2\x17\x30\x5d\xc3\x43\x92\xaa\x4b\x8e\x57\xf6\x4f\x5a\x3a"
        "\xfd\xd2\x7f\x1f\xa9\x69\xa9\xa2\x60\x83\x53\xf8\x2b\x95\xcf\xb4"
        "\xae\x84\x59\x8d\x01\x57\x5a\x57\x8a\x10\x68\xa5\x9b\x34\xb5\x04"
        "\x5f\xf6\xd5\x29\x9c\x5c\xb7\xee\x17\x18\x07\x01\xb2\xd1\xd6\x95";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 10.
 */
BEGIN_TEST_F(hash_10)
    const char INPUT[] =
        "\xba\xd7\xc6\x18\xf4\x5b\xe2\x07\x97\x5e";
    const char EXPECTED_HASH[] =
        "\x58\x86\x82\x89\x59\xd1\xf8\x22\x54\x06\x8b\xe0\xbd\x14\xb6\xa8"
        "\x8f\x59\xf5\x34\x06\x1f\xb2\x03\x76\xa0\x54\x10\x52\xdd\x36\x35"
        "\xed\xf3\xc6\xf0\xca\x3d\x08\x77\x5e\x13\x52\x5d\xf9\x33\x3a\x21"
        "\x13\xc0\xb2\xaf\x76\x51\x58\x87\x52\x99\x10\xb6\xc7\x93\xc8\xa5";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 11.
 */
BEGIN_TEST_F(hash_11)
    const char INPUT[] =
        "\x62\x13\xe1\x0a\x44\x20\xe0\xd9\xb7\x70\x37";
    const char EXPECTED_HASH[] =
        "\x99\x82\xdc\x2a\x04\xdf\xf1\x65\x56\x7f\x27\x6f\xd4\x63\xef\xef"
        "\x2b\x36\x9f\xa2\xfb\xca\x8c\xee\x31\xce\x0d\xe8\xa7\x9a\x2e\xb0"
        "\xb5\x3e\x43\x7f\x7d\x9d\x1f\x41\xc7\x1d\x72\x5c\xab\xb9\x49\xb5"
        "\x13\x07\x5b\xad\x17\x40\xc9\xee\xfb\xf6\xa5\xc6\x63\x34\x00\xc7";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 12.
 */
BEGIN_TEST_F(hash_12)
    const char INPUT[] =
        "\x63\x32\xc3\xc2\xa0\xa6\x25\xa6\x1d\xf7\x18\x58";
    const char EXPECTED_HASH[] =
        "\x9d\x60\x37\x5d\x98\x58\xd9\xf2\x41\x6f\xb8\x6f\xa0\xa2\x18\x9e"
        "\xe4\x21\x3e\x87\x10\x31\x4f\xd1\xeb\xed\x0f\xd1\x58\xb0\x43\xe6"
        "\xe7\xc9\xa7\x6d\x62\xc6\xba\x1e\x1d\x41\x1a\x73\x09\x02\x30\x9e"
        "\xc6\x76\xdd\x49\x14\x33\xc6\xef\x66\xc8\xf1\x16\x23\x3d\x6c\xe7";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 13.
 */
BEGIN_TEST_F(hash_13)
    const char INPUT[] =
        "\xf4\x7b\xe3\xa2\xb0\x19\xd1\xbe\xed\xed\xf5\xb8\x0c";
    const char EXPECTED_HASH[] =
        "\xb9\x42\x92\x62\x5c\xaa\x28\xc7\xbe\x24\xa0\x99\x7e\xb7\x32\x80"
        "\x62\xa7\x6d\x9b\x52\x9c\x0f\x1d\x56\x8f\x85\x0d\xf6\xd5\x69\xb5"
        "\xe8\x4d\xf0\x7e\x9e\x24\x6b\xe2\x32\x03\x3f\xfa\xc3\xad\xf2\xd1"
        "\x8f\x92\xab\x9d\xac\xfc\x0e\xcf\x08\xaf\xf7\x14\x5f\x0b\x83\x3b";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 14.
 */
BEGIN_TEST_F(hash_14)
    const char INPUT[] =
        "\xb1\x71\x5f\x78\x2f\xf0\x2c\x6b\x88\x93\x7f\x05\x41\x16";
    const char EXPECTED_HASH[] =
        "\xee\x1a\x56\xee\x78\x18\x2e\xc4\x1d\x2c\x3a\xb3\x3d\x4c\x41\x87"
        "\x1d\x43\x7c\x5c\x1c\xa0\x60\xee\x9e\x21\x9c\xb8\x36\x89\xb4\xe5"
        "\xa4\x17\x4d\xfd\xab\x5d\x1d\x10\x96\xa3\x1a\x7c\x8d\x3a\xbd\xa7"
        "\x5c\x1b\x5e\x6d\xa9\x7e\x18\x14\x90\x1c\x50\x5b\x0b\xc0\x7f\x25";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 15.
 */
BEGIN_TEST_F(hash_15)
    const char INPUT[] =
        "\x9b\xcd\x52\x62\x86\x8c\xd9\xc8\xa9\x6c\x9e\x82\x98\x7f\x03";
    const char EXPECTED_HASH[] =
        "\x2e\x07\x66\x2a\x00\x1b\x97\x55\xae\x92\x2c\x8e\x8a\x95\x75\x6d"
        "\xb5\x34\x1d\xc0\xf2\xe6\x2a\xe1\xcf\x82\x70\x38\xf3\x3c\xe0\x55"
        "\xf6\x3a\xd5\xc0\x0b\x65\x39\x14\x28\x43\x4d\xdc\x01\xe5\x53\x5e"
        "\x7f\xec\xbf\x53\xdb\x66\xd9\x30\x99\xb8\xe0\xb7\xe4\x4e\x4b\x25";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 16.
 */
BEGIN_TEST_F(hash_16)
    const char INPUT[] =
        "\xcd\x67\xbd\x40\x54\xaa\xa3\xba\xa0\xdb\x17\x8c\xe2\x32\xfd\x5a";
    const char EXPECTED_HASH[] =
        "\x0d\x85\x21\xf8\xf2\xf3\x90\x03\x32\xd1\xa1\xa5\x5c\x60\xba\x81"
        "\xd0\x4d\x28\xdf\xe8\xc5\x04\xb6\x32\x8a\xe7\x87\x92\x5f\xe0\x18"
        "\x8f\x2b\xa9\x1c\x3a\x9f\x0c\x16\x53\xc4\xbf\x0a\xda\x35\x64\x55"
        "\xea\x36\xfd\x31\xf8\xe7\x3e\x39\x51\xca\xd4\xeb\xba\x8c\x6e\x04";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 17.
 */
BEGIN_TEST_F(hash_17)
    const char INPUT[] =
        "\x6b\xa0\x04\xfd\x17\x67\x91\xef\xb3\x81\xb8\x62\xe2\x98\xc6\x7b"
        "\x08";
    const char EXPECTED_HASH[] =
        "\x11\x2e\x19\x14\x4a\x9c\x51\xa2\x23\xa0\x02\xb9\x77\x45\x99\x20"
        "\xe3\x8a\xfd\x4c\xa6\x10\xbd\x1c\x53\x23\x49\xe9\xfa\x7c\x0d\x50"
        "\x32\x15\xc0\x1a\xd7\x0e\x1b\x2a\xc5\x13\x3c\xf2\xd1\x0c\x9e\x8c"
        "\x1a\x4c\x94\x05\xf2\x91\xda\x2d\xc4\x5f\x70\x67\x61\xc5\xe8\xfe";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 18.
 */
BEGIN_TEST_F(hash_18)
    const char INPUT[] =
        "\xc6\xa1\x70\x93\x65\x68\x65\x10\x20\xed\xfe\x15\xdf\x80\x12\xac"
        "\xda\x8d";
    const char EXPECTED_HASH[] =
        "\xc3\x6c\x10\x0c\xdb\x6c\x8c\x45\xb0\x72\xf1\x82\x56\xd6\x3a\x66"
        "\xc9\x84\x3a\xcb\x4d\x07\xde\x62\xe0\x60\x07\x11\xd4\xfb\xe6\x4c"
        "\x8c\xf3\x14\xec\x34\x57\xc9\x03\x08\x14\x7c\xb7\xac\x7e\x4d\x07"
        "\x3b\xa1\x0f\x0c\xed\x78\xea\x72\x4a\x47\x4b\x32\xda\xe7\x12\x31";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 19.
 */
BEGIN_TEST_F(hash_19)
    const char INPUT[] =
        "\x61\xbe\x0c\x9f\x5c\xf6\x27\x45\xc7\xda\x47\xc1\x04\x59\x71\x94"
        "\xdb\x24\x5c";
    const char EXPECTED_HASH[] =
        "\xb3\x79\x24\x9a\x3c\xa5\xf1\x4c\x29\x45\x67\x10\x11\x4b\xa6\xf6"
        "\x13\x6b\x34\xc3\xfc\x9f\x6f\xb9\x1b\x59\xd4\x91\xaf\x78\x2d\x6b"
        "\x23\x7e\xb7\x1a\xaf\xfd\xd3\x80\x79\x46\x1c\xf6\x90\xa4\x6d\x9a"
        "\x4d\xdd\x60\x2d\x19\x80\x8a\xb6\x23\x5d\x1d\x8a\xa0\x1e\x82\x00";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 20.
 */
BEGIN_TEST_F(hash_20)
    const char INPUT[] =
        "\xe0\x70\x56\xd4\xf7\x27\x7b\xc5\x48\x09\x95\x77\x72\x0a\x58\x1e"
        "\xec\x94\x14\x1d";
    const char EXPECTED_HASH[] =
        "\x59\xf1\x85\x63\x03\xff\x16\x5e\x2a\xb5\x68\x3d\xdd\xeb\x6e\x8a"
        "\xd8\x1f\x15\xbb\x57\x85\x79\xb9\x99\xeb\x57\x46\x68\x0f\x22\xcf"
        "\xec\x6d\xba\x74\x1e\x59\x1c\xa4\xd9\xe5\x39\x04\x83\x77\x01\xb3"
        "\x74\xbe\x74\xbb\xc0\x84\x7a\x92\x17\x9a\xc2\xb6\x74\x96\xd8\x07";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 21.
 */
BEGIN_TEST_F(hash_21)
    const char INPUT[] =
        "\x67\xeb\xda\x0a\x35\x73\xa9\xa5\x87\x51\xd4\x16\x9e\x10\xc7\xe8"
        "\x66\x3f\xeb\xb3\xa8";
    const char EXPECTED_HASH[] =
        "\x13\x96\x3f\x81\xcf\xab\xfc\xa7\x1d\xe4\x73\x9f\xd2\x4a\x10\xce"
        "\x38\x97\xbb\xa1\xd7\x16\x90\x7f\xc0\xa2\x84\x90\xc1\x92\xa7\xfc"
        "\x3c\xcb\x8d\xb1\xf9\x1a\xf7\xa2\xd2\x50\xd6\x61\x7f\x0d\xfd\x15"
        "\x19\xd2\x21\xd6\x18\xa0\x2e\x3e\x3f\xa9\x04\x1c\xf3\x5e\xd1\xea";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 22.
 */
BEGIN_TEST_F(hash_22)
    const char INPUT[] =
        "\x63\xe0\x9d\xb9\x9e\xb4\xcd\x62\x38\x67\x78\x59\xa5\x67\xdf\x31"
        "\x3c\x85\x20\xd8\x45\xb4";
    const char EXPECTED_HASH[] =
        "\x90\x83\xe5\x34\x8b\x08\xeb\x98\x10\xb2\xd1\x57\x81\xd8\x26\x58"
        "\x45\x41\x0d\xe5\x4f\xe6\x17\x50\xd4\xb9\x38\x53\x69\x06\x49\xad"
        "\xc6\xe7\x24\x90\xbc\x2b\x7c\x36\x5e\x23\x90\x57\x3d\x94\x14\xbe"
        "\xcc\x09\x39\x71\x9e\x0c\xb7\x8e\xca\x6b\x2c\x80\xc2\xfd\xa9\x20";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 23.
 */
BEGIN_TEST_F(hash_23)
    const char INPUT[] =
        "\xf3\xe0\x6b\x4b\xd7\x9e\x38\x0a\x65\xcb\x67\x9a\x98\xcc\xd7\x32"
        "\x56\x3c\xc5\xeb\xe8\x92\xe2";
    const char EXPECTED_HASH[] =
        "\x6b\x31\x5f\x10\x6b\x07\xc5\x9e\xed\xc5\xab\x1d\xf8\x13\xb3\xc0"
        "\xb9\x03\x06\x0e\x72\x17\xcc\x01\x0e\x90\x70\x27\x85\x12\xa8\x85"
        "\x00\x8d\xac\x8b\x24\x72\xa5\x21\xe7\x78\x35\xa7\xf4\xde\xad\xc1"
        "\xd5\x91\xaa\x23\xb6\x24\xb6\x99\x48\xa9\x9b\xb6\x01\x21\xc5\x4e";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 24.
 */
BEGIN_TEST_F(hash_24)
    const char INPUT[] =
        "\x16\xb1\x70\x74\xd3\xe3\xd9\x75\x57\xf9\xed\x77\xd9\x20\xb4\xb1"
        "\xbf\xf4\xe8\x45\xb3\x45\xa9\x22";
    const char EXPECTED_HASH[] =
        "\x68\x84\x13\x45\x82\xa7\x60\x04\x64\x33\xab\xcb\xd5\x3d\xb8\xff"
        "\x1a\x89\x99\x58\x62\xf3\x05\xb8\x87\x02\x0f\x6d\xa6\xc7\xb9\x03"
        "\xa3\x14\x72\x1e\x97\x2b\xf4\x38\x48\x3f\x45\x2a\x8b\x09\x59\x62"
        "\x98\xa5\x76\xc9\x03\xc9\x1d\xf4\xa4\x14\xc7\xbd\x20\xfd\x1d\x07";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 25.
 */
BEGIN_TEST_F(hash_25)
    const char INPUT[] =
        "\x3e\xdf\x93\x25\x13\x49\xd2\x28\x06\xbe\xd2\x53\x45\xfd\x5c\x19"
        "\x0a\xac\x96\xd6\xcd\xb2\xd7\x58\xb8";
    const char EXPECTED_HASH[] =
        "\x29\x9e\x0d\xaf\x66\x05\xe5\xb0\xc3\x0e\x1e\xc8\xbb\x98\xe7\xa3"
        "\xbd\x7b\x33\xb3\x88\xbd\xb4\x57\x45\x2d\xab\x50\x95\x94\x40\x6c"
        "\x8e\x7b\x84\x1e\x6f\x4e\x75\xc8\xd6\xfb\xd6\x14\xd5\xeb\x9e\x56"
        "\xc3\x59\xbf\xaf\xb4\x28\x57\x54\x78\x7a\xb7\x2b\x46\xdd\x33\xf0";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 26.
 */
BEGIN_TEST_F(hash_26)
    const char INPUT[] =
        "\xb2\xd5\xa1\x4f\x01\xe6\xb7\x78\x88\x8c\x56\x2a\x05\x9e\xc8\x19"
        "\xad\x89\x99\x2d\x16\xa0\x9f\x7a\x54\xb4";
    const char EXPECTED_HASH[] =
        "\xab\x2e\x7d\x74\x5d\x8a\xd3\x93\x43\x9a\xf2\xa3\xfb\xc9\xcd\xc2"
        "\x55\x10\xd4\xa0\x4e\x78\xb5\x26\xe1\x2b\x1c\x0b\xe3\xb2\x29\x66"
        "\x87\x2e\xbe\x65\x2e\x2f\x46\xed\x5c\x5a\xce\xcd\x2f\x23\x3a\x91"
        "\x75\xdd\x29\x5e\xbe\xb3\xa0\x70\x6f\xc6\x6f\xa1\xb1\x37\x04\x2b";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 27.
 */
BEGIN_TEST_F(hash_27)
    const char INPUT[] =
        "\x84\x4b\x66\xf1\x2b\xa0\xc5\xf9\xe9\x27\x31\xf5\x71\x53\x9d\x1e"
        "\xef\x33\x2e\x15\x49\xa4\x9d\xbf\xa4\xc6\xde";
    const char EXPECTED_HASH[] =
        "\xc3\xf9\xc5\x78\x19\x25\x77\x47\x83\xae\x9d\x83\x97\x72\xd7\x51"
        "\x3d\xfc\xea\x8c\x5a\xf8\xda\x26\x2c\x19\x6f\x9f\xe8\x01\x35\xb2"
        "\xb0\xc8\xc6\xca\x0a\x16\x04\xe0\xa3\x46\x02\x47\x62\x0d\xe2\x0b"
        "\x29\x9f\x2d\xb7\x87\x19\x82\xd2\x7c\x21\x76\xae\x5f\xa7\xad\x65";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 28.
 */
BEGIN_TEST_F(hash_28)
    const char INPUT[] =
        "\x6b\x6c\xc6\x92\xd3\x98\x60\xb1\xf3\x02\x03\x65\x3e\x25\xd0\x9c"
        "\x01\xe6\xa8\x04\x3c\x1a\x9c\xb8\xb2\x49\xa4\x1e";
    const char EXPECTED_HASH[] =
        "\x2e\x52\x63\xd9\xa4\xf2\x1b\x21\x0e\x0e\x16\x1e\xd3\x9d\xf4\x41"
        "\x02\x86\x43\x25\x78\x86\x47\x26\x1a\x6e\x70\xea\x4b\x1e\xe0\xab"
        "\xb5\x7b\x57\x49\x9b\xc8\x21\x58\xd8\x23\x36\xdd\x53\xf1\xef\x44"
        "\x64\xc6\xa0\x81\x26\xe1\x38\xb2\xcc\x08\x92\xf7\x65\xf6\xaf\x85";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 29.
 */
BEGIN_TEST_F(hash_29)
    const char INPUT[] =
        "\xab\x1f\xc9\xee\x84\x5e\xeb\x20\x5e\xc1\x37\x25\xda\xf1\xfb\x1f"
        "\x5d\x50\x62\x9b\x14\xea\x9a\x22\x35\xa9\x35\x0a\x88";
    const char EXPECTED_HASH[] =
        "\x72\xd1\x88\xa9\xdf\x5f\x3b\x00\x05\x7b\xca\x22\xc9\x2c\x0f\x82"
        "\x28\x42\x2d\x97\x43\x02\xd2\x2d\x4b\x32\x2e\x7a\x6c\x8f\xc3\xb2"
        "\xb5\x0e\xc7\x4c\x68\x42\x78\x1f\x29\xf7\x07\x5c\x3d\x4b\xd0\x65"
        "\x87\x86\x48\x84\x6c\x39\xbb\x3e\x4e\x26\x92\xc0\xf0\x53\xf7\xed";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 30.
 */
BEGIN_TEST_F(hash_30)
    const char INPUT[] =
        "\x59\x4e\xd8\x2a\xcf\xc0\x3c\x0e\x35\x9c\xc5\x60\xb8\xe4\xb8\x5f"
        "\x6e\xe7\x7e\xe5\x9a\x70\x02\x3c\x2b\x3d\x5b\x32\x85\xb2";
    const char EXPECTED_HASH[] =
        "\x5e\xf3\x22\xcb\x40\x14\xec\xbb\x71\x3a\x13\x65\x96\x12\xa2\x22"
        "\x22\x59\x84\xd3\x1c\x18\x7d\xeb\xc4\x45\x9b\xa7\x90\x1f\x03\xda"
        "\xc7\x75\x40\x0a\xcf\xe3\x51\x0b\x30\x6b\x79\x89\x4f\xb0\xe8\x43"
        "\x7b\x41\x21\x50\xc9\x19\x3e\xe5\xa2\x16\x43\x06\xeb\xb7\x83\x01";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 31.
 */
BEGIN_TEST_F(hash_31)
    const char INPUT[] =
        "\xf2\xc6\x6e\xfb\xf2\xa7\x6c\x5b\x04\x18\x60\xea\x57\x61\x03\xcd"
        "\x8c\x6b\x25\xe5\x0e\xca\x9f\xf6\xa2\xfa\x88\x08\x3f\xe9\xac";
    const char EXPECTED_HASH[] =
        "\x79\x78\xf9\x3e\xf7\xed\x02\xc4\xa2\x4a\xbe\xcb\xa1\x24\xd1\x4d"
        "\xd2\x14\xe1\x49\x2f\xf1\xe1\x68\x30\x4c\x0e\xab\x89\x63\x7d\xa0"
        "\xf7\xa5\x69\xc4\x3d\xc4\x56\x2b\xdb\x94\x04\xa0\x18\xb6\x31\x4f"
        "\xe0\xee\xba\xcc\xfb\x25\xba\x76\x50\x6a\xa7\xe9\xdc\xd9\x56\xa7";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 32.
 */
BEGIN_TEST_F(hash_32)
    const char INPUT[] =
        "\x8c\xcb\x08\xd2\xa1\xa2\x82\xaa\x8c\xc9\x99\x02\xec\xaf\x0f\x67"
        "\xa9\xf2\x1c\xff\xe2\x80\x05\xcb\x27\xfc\xf1\x29\xe9\x63\xf9\x9d";
    const char EXPECTED_HASH[] =
        "\x45\x51\xde\xf2\xf9\x12\x73\x86\xee\xa8\xd4\xda\xe1\xea\x8d\x8e"
        "\x49\xb2\xad\xd0\x50\x9f\x27\xcc\xbc\xe7\xd9\xe9\x50\xac\x7d\xb0"
        "\x1d\x5b\xca\x57\x9c\x27\x1b\x9f\x2d\x80\x67\x30\xd8\x8f\x58\x25"
        "\x2f\xd0\xc2\x58\x78\x51\xc3\xac\x8a\x0e\x72\xb4\xe1\xdc\x0d\xa6";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 33.
 */
BEGIN_TEST_F(hash_33)
    const char INPUT[] =
        "\x9f\x8c\x49\x32\x0a\xf9\x37\x0c\xd3\xdb\x20\xe9\xb5\x0d\x3e\xaa"
        "\x59\xa6\x23\x2d\x7a\x86\xfb\x7d\x47\x2f\x12\x45\x08\xd7\x96\x8b"
        "\x05";
    const char EXPECTED_HASH[] =
        "\x81\xb0\x02\xf1\x5c\x4d\x48\xbe\x85\x17\xf7\xed\x89\xdf\x30\x2f"
        "\xb1\x43\x5c\x94\x35\xef\xef\xed\x58\xf3\xeb\x8e\xa1\x19\x10\x62"
        "\x3f\x1e\xb9\x02\x8a\x66\xe0\x21\x21\xa7\xf0\x8a\x7c\x60\x42\x26"
        "\xf2\x32\x4f\x48\x3e\x91\x54\x8d\xbb\xd2\xc4\x41\xab\x70\x4c\xe5";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 34.
 */
BEGIN_TEST_F(hash_34)
    const char INPUT[] =
        "\x4a\xb9\xaa\x06\x94\x75\xe5\x4b\x25\xe5\x68\x8a\x52\xdd\x4a\xcd"
        "\x13\x41\x69\xc8\x58\x10\x5f\x01\xa0\xa1\xb1\x34\xc7\x2d\x4a\xf5"
        "\x1f\x8e";
    const char EXPECTED_HASH[] =
        "\x48\xba\x5a\x63\xab\xa7\xe7\xbd\x8e\x42\x04\x75\x33\x11\x25\xa9"
        "\x47\x92\x8c\x67\xfd\xb0\x0f\x65\xc4\x08\x0d\x9a\x0b\x99\xc0\x67"
        "\x24\x24\xe7\x6a\x1b\xa6\xbd\x76\xdf\xe4\x92\xc7\x30\xf6\xf9\xad"
        "\xcc\xae\xe7\xbb\x11\x57\x1a\xad\xb3\x1f\x6b\xb6\x28\xcf\xa9\x33";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 35.
 */
BEGIN_TEST_F(hash_35)
    const char INPUT[] =
        "\xf0\xc1\xd3\x40\x7d\xe9\x2e\xf7\x42\x1e\x42\xdf\x5c\x9a\xb3\x1d"
        "\x2e\xc0\xa7\x50\xa9\x52\x28\x69\xcb\xe4\xca\xbd\x66\x90\x8d\x58"
        "\x23\xec\x04";
    const char EXPECTED_HASH[] =
        "\x9e\x75\xc5\xbc\xa2\xc2\xaf\x1d\x77\x39\x78\x7f\x46\xe1\xd9\x81"
        "\xc4\xf9\x8e\x49\x3d\x07\x24\xb5\x25\x2c\x2f\xba\xe3\xc5\x26\x71"
        "\x9f\x1d\x27\xe6\xcc\xd0\xd7\x05\x24\x02\x81\xe8\xfb\xf3\xdb\x75"
        "\xb9\xb3\x20\x5c\x14\x13\x43\x6d\x3b\x5d\x14\x00\x04\xb8\xcc\xa1";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 36.
 */
BEGIN_TEST_F(hash_36)
    const char INPUT[] =
        "\xae\x8c\x9f\x8f\xb4\x1b\x51\x9b\x6d\x94\x38\x33\xfe\x1c\x32\xd1"
        "\xc4\x29\x2f\xb1\xdd\xf1\xdb\xe2\xeb\x22\x7d\x9e\x14\xd3\x1e\xd7"
        "\x4e\xba\xef\x12";
    const char EXPECTED_HASH[] =
        "\x04\x2f\x9f\xd0\xa4\xed\x3d\x9f\xec\x36\x55\xae\x11\x01\x1c\x6f"
        "\x2b\xc7\xe4\x57\xe8\x81\x2b\x6d\x8b\xe2\xcd\x45\xfc\x6c\x43\x2a"
        "\x94\x55\x8c\x88\xf2\x2c\x01\x43\x96\x18\x86\x5e\x8e\x49\xe5\x09"
        "\xc4\x48\xb3\x42\xca\x91\x4b\x12\x03\x44\xaa\xf7\xbc\xbd\xca\x18";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 37.
 */
BEGIN_TEST_F(hash_37)
    const char INPUT[] =
        "\xda\x39\xfb\x86\x23\x7f\x00\x30\x38\x44\xe6\x1f\xc6\xcf\xe7\x79"
        "\xe4\x2a\xf5\x33\x49\x83\x95\x90\xbc\xd2\xf0\xe4\xcb\xbc\x27\x9e"
        "\xc0\xb7\xe8\x85\xd1";
    const char EXPECTED_HASH[] =
        "\xec\xb4\x3d\xe8\xc2\x33\xa7\x31\xb3\x8e\x30\xc5\x69\x6f\x88\x76"
        "\x76\x1b\x7e\xa7\x2e\xfe\x28\x3f\xd0\x7b\xed\xf2\x00\x29\xf4\x7c"
        "\x6d\x2a\x44\x27\x82\x3e\x10\x0f\xb0\x87\xab\xaf\x22\xd7\xef\xf4"
        "\x2a\x95\x1c\x97\xc3\xdd\x05\xf4\x8a\x20\x16\x3f\xa4\x36\x7c\xba";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 38.
 */
BEGIN_TEST_F(hash_38)
    const char INPUT[] =
        "\x3e\x72\x71\xd2\x07\x0e\xf0\x95\x39\x46\x20\xc4\xb0\x16\x57\x6c"
        "\x15\x0f\x34\xbe\xa6\x07\x84\x61\x3a\x0f\x66\x0d\x7f\xa5\xae\x56"
        "\x87\x2b\x88\xc5\x83\x98";
    const char EXPECTED_HASH[] =
        "\x81\x54\xd0\xda\x63\x4a\xb2\x26\x60\x61\xac\xc1\x23\xac\xb4\x07"
        "\x65\x0f\xfe\x91\x64\xa2\x2d\xe3\xfe\x29\xbf\x05\x39\x3b\x2a\xec"
        "\xe9\x2c\xf4\xdb\x00\xea\x5b\x43\x41\xc3\x1d\xdb\x7d\xe1\x51\x68"
        "\x3c\x8a\x71\xb5\xa4\x4d\x5c\x31\x75\x79\x0f\xea\xc6\x7d\x18\xee";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 39.
 */
BEGIN_TEST_F(hash_39)
    const char INPUT[] =
        "\x31\x1f\xb6\x7f\x6a\x07\x84\xbb\x01\xa2\xd5\xa3\xf3\x09\x2c\x40"
        "\x7a\x9d\x33\x22\x31\x9d\xff\x9a\x79\xf8\x94\x29\x1c\x5f\xac\x37"
        "\x31\x9f\xb4\x08\x40\x2e\x18";
    const char EXPECTED_HASH[] =
        "\x18\x70\xfe\x91\x3a\xbb\x0a\x4b\x4f\x53\xb6\x58\x1a\xe1\x83\x22"
        "\xcd\x05\x32\x85\x14\x55\x66\x07\xf3\xf4\xd7\xb6\xa2\xac\x8e\x91"
        "\x85\xd9\x4d\x94\x7d\x8b\x9c\x88\xe0\xef\xa6\x6d\x89\xb5\x9f\x74"
        "\x39\xc7\x5f\xda\xdd\x18\x16\xf7\x41\x23\x06\xab\x2b\x59\xd6\x64";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 40.
 */
BEGIN_TEST_F(hash_40)
    const char INPUT[] =
        "\x76\x51\xab\x49\x1b\x8f\xa8\x6f\x96\x9d\x42\x97\x7d\x09\xdf\x5f"
        "\x8b\xee\x3e\x58\x99\x18\x0b\x52\xc9\x68\xb0\xdb\x05\x7a\x6f\x02"
        "\xa8\x86\xad\x61\x7a\x84\x91\x5a";
    const char EXPECTED_HASH[] =
        "\xf3\x5e\x50\xe2\xe0\x2b\x87\x81\x34\x5f\x8c\xeb\x21\x98\xf0\x68"
        "\xba\x10\x34\x76\xf7\x15\xcf\xb4\x87\xa4\x52\x88\x2c\x9f\x0d\xe0"
        "\xc7\x20\xb2\xa0\x88\xa3\x9d\x06\xa8\xa6\xb6\x4c\xe4\xd6\x47\x0d"
        "\xfe\xad\xc4\xf6\x5a\xe0\x66\x72\xc0\x57\xe2\x9f\x14\xc4\xda\xf9";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 41.
 */
BEGIN_TEST_F(hash_41)
    const char INPUT[] =
        "\xdb\xe5\xdb\x68\x5e\xd7\xcb\x84\x8c\x09\x45\x24\xc1\x72\x35\x19"
        "\xd4\x9d\xc6\x6e\xf9\xfe\x6d\x57\xe6\x86\x2a\x64\x35\x75\x0b\xfa"
        "\x0a\x70\xf1\x04\xf5\xd3\x96\xe6\x1a";
    const char EXPECTED_HASH[] =
        "\x2f\xa6\xe5\xb2\xc4\x43\xa6\x80\x50\xf0\x93\xe7\xfb\x71\x3b\xd6"
        "\xb1\x8f\x62\x74\xc0\x61\xed\x61\xd7\x9b\xf0\x68\x8a\x61\xdb\xa1"
        "\x94\x0b\xcc\x30\x99\x82\x76\x86\x09\x43\xab\x03\x89\x02\x89\x6d"
        "\x0f\xbf\x59\xb8\x8b\x07\xc8\x0d\xe9\x27\x03\x70\x97\x15\x0c\x40";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 42.
 */
BEGIN_TEST_F(hash_42)
    const char INPUT[] =
        "\x9f\xa8\x3e\x96\xb2\xa6\xdf\x23\xfb\x37\x28\x95\x01\x56\x78\xe0"
        "\xb2\xc9\xcd\x18\xa8\x54\x2c\x3e\xaa\x2c\x43\x5a\x76\xae\x4d\xc9"
        "\xbd\x51\x36\xd9\x70\xda\xff\x93\x3a\xcf";
    const char EXPECTED_HASH[] =
        "\x3a\x2c\x0e\xc8\x8a\x3e\x53\x47\xcf\x0e\xa9\xc0\x78\x83\x83\x00"
        "\xef\x73\x56\xf9\xa6\xc3\x42\x06\x32\x77\xc1\x06\xb8\x80\xa0\x0e"
        "\xd2\xbe\x20\x5c\x13\x06\x40\x97\xbd\x37\x2f\xde\x38\x00\x7b\xc3"
        "\x06\x56\x1e\xb4\xe7\x4b\xba\x2b\xb2\x0b\xd3\x54\xaa\x69\x0c\xa6";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 43.
 */
BEGIN_TEST_F(hash_43)
    const char INPUT[] =
        "\x8a\x5a\x45\xe3\x98\xba\xc1\xd9\xb8\x96\xb5\xa2\xb4\xe3\x56\x6b"
        "\x91\xd8\x0a\xd2\x0c\x97\x7e\xa7\x45\x0f\xf2\xef\xb5\x21\xd8\x2f"
        "\x65\x01\x9e\xe7\x62\xe0\xc8\x5c\x6c\xc8\x41";
    const char EXPECTED_HASH[] =
        "\x3c\x70\x46\x20\xf4\x06\x6d\x79\xc1\xff\x67\x75\x29\x80\xf3\x9e"
        "\xf3\xd9\xc1\x02\x3f\xa5\xa2\x13\xa5\x26\x53\x76\xb1\x4a\x15\x16"
        "\x6f\xfe\x06\x9b\x51\xdf\x77\x10\xd8\x90\x7f\xef\x94\x06\xbf\x37"
        "\x5d\x50\x2c\xe0\x86\xac\x82\xaf\xf1\x72\x29\xaa\xa7\xa5\xa3\x34";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 44.
 */
BEGIN_TEST_F(hash_44)
    const char INPUT[] =
        "\x49\xcf\xff\xda\xf4\xd0\x31\xe3\x3b\x1d\x28\xa4\x47\x45\x05\x45"
        "\xf6\xc4\x29\x3b\x38\xd5\xaf\xbc\xb9\x88\x39\x76\xc0\x14\xf0\x80"
        "\x57\x6e\xc6\x91\xac\x1b\xff\x70\xb7\x42\xef\xab";
    const char EXPECTED_HASH[] =
        "\x8b\xcc\x4f\x1e\xa2\xb7\x86\x2e\xf1\x59\x1b\xfa\x73\x91\x66\x65"
        "\xde\x8f\xaf\x65\x43\x9d\xdf\x5c\xc1\xbe\x43\xce\xbf\xd5\xf6\x0f"
        "\x20\x5e\x83\x5a\x2b\x18\x6b\x67\x5b\x04\x12\x58\xc5\xcf\xf4\x26"
        "\x69\x31\x6c\xe2\x5b\x46\xa2\xf4\xd4\x21\x8e\x10\x2f\x0f\x5d\x6f";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 45.
 */
BEGIN_TEST_F(hash_45)
    const char INPUT[] =
        "\x2f\xf8\x45\xd8\x5e\xfb\xc4\xfa\x56\x37\xe9\x44\x8d\x95\x04\x96"
        "\xf1\x9d\x8d\x57\xda\x99\xb7\xbd\x3d\xf7\x47\x48\x22\xf0\xa7\x90"
        "\x58\x67\x36\x41\x67\x14\xe3\x64\xc6\xe1\xfa\xe0\x4e";
    const char EXPECTED_HASH[] =
        "\x23\x6f\x6f\x4e\xd6\xe8\x58\xc0\x2d\x51\x78\x7e\x60\xc5\x78\xf7"
        "\x31\xf6\x94\xf8\xe5\x2b\x5d\xf4\xec\xd5\xb0\x4d\xff\x14\xc7\x8e"
        "\x56\xba\xd1\x02\x8d\x6f\x62\x6c\x29\xd8\x5a\xee\xe1\x51\xa2\xa2"
        "\x84\x6d\x3e\xed\x5c\xfa\xfa\x98\x54\xa6\x9f\xea\x8a\xf6\xd0\x4a";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 46.
 */
BEGIN_TEST_F(hash_46)
    const char INPUT[] =
        "\xcf\xca\x05\xfd\x89\x3c\x0f\x00\x5f\x5f\xf7\x96\xf4\xda\x19\xba"
        "\x27\xa1\xe7\x29\x95\x6b\x8b\x71\x5e\x67\xce\x4b\x2d\x2a\x38\x2a"
        "\x72\xec\x78\x14\xf2\xf5\x07\xb1\x82\x52\x09\xa2\x0f\xcc";
    const char EXPECTED_HASH[] =
        "\xd8\x09\x69\x28\x4a\x45\x65\xad\xd4\xda\xd6\xab\x9b\x3b\xdf\x53"
        "\x44\x61\x42\xf8\x4a\xaf\x92\xd4\xb2\x3d\xd2\x2e\xe7\x24\x1e\x6c"
        "\x81\x48\x9a\xc8\xb2\x46\xed\xcb\x6d\xf9\xbd\x7b\x23\xd9\x1a\x0c"
        "\x51\x7f\x54\x6f\xeb\xa4\xed\x57\x90\xa2\xbe\x6e\x16\x5c\x17\x09";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 47.
 */
BEGIN_TEST_F(hash_47)
    const char INPUT[] =
        "\xcf\xc4\x25\x75\x9a\x9c\x36\xbb\x9f\x4b\x32\xee\xd7\x76\x7a\xf6"
        "\x56\x6f\x68\xde\xd0\xad\xea\xe2\x5c\x7a\x70\xca\x78\xec\x09\x77"
        "\x4d\x16\xc8\xbc\x35\x7f\x6d\x6f\x7b\xd4\x41\xbf\x62\xd9\x42";
    const char EXPECTED_HASH[] =
        "\xb5\x87\xa7\x85\xcd\xf4\x55\xcc\x9c\x54\x4e\x75\x6c\x1e\x30\x63"
        "\x00\xaa\x3c\x59\xf8\x72\x50\x12\xe6\x8a\xb4\xd5\x40\x20\xb6\xd2"
        "\x27\xa1\x64\xd9\xf8\x3c\x90\x5e\x86\xf8\xce\xbe\xef\x70\x8a\x69"
        "\xf9\x76\xd6\xe7\xb1\x8b\x9b\xf7\x8e\x9b\x98\xcc\x4a\x5c\xd1\xb6";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 48.
 */
BEGIN_TEST_F(hash_48)
    const char INPUT[] =
        "\x09\x7c\x9d\xb9\x19\x51\x52\x42\xc9\x9d\x97\x3a\xcb\x1d\xc4\xed"
        "\x48\x27\x68\xf9\x74\xeb\x83\xb4\x65\xf9\xf6\xc8\x25\x03\x37\x20"
        "\x06\xe4\x49\x08\x35\xe2\xec\x8f\x92\x30\x11\x30\xbf\xb7\x90\xb2";
    const char EXPECTED_HASH[] =
        "\xff\x5a\x37\x6f\x93\x8e\x73\x01\x4c\xae\xf7\xfe\x39\x62\x94\x4a"
        "\x72\x30\xd0\x20\xb7\x08\x78\x69\xeb\xe7\xec\x70\x30\x27\x21\xcd"
        "\x06\xfc\xdc\x98\x1c\x89\x3a\x42\x5d\x05\xe2\xf9\x9f\xe1\x98\xe4"
        "\xdb\x50\xa0\x88\xae\xe2\xbf\x12\x63\x21\x21\x10\xef\xed\x42\x2c";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 49.
 */
BEGIN_TEST_F(hash_49)
    const char INPUT[] =
        "\x77\xe7\x3d\x38\x7e\x7b\xc8\x04\x19\xeb\xf5\x48\x2b\x61\xd5\x25"
        "\x5c\xaf\x81\x9f\xb5\x92\x51\xff\x6a\x38\x4e\x75\xf6\x01\xea\x02"
        "\x6d\x83\xef\x95\x0e\xd0\xb6\x75\x18\xfb\x99\xde\xe0\xd8\xaa\xef"
        "\x1f";
    const char EXPECTED_HASH[] =
        "\xc4\xc8\x9c\xd8\x82\xec\x94\x5c\xc8\x88\xfb\x9a\x01\x27\xd3\x5e"
        "\x58\x5e\xcc\x14\xa7\x5e\x4b\x5b\x3d\x83\x30\x53\x8d\x22\xda\x28"
        "\xcf\x6a\xf1\xeb\xec\x96\xdc\x24\x7f\x10\x9c\xd2\xaa\xab\x97\x56"
        "\xe6\x94\x6a\x3d\x80\xdb\x83\x63\xa4\xda\x3e\x6d\xdb\xb5\x10\xa1";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 50.
 */
BEGIN_TEST_F(hash_50)
    const char INPUT[] =
        "\x31\x7e\x5d\x9a\xc7\x3e\xd0\x63\x3f\xa1\x8e\xbe\xbb\xca\x79\x09"
        "\xec\x3a\x5e\xf7\x90\x47\x8f\x9c\x38\xca\xce\xc4\x4f\x19\x6d\x89"
        "\x58\x35\xb4\x25\x77\x44\x83\x04\x33\x41\x38\x1e\x7a\xf2\xd3\x83"
        "\xe5\x1a";
    const char EXPECTED_HASH[] =
        "\xb1\x0b\xb0\x44\x91\xb9\xc0\xc3\x34\x70\x9b\x40\x7c\xda\x1d\x50"
        "\x3e\xfb\x6b\x63\xee\x94\x4f\x2d\x36\x6b\x68\x55\xe6\xe6\x3e\x5b"
        "\x80\x11\x5b\xe4\xbe\x7f\xf6\x3e\xde\xcd\xfb\x59\x23\x79\x2e\x68"
        "\x12\x39\x76\xd7\x92\x12\xb3\x88\x4d\xec\x21\x79\xd1\xfc\xf3\x82";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 51.
 */
BEGIN_TEST_F(hash_51)
    const char INPUT[] =
        "\x20\x94\x61\xf2\x06\x66\xa3\x46\xfe\xdf\x4a\x53\x0f\x41\xa6\xfa"
        "\x28\x0c\x43\x66\x57\x67\xbe\x92\x3b\xc1\xd8\x0b\xbc\xb8\xc9\xf8"
        "\xf9\x3a\xd7\x57\x82\xea\x26\x89\xc8\xc5\xd2\x11\xd2\x05\x3b\x99"
        "\x31\x45\xa0";
    const char EXPECTED_HASH[] =
        "\x67\xb7\xa3\x28\xd9\x44\x40\x56\xa5\x2c\xa2\xf6\x95\xc5\xd3\xf3"
        "\xba\xaf\xb6\x25\xa1\x4f\xb3\x2e\xee\x8f\xf2\x6a\x40\xcc\xb2\x96"
        "\xbe\xc1\x77\x1a\x82\x6b\x55\xf7\xdd\xb6\x17\x0d\x4c\xaf\x77\x95"
        "\xb6\x12\x44\x8e\x66\xa0\xf1\x93\x56\xfe\x50\x59\x27\x14\x9b\x47";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 52.
 */
BEGIN_TEST_F(hash_52)
    const char INPUT[] =
        "\x5d\x61\xaa\x45\xc4\x46\xf3\xbf\x93\x60\x4b\x05\x11\x31\x3b\x4e"
        "\x2f\x30\x6d\x6b\x04\x6f\xbd\x94\x79\x7b\x92\x67\x46\x83\x6f\x2e"
        "\x1d\xbd\xc5\x61\x24\x06\x0c\x6c\xa9\xc9\x11\xb1\x12\x21\x92\xd1"
        "\x12\x42\x08\x27";
    const char EXPECTED_HASH[] =
        "\xd3\x93\x1b\xde\x2b\xde\x82\x71\xed\x18\xca\x0b\x91\x48\xb1\x2f"
        "\x6f\x16\x16\x1e\x63\x7e\x37\x6f\xc9\x61\xf6\x5b\xc3\x3b\xca\xcf"
        "\x2f\x6a\xdd\xf2\x6a\x3e\xaa\x81\xb1\x96\x65\x3c\xc3\x7e\x8a\x73"
        "\x9e\xc5\xb3\xdf\x87\x0d\x8c\x38\xc8\xf2\x86\x91\xc2\x2a\x39\xbb";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 53.
 */
BEGIN_TEST_F(hash_53)
    const char INPUT[] =
        "\x92\x88\xc7\x95\xbb\x0b\x86\xc0\x41\x9d\x9c\x56\x37\xdc\xc3\x7b"
        "\x39\xbf\xa1\x8d\x44\x1e\x3f\xbf\xca\x75\xbc\x03\x06\xe5\x43\x2e"
        "\x8e\x7b\x3a\x56\x27\xb5\xbc\x7f\xdc\x42\x4a\x77\x52\x0a\xbd\xff"
        "\x56\x6e\x7f\x2b\xb8";
    const char EXPECTED_HASH[] =
        "\xe3\x63\xd0\xe9\x5d\x8c\xd1\x8c\x38\x40\x16\xeb\xee\xd6\xd9\x9c"
        "\x4f\xa2\x76\x8e\x2b\xd5\x8f\xca\x01\x9c\x51\x08\xb9\xcd\xe1\xcb"
        "\x46\xf3\xf8\x84\x02\x8a\x55\xce\x28\x2e\xc3\x10\xa1\x00\x37\xfa"
        "\xa1\xb1\x6b\x4a\x6a\x66\x99\x57\xf0\xb0\x0f\x35\x0b\xbd\x63\xd0";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 54.
 */
BEGIN_TEST_F(hash_54)
    const char INPUT[] =
        "\x78\x04\x27\xdc\x16\x4b\x2f\x69\xb8\xc7\xd5\x69\x26\x6f\x46\x1e"
        "\x2d\x30\xc8\x8c\x4c\xd6\x05\x7f\xb0\x30\xa6\xcf\x63\x6f\x24\xe3"
        "\xc0\xd0\xdb\x74\x2a\x7b\x61\x93\xfd\xaa\x15\xee\xc5\x0d\xfb\x4f"
        "\xae\x6e\xc7\x65\x3c\x91";
    const char EXPECTED_HASH[] =
        "\x29\x64\xb0\x09\xfb\x1b\xf9\x96\xde\x12\xe0\x30\xb9\xd6\xe0\x60"
        "\x8a\xe8\xb9\xdb\xf2\xac\xfb\x9b\xeb\x76\xfc\x53\x61\xcc\x10\x4e"
        "\xe8\x5c\x2a\x46\xfb\x7b\x4c\xee\x90\x84\x83\x12\xda\x30\x2d\xe4"
        "\x9a\xfe\x61\xc5\x46\x47\x7e\x2b\x25\xd2\x23\xd5\xe3\xd3\x35\x60";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 55.
 */
BEGIN_TEST_F(hash_55)
    const char INPUT[] =
        "\xec\x2a\x92\xe4\x7f\x69\x2b\x53\xc1\x35\x54\x75\xc7\x1c\xef\xf0"
        "\xb0\x95\x2a\x8b\x35\x41\xb2\x93\x82\x70\x24\x7d\x44\xe7\xc5\xcc"
        "\x04\xe1\x72\x36\xb3\x53\xda\x02\x86\x74\xea\xb4\x04\x7d\x89\xec"
        "\x5d\xad\x86\x8c\xfd\x91\xce";
    const char EXPECTED_HASH[] =
        "\xc8\x3a\xca\x61\x47\xbf\xcb\xbc\x72\xc3\x77\xef\xa8\xd5\x36\x54"
        "\xba\x08\x30\xc5\xa6\xa8\x9e\x1d\x2a\x19\xb7\x13\xe6\x8f\xb5\x34"
        "\x64\x0d\xeb\x83\x3c\xa5\x12\x24\x71\x66\xdd\x27\x3b\x58\x97\xe5"
        "\x7d\x52\x6f\x88\xee\xf5\x8f\x6f\xf9\x7b\xae\xe0\xb4\xee\x56\x44";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 56.
 */
BEGIN_TEST_F(hash_56)
    const char INPUT[] =
        "\xc9\x9e\x31\xad\x4e\x23\xac\x68\xe1\x5e\x60\x5d\x0b\x02\x43\x7f"
        "\x81\x47\xc4\x4f\x54\x45\xa5\x5b\x68\xa1\x09\x05\x27\x6c\xce\x86"
        "\x76\x48\x1c\x33\xe8\xcd\x3e\xfe\x32\x2b\xb1\x3f\xe0\x10\x7b\xb5"
        "\x46\xcc\xbe\xc7\xb8\xb3\x8d\x10";
    const char EXPECTED_HASH[] =
        "\x52\x99\x2d\x45\xa8\x82\x21\xd9\x72\x95\x8e\x9f\x28\x54\xad\xaa"
        "\x9a\x21\xd2\xbf\x70\x51\xe1\xf1\x01\x9a\xe7\x80\x04\xda\x50\xc5"
        "\xb5\x5c\x14\x4a\x02\xaf\xff\xe5\x39\xd7\x53\x94\x9a\x2b\x05\x65"
        "\x34\xf5\xb4\xc2\x1f\x24\x8a\x05\xba\xa5\x2a\x6c\x38\xc7\xf5\xdd";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 57.
 */
BEGIN_TEST_F(hash_57)
    const char INPUT[] =
        "\x9a\xa3\xe8\xad\x92\x77\x7d\xfe\xb1\x21\xa6\x46\xce\x2e\x91\x8d"
        "\x1e\x12\xb3\x07\x54\xbc\x09\x47\x0d\x6d\xa4\xaf\x6c\xc9\x64\x2b"
        "\x01\x2f\x04\x1f\xf0\x46\x56\x9d\x4f\xd8\xd0\xdc\xcf\xe4\x48\xe5"
        "\x9f\xee\xfc\x90\x8d\x9a\xd5\xaf\x6f";
    const char EXPECTED_HASH[] =
        "\x99\x4d\x1c\xda\x4d\xe4\x0a\xff\x47\x13\x23\x7c\xf9\xf7\x8f\x70"
        "\x33\xaf\x83\x36\x9a\xc9\xc6\x4e\x50\x40\x91\xea\x2f\x1c\xaf\xf6"
        "\xc5\x15\x2d\x6a\x0c\x56\x08\xf8\x28\x86\xc0\x09\x3b\x3d\x7f\xba"
        "\xdd\x49\xdf\xd1\xf9\xe0\xf8\x5a\xcc\xf2\x3b\xc7\xda\xd4\x89\x04";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 58.
 */
BEGIN_TEST_F(hash_58)
    const char INPUT[] =
        "\x58\x42\x51\x2c\x37\x31\x25\x11\xa3\xd8\xae\x41\xf5\x80\x1d\xf6"
        "\x0c\xd6\x82\xd5\x8b\x4a\x99\x73\x42\xb6\xe7\x17\xe9\x40\x06\xc2"
        "\x14\x81\x3e\x6c\x63\xe7\x55\x91\xf9\x57\xa7\xec\x30\x17\x79\x83"
        "\x8b\xec\x8a\xe3\xed\x7f\xeb\xad\x08\x05";
    const char EXPECTED_HASH[] =
        "\x97\x63\xc4\x33\x31\xad\x0e\xb2\x79\xd7\x04\xc5\xf6\xe9\x7e\x02"
        "\xda\x87\x24\x11\x50\x26\x82\x7f\x88\x9e\x9f\xcd\xa2\x1f\x60\xfd"
        "\x23\x08\x94\xab\x35\xab\xb7\x19\x89\x0f\x3a\xfa\x51\xaf\xd3\x1b"
        "\xc6\x85\x21\x83\xb9\xc5\x10\x59\x91\x0a\xf4\x60\xab\xd2\x47\x4d";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 59.
 */
BEGIN_TEST_F(hash_59)
    const char INPUT[] =
        "\xca\x14\xe2\xea\x2f\x37\xc7\x8f\x78\xef\x28\x0f\x58\x70\x7e\xc5"
        "\x49\xa3\x1a\x94\x36\x10\x73\xe3\x77\x01\xbf\xe5\x03\xe4\xc0\x1e"
        "\xe1\xf2\xe1\x23\xe0\x0e\x81\xa1\x88\xf0\x8f\xa0\x50\x82\x57\x09"
        "\x12\x8a\x9b\x66\xbb\x8a\xe6\xea\x47\xe4\x1d";
    const char EXPECTED_HASH[] =
        "\x46\x00\xe0\x22\xa0\x22\x58\x73\x9f\x67\xfd\xd3\x67\xcc\x1e\x66"
        "\x26\x31\xfb\x08\x79\x18\x76\x83\x52\x06\x2b\x9b\x3c\x8d\xe8\xdb"
        "\xca\x0e\x9e\xc7\x51\xb9\x1f\x28\x46\x94\xfb\xdd\xb8\xd3\x25\xc0"
        "\x63\x7b\xcc\xb2\x1d\xd2\xef\xa9\x2e\x48\xdb\xab\x2e\x5e\x9c\x26";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 60.
 */
BEGIN_TEST_F(hash_60)
    const char INPUT[] =
        "\x64\x76\x29\xc7\x79\xb2\x4c\x1e\x76\xf4\x17\x44\xab\xa1\x71\x59"
        "\x48\x75\x32\xa0\x15\x6a\x7d\x82\x64\xdb\x50\xd6\x45\xe9\x59\x5f"
        "\xf8\x1e\x0c\x96\xa8\x50\xf2\xaa\x56\xc8\x44\xc6\x13\xa4\xb8\x92"
        "\x72\x7a\x9b\xfc\x3d\x3e\x20\x38\x67\x66\xf8\x05";
    const char EXPECTED_HASH[] =
        "\x5b\xc8\x42\xfc\x2d\x3b\x7e\xb3\x1d\x2d\x30\x44\xdf\x3e\xc3\x2a"
        "\xf1\x14\xfe\xaa\x7c\xfc\x27\xeb\xc8\x63\x0f\x46\xab\x6f\x0c\x54"
        "\x3f\x59\xb8\x12\xe7\x76\xe5\x30\x38\x61\xd1\x7d\xa3\xf1\xf1\x60"
        "\x97\x64\x1f\x3b\x80\x8d\x4d\x5c\xb3\xe4\x83\x94\x64\x09\x74\x6c";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 61.
 */
BEGIN_TEST_F(hash_61)
    const char INPUT[] =
        "\x1c\x5d\xc0\xd1\xdd\x2e\x4c\x71\x76\x35\xff\x3e\x9b\x67\xca\xf9"
        "\x57\xae\xc0\xf8\xf6\x3c\x1b\x1e\x22\x1e\x80\x0a\x4c\x14\x84\x8f"
        "\x4e\xa0\x6e\x64\x4e\x5d\x3e\x1d\xe5\x92\xef\x5a\x80\x07\xfa\x3f"
        "\x07\x17\x1b\x24\xbd\x07\x57\x8d\x68\x96\x3e\x5c\xb1";
    const char EXPECTED_HASH[] =
        "\xcb\xf1\xea\x86\xfa\x5b\x3d\xbf\x67\xbe\x82\xfa\xc4\x1e\x84\xcc"
        "\xcd\x0d\x29\x6c\x75\x71\x69\xb3\x78\x37\xd2\x73\xcc\xc0\x15\xee"
        "\xcd\x10\x2b\x9c\xe1\xcf\xf6\x8f\xdc\x7f\x05\xd2\x2f\x2b\x77\x47"
        "\x34\xf6\x2d\xed\x54\xc8\xee\x0b\xf5\x7a\x5a\x82\x01\x0d\x74\xf5";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 62.
 */
BEGIN_TEST_F(hash_62)
    const char INPUT[] =
        "\x8a\x55\x5e\x75\x47\x7d\x06\x5b\x3a\xf7\xe6\x15\x47\x5f\x37\xc0"
        "\xa6\x67\xf7\x3a\x4c\x7a\xf5\xe4\xa6\x9f\x28\xa6\x8d\x9f\x44\x34"
        "\x77\x6a\x8f\x90\xea\xb7\xf1\xd1\x37\xeb\x4b\x22\x64\x3c\x0a\x0d"
        "\x6a\x16\xfc\xfa\xa1\xbd\x62\xf2\x78\x35\x46\xa9\x69\x5f";
    const char EXPECTED_HASH[] =
        "\xc0\x88\xe4\xa3\xd7\xda\x2f\x6f\x99\xa8\xf3\xf7\x17\x36\x11\x08"
        "\x87\x2b\x8f\xfe\xf9\x21\xb3\x83\xc2\x4b\x80\x61\xd4\xe7\xc2\x7f"
        "\xc5\x6f\x4f\x20\xdc\x8f\x95\x2a\x14\x04\x3c\x56\x50\xb5\xa9\xe7"
        "\x77\xc4\x9c\x41\xcf\xeb\x3f\x2d\xe9\x7e\xe2\xe1\x6b\x2c\x39\x24";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 63.
 */
BEGIN_TEST_F(hash_63)
    const char INPUT[] =
        "\xeb\xb3\xe2\xad\x78\x03\x50\x8b\xa4\x6e\x81\xe2\x20\xb1\xcf\xf3"
        "\x3e\xa8\x38\x15\x04\x11\x0e\x9f\x80\x92\xef\x08\x5a\xfe\xf8\x4d"
        "\xb0\xd4\x36\x93\x1d\x08\x5d\x0e\x1b\x06\xbd\x21\x8c\xf5\x71\xc7"
        "\x93\x38\xda\x31\xa8\x3b\x4c\xb1\xec\x6c\x06\xd6\xb9\x87\x68";
    const char EXPECTED_HASH[] =
        "\xf3\x34\x28\xd8\xfc\x67\xaa\x2c\xc1\xad\xcb\x28\x22\xf3\x7f\x29"
        "\xcb\xd7\x2a\xbf\xf6\x81\x90\x48\x3e\x41\x58\x24\xf0\xbc\xec\xd4"
        "\x47\xcb\x4f\x05\xa9\xc4\x70\x31\xb9\xc5\x0e\x04\x11\xc5\x52\xf3"
        "\x1c\xd0\x4c\x30\xce\xa2\xbc\x64\xbc\xf8\x25\xa5\xf8\xa6\x60\x28";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 64.
 */
BEGIN_TEST_F(hash_64)
    const char INPUT[] =
        "\xc1\xca\x70\xae\x12\x79\xba\x0b\x91\x81\x57\x55\x8b\x49\x20\xd6"
        "\xb7\xfb\xa8\xa0\x6b\xe5\x15\x17\x0f\x20\x2f\xaf\xd3\x6f\xb7\xf7"
        "\x9d\x69\xfa\xd7\x45\xdb\xa6\x15\x05\x68\xdb\x1e\x2b\x72\x85\x04"
        "\x11\x3e\xea\xc3\x4f\x52\x7f\xc8\x2f\x22\x00\xb4\x62\xec\xbf\x5d";
    const char EXPECTED_HASH[] =
        "\x04\x6e\x46\x62\x39\x12\xb3\x93\x2b\x8d\x66\x2a\xb4\x25\x83\x42"
        "\x38\x43\x20\x63\x01\xb5\x8b\xf2\x0a\xb6\xd7\x6f\xd4\x7f\x1c\xbb"
        "\xcf\x42\x1d\xf5\x36\xec\xd7\xe5\x6d\xb5\x35\x4e\x7e\x0f\x98\x82"
        "\x2d\x21\x29\xc1\x97\xf6\xf0\xf2\x22\xb8\xec\x52\x31\xf3\x96\x7d";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 65.
 */
BEGIN_TEST_F(hash_65)
    const char INPUT[] =
        "\xd3\xdd\xdd\xf8\x05\xb1\x67\x8a\x02\xe3\x92\x00\xf6\x44\x00\x47"
        "\xac\xbb\x06\x2e\x4a\x2f\x04\x6a\x3c\xa7\xf1\xdd\x6e\xb0\x3a\x18"
        "\xbe\x00\xcd\x1e\xb1\x58\x70\x6a\x64\xaf\x58\x34\xc6\x8c\xf7\xf1"
        "\x05\xb4\x15\x19\x46\x05\x22\x2c\x99\xa2\xcb\xf7\x2c\x50\xcb\x14"
        "\xbf";
    const char EXPECTED_HASH[] =
        "\xba\xe7\xc5\xd5\x90\xbf\x25\xa4\x93\xd8\xf4\x8b\x8b\x46\x38\xcc"
        "\xb1\x05\x41\xc6\x79\x96\xe4\x72\x87\xb9\x84\x32\x20\x09\xd2\x7d"
        "\x13\x48\xf3\xef\x29\x99\xf5\xee\x0d\x38\xe1\x12\xcd\x5a\x80\x7a"
        "\x57\x83\x0c\xdc\x31\x8a\x11\x81\xe6\xc4\x65\x3c\xdb\x8c\xf1\x22";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 66.
 */
BEGIN_TEST_F(hash_66)
    const char INPUT[] =
        "\x8e\x8e\xf8\xaa\x33\x6b\x3b\x98\x89\x4c\x31\x26\xc7\x18\x78\x91"
        "\x06\x18\x83\x8c\x00\xac\x85\x90\x17\x3c\x91\x74\x99\x72\xff\x3d"
        "\x42\xa6\x11\x37\x02\x9a\xd7\x45\x01\x68\x4f\x75\xe1\xb8\xd1\xd7"
        "\x43\x36\xaa\x90\x8c\x44\x08\x2a\xe9\xeb\x16\x2e\x90\x18\x67\xf5"
        "\x49\x05";
    const char EXPECTED_HASH[] =
        "\x41\x67\x29\x31\x55\x8a\x93\x76\x25\x22\xb1\xd5\x53\x89\xec\xf1"
        "\xb8\xc0\xfe\xb8\xb8\x8f\x45\x87\xfb\xd4\x17\xca\x80\x90\x55\xb0"
        "\xcb\x63\x0d\x8b\xea\x13\x3a\xb7\xf6\xcf\x1f\x21\xc6\xb3\x5e\x2e"
        "\x25\xc0\xd1\x95\x83\x25\x88\x08\xe6\xc2\x3e\x1a\x75\x33\x61\x03";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 67.
 */
BEGIN_TEST_F(hash_67)
    const char INPUT[] =
        "\x52\x76\x1e\x1d\xac\x0e\xae\xa8\x98\xe0\xb0\x7c\xd2\x4f\x4b\x2e"
        "\x6b\xb7\xbc\x20\x0e\xa4\xb0\x52\x88\x42\xf1\x7b\x87\x15\x45\x59"
        "\xa2\xea\x94\x45\x9a\x0e\x48\x0a\xe0\xbd\xf9\xf7\x57\xdd\x4a\x33"
        "\x5a\xed\x0e\x51\x01\x38\xb0\x24\xa0\x4e\xd1\xd5\x91\xb4\x32\x32"
        "\x34\xdb\xd5";
    const char EXPECTED_HASH[] =
        "\xb8\x26\xfe\x80\x49\x4e\x19\xc5\x1b\x42\xf2\x58\x2b\x2d\x08\x0b"
        "\xa6\xb9\x05\x12\xf3\x5f\x2d\xb6\x7d\xd7\xfd\x5e\xe5\x32\xea\xa1"
        "\x64\x98\xaf\xba\x08\xb4\x99\x6c\xbc\xfd\xf8\xd1\xa2\xdf\x6b\x1d"
        "\xa9\x39\xe8\x26\x51\x15\xa4\x8a\xef\xa4\x2f\x38\x20\x5d\xb4\x36";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 68.
 */
BEGIN_TEST_F(hash_68)
    const char INPUT[] =
        "\x38\x04\xeb\xc4\x3c\xbe\xa8\x0c\x2b\xd7\xe4\xfd\xa5\xc5\x51\x55"
        "\x00\xcd\x2d\x2b\x84\x6a\x13\x78\xdb\xf2\x18\xd5\xc3\x77\x13\x86"
        "\x06\xeb\x3c\xb8\xac\x88\xf9\x07\x6f\x6f\xf4\x43\x6f\x90\x71\x74"
        "\x27\xc9\xdf\x1b\xa0\x52\xac\xbb\xe4\x58\x5e\x98\xb6\xe8\xe0\xbf"
        "\x80\x0f\x19\x46";
    const char EXPECTED_HASH[] =
        "\x17\xdd\x6d\x87\xbc\x67\x73\x05\x1e\x52\x04\x7f\xd4\x44\x99\x6a"
        "\xfa\x81\x24\xb0\x48\x3f\xe1\x21\x87\x7f\x98\x55\x34\x48\x77\x2b"
        "\xd0\xe7\x75\x1f\xc6\x55\xe9\xcc\x2d\x29\x83\x02\x11\x01\x5d\x31"
        "\x0f\x19\x14\x74\xca\x6a\xdc\x04\x77\xa1\x87\xc0\x3b\x8f\xe2\x52";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 69.
 */
BEGIN_TEST_F(hash_69)
    const char INPUT[] =
        "\x22\x49\xd6\x98\xc4\xd8\x07\xa8\xe7\xb4\xde\x21\xc4\x85\x73\x89"
        "\x59\xa0\xd6\x7e\x5d\x2c\xa6\xf7\x79\x83\xdf\xcc\xb5\xdb\xf4\x79"
        "\x31\x26\x1e\x1f\x15\x37\xf3\xcb\xca\x25\x3a\xfb\x6b\xf4\xfe\x5e"
        "\x76\x72\xe1\xdc\xc8\x60\xb3\xd6\xc8\xd2\x43\xaf\xe2\xd9\x75\x8b"
        "\x37\x5e\x95\x56\x92";
    const char EXPECTED_HASH[] =
        "\x6a\xf4\x45\x63\xfc\x46\x8d\x51\x18\x2f\x6c\x3b\xe5\x8d\x45\x93"
        "\x2a\xf1\xd9\x85\xc6\xf2\x83\x97\x6c\x91\xa9\xff\x42\x1f\x38\x3f"
        "\xe2\x1d\xc7\x32\x2f\x39\x7c\xce\xad\x58\x3e\x26\xb3\xe3\xfd\xa0"
        "\x67\x97\x6a\x7f\x34\x66\x5d\xf2\x5a\x2c\xed\x7b\x4b\x09\xcd\xec";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 70.
 */
BEGIN_TEST_F(hash_70)
    const char INPUT[] =
        "\x32\xa9\xc1\x70\x33\x65\x8c\x54\xf2\x2c\x71\x35\xdd\xfc\x87\x9d"
        "\xe9\x4d\x79\x59\x3e\xf2\xdc\x7d\x30\x41\xbf\xa8\x72\x73\x83\x89"
        "\x86\x4e\xed\xa2\x78\x01\x79\x4c\xcc\x4f\xf1\xfc\xb5\xef\x3f\xc4"
        "\x88\x33\x80\x1d\x6f\xe9\x59\xe3\x62\x7f\x8e\xa1\x53\x6a\xd0\x0f"
        "\xa9\xc7\xd7\xd9\xf0\x43";
    const char EXPECTED_HASH[] =
        "\x6a\x47\x69\x9d\xd3\xad\xa2\xf1\x1b\xc4\xea\x42\x07\x2b\x06\xcc"
        "\x20\x85\x7b\xf1\x64\x49\x7d\xf1\x28\x54\x00\xc2\x50\xf5\x84\x8b"
        "\x6f\x71\x95\x7d\xbd\xc8\x45\xf5\xda\xea\xb9\x13\x03\x66\x61\xf6"
        "\x93\x87\x89\x3f\xc2\xd6\x1c\x25\xfa\x59\xb9\xd8\x5b\x19\xf4\x01";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 71.
 */
BEGIN_TEST_F(hash_71)
    const char INPUT[] =
        "\x3d\x65\xf6\x9a\x59\x0a\x5b\xaa\xab\xcd\x27\x4f\xe3\xef\x9e\x88"
        "\x92\x0f\xfc\x7a\xdf\x05\xc1\x6d\x7b\x0f\x4d\x18\xd7\x2b\xac\x1e"
        "\x94\xc3\xb3\xd8\x3b\x8f\x4c\x55\x2e\xb8\x0e\x9f\xde\x39\x11\x40"
        "\x3f\x8b\x00\x05\x79\x81\x6f\x02\xe1\x71\x6f\xd6\x27\x94\x60\x31"
        "\xd0\xaf\x07\x93\xe7\xf3\xe1";
    const char EXPECTED_HASH[] =
        "\xff\xb2\xd9\x45\x09\x43\xc2\x4b\x59\x33\xc2\x48\x12\x45\x9b\x75"
        "\xd3\xd9\xf3\x80\x34\x4c\x9b\xc0\x6f\xa3\xe1\x7e\xe4\x48\xec\xa2"
        "\xf9\x8f\xf7\x9f\x7e\x22\x35\xcc\xd9\xf9\xa8\x17\x6f\x68\xa2\x25"
        "\x4b\xbc\x9b\x83\x4d\x6a\xc8\xd2\xbf\xdb\xc1\x59\x7c\x43\x2c\x9f";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 72.
 */
BEGIN_TEST_F(hash_72)
    const char INPUT[] =
        "\x76\xff\x8b\x20\xa1\x8c\xf1\x04\xf6\xcd\xb6\x5e\x2b\xa8\xf6\x6e"
        "\xcf\x84\x4a\xf7\xe8\x5e\x8e\xf2\xda\x19\xe8\x84\x8a\x16\x05\x2e"
        "\xc4\x05\xa6\x44\xda\xfb\x5c\xa0\x8e\xc4\x8f\x97\x32\x7a\xc5\x2c"
        "\x0e\x56\x21\x84\x02\xc7\x2a\x9a\x6d\xc1\xcf\x34\x4d\x58\xa7\x16"
        "\xa7\x8d\x7d\x75\x29\x68\x0b\xae";
    const char EXPECTED_HASH[] =
        "\xf8\x85\x81\x44\xc6\xd7\x09\xdd\x06\x89\xa5\x26\xa5\x48\xa4\x3f"
        "\x17\x49\x49\x50\xba\x2a\xc2\x05\x44\x79\x9e\x8e\xa2\x72\x01\xd7"
        "\x8b\xce\x5b\x92\x1e\x29\xa7\xb4\x02\x92\x78\xe6\x83\x41\xef\x2a"
        "\x0c\xa4\xba\x38\x94\x56\x6b\x3c\x8f\x89\x50\xe3\xe5\x45\xa6\x89";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 73.
 */
BEGIN_TEST_F(hash_73)
    const char INPUT[] =
        "\xca\x88\xdd\xdf\xc8\x76\xa1\x2f\x45\xf1\x95\x62\xbc\x9c\xa2\x50"
        "\xf4\x32\x67\xab\x25\x1a\x7f\x34\x5c\x3c\x02\x2e\x20\x14\x4e\x13"
        "\x56\x04\x07\x87\x62\xef\x5c\x8a\x8f\x03\x8c\xf1\xb1\xd6\xa9\x17"
        "\x09\xb5\x9d\xd0\x68\x39\x6a\x9e\x97\x1a\xb6\x28\xf7\x48\x86\xe7"
        "\x65\x38\x4a\x23\x60\x7c\x1a\x1e\x6e";
    const char EXPECTED_HASH[] =
        "\x4f\x3d\x9e\xee\xf3\x49\xca\x51\xa7\xe4\x19\xaf\x16\x86\xf4\x27"
        "\x95\xab\xde\x58\xa8\x53\x35\xce\x68\xd4\x96\xe8\x1e\x44\x36\xa8"
        "\x0a\x61\xdc\x14\x3a\x43\x00\x00\x8c\x23\xa3\xe7\x1f\x4b\xa9\x87"
        "\x43\x19\x5a\x36\x94\xa8\xd0\x2f\xee\x11\xbd\x31\x45\x69\xab\xc0";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 74.
 */
BEGIN_TEST_F(hash_74)
    const char INPUT[] =
        "\x0a\x78\xb1\x6b\x40\x26\xf7\xec\x06\x3d\xb4\xe7\xb7\x7c\x42\xa2"
        "\x98\xe5\x24\xe2\x68\x09\x3c\x50\x38\x85\x3e\x21\x7d\xcd\x65\xf6"
        "\x64\x28\x65\x01\x65\xfc\xa0\x6a\x1b\x4c\x9c\xf1\x53\x7f\xb5\xd4"
        "\x63\x63\x0f\xf3\xbd\x71\xcf\x32\xc3\x53\x8b\x1f\xdd\xa3\xfe\xd5"
        "\xc9\xf6\x01\x20\x33\x19\xb7\xe1\x86\x9a";
    const char EXPECTED_HASH[] =
        "\x60\x95\xc3\xdf\x5b\x9d\xb7\xce\x52\x4d\x76\x12\x3f\x77\x42\x1c"
        "\xe8\x88\xb8\x6a\x47\x7a\xe8\xc6\xdb\x1d\x0b\xe8\xd3\x26\xd2\x2c"
        "\x85\x29\x15\xab\x03\xc0\xc8\x1a\x5b\x7a\xc7\x1e\x2c\x14\xe7\x4b"
        "\xda\x17\xa7\x8d\x2b\x10\x58\x5f\xa2\x14\xf6\x54\x6e\xb7\x10\xa0";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 75.
 */
BEGIN_TEST_F(hash_75)
    const char INPUT[] =
        "\x20\xf1\x0e\xf9\xa0\xe6\x12\x86\x75\x34\x01\x71\xcd\x24\x8d\xf3"
        "\x0b\x58\x65\x57\x62\x0b\x61\x5c\xa3\x9a\x00\xdb\x53\x43\x15\xa9"
        "\x01\x2d\xbd\xbf\xd6\xa9\x94\x98\x6e\xb8\x29\xdb\xe6\xcd\xaf\x3a"
        "\x37\xd4\xf5\x9a\xc2\x72\x98\x74\x2c\x8f\x77\x7b\x6b\x12\x67\x7f"
        "\x21\xeb\x28\x91\x29\x57\x98\x68\x70\x5f\x27";
    const char EXPECTED_HASH[] =
        "\xb4\xea\xd3\xf8\x60\xea\xbb\xd3\x6c\x77\x0d\x66\xc7\x35\x6f\x81"
        "\x07\xac\xd1\x48\x5c\x7c\x94\x17\x8c\x2e\xaa\xbd\x50\x26\x6d\x76"
        "\x45\xd0\x09\x97\x25\x86\xef\x83\xed\x43\xed\x92\x88\x21\x37\xdf"
        "\x51\x17\xb8\x8f\x35\x23\x1b\x89\x4e\xc1\x74\x1a\xe7\x50\x11\x45";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 76.
 */
BEGIN_TEST_F(hash_76)
    const char INPUT[] =
        "\x99\x5c\x8f\x74\x7e\xa4\x18\xf7\xd6\x3a\xba\x22\x60\xb3\x4a\xc3"
        "\xc7\xdc\xee\xbb\x78\x43\x8c\xa4\xb1\xf9\x82\xb7\xdb\x97\x98\xec"
        "\x1a\x7f\x32\x62\x22\x64\xcb\x02\x4c\x0d\x9e\x60\xe9\x55\xa6\xe1"
        "\xd6\x77\xc9\x23\x51\x88\x51\x99\x0a\x45\x9b\x76\x7d\x0f\x13\xcd"
        "\x80\x34\x60\xf6\x18\x70\xdb\x33\x91\xb4\x46\x93";
    const char EXPECTED_HASH[] =
        "\xa0\x0a\x60\x1e\xde\xac\xa8\x30\x41\xdc\x45\x2d\x43\x8a\x8d\xe5"
        "\x49\x59\x4e\x25\xd8\x43\xc2\xcf\x60\xa0\xe0\x09\xfb\x92\xd8\x7a"
        "\xbe\x28\xa7\x26\x90\xab\x65\x7c\x8d\x35\xb4\x3c\xd0\x2d\x22\xec"
        "\x07\x55\xde\x22\x9d\x1f\x92\x2f\xa6\xca\x18\xa6\xd6\xc2\xaa\xae";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 77.
 */
BEGIN_TEST_F(hash_77)
    const char INPUT[] =
        "\x0f\xeb\x23\xc7\xe4\xa1\x9b\xcb\xd7\x0b\xd3\x00\xd7\x6e\xc9\x04"
        "\x5d\x69\x6f\x8c\x96\x87\xf4\x9e\xc4\x15\x44\x00\xe2\x31\xd2\xf0"
        "\x86\x24\x95\x15\x0c\xf2\x50\xb6\xf1\x2f\x17\x2a\x7d\x13\x0f\x8f"
        "\xa5\xd1\x75\xbf\x2f\x25\xe2\x80\x17\x2c\xcd\xfb\x32\x79\x51\x70"
        "\x11\x65\x30\x27\x28\xa6\x19\xaa\x2f\x24\x26\x31\xc9";
    const char EXPECTED_HASH[] =
        "\xee\xb6\xde\xe3\x0c\x11\x9f\xb1\xe1\xeb\x5c\x15\xff\x2b\x32\xd8"
        "\xb9\xc7\x46\x4a\x4e\x4c\xc6\x81\x5c\xd2\x51\xa6\xba\xe2\x9b\x49"
        "\x96\x1d\xd5\xc2\xfa\x9c\x44\xa9\xb1\x42\xca\x06\x2c\x70\x72\xcb"
        "\xf3\xdb\x04\x29\x9b\x76\x77\x89\x04\x01\x96\xbf\x0c\x06\xaa\x76";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 78.
 */
BEGIN_TEST_F(hash_78)
    const char INPUT[] =
        "\xac\x59\xa1\x10\x62\x3f\x1a\x64\x66\x6f\x16\x0e\xd3\x29\x26\x67"
        "\x6c\xb5\xbe\x25\xdd\x9d\x96\x2f\x44\x19\x51\xb0\xef\xcb\x5d\x6a"
        "\x67\xac\x1a\x4e\xae\x47\x3e\x49\xc6\x25\x78\x60\x72\x88\x53\xff"
        "\x41\x5c\x5e\x8e\xc7\x6a\x8a\x46\x2e\xcf\xd3\x43\xee\xac\x22\xda"
        "\xd8\x20\x72\x2c\x59\x73\x32\xfb\xfd\x94\xeb\xbd\x32\xc6";
    const char EXPECTED_HASH[] =
        "\xf6\x5e\xa9\x42\xae\x0a\x47\xe7\x3b\x02\xb1\x44\x2e\x5b\x26\x08"
        "\x3d\xb7\x93\x07\xf6\x4d\xd3\x4a\x03\x9c\x47\x6f\xaf\x18\xd5\xc5"
        "\x14\xbb\x77\xa2\xc4\x12\xa6\x07\x4a\x7a\xfc\x32\x6e\xa6\x6c\x74"
        "\xe5\x70\x5f\xe2\xab\xba\xbf\x27\x43\x33\x32\x5a\x15\xb6\x1f\xd9";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 79.
 */
BEGIN_TEST_F(hash_79)
    const char INPUT[] =
        "\x9e\x3e\x10\x77\xe1\x33\x3a\x1f\xb1\xaa\x63\x3c\xcf\x2f\x74\x65"
        "\x88\xad\x42\x64\x89\xea\x08\xdf\xf5\x51\x14\x38\xb5\xf4\xc0\xb1"
        "\x10\xd1\xa4\xd4\x7b\x54\x0a\x12\xb2\x1e\xa2\xaa\x07\x05\x78\xcc"
        "\xfa\x5c\x22\xfe\x0b\x74\x3e\xc0\xcc\x62\x1c\x6b\x3a\x03\xb7\x5f"
        "\x4d\x3e\xea\x5d\xce\x89\xe0\x32\x69\xaf\xcd\x96\x03\xd0\xdb";
    const char EXPECTED_HASH[] =
        "\x4b\x5c\x5d\xf8\x0c\x34\x4c\x12\x38\x8c\x72\x38\x56\xcd\x06\x96"
        "\x5b\x21\x90\xaf\x65\x24\x80\x47\x67\x47\xdc\x21\x95\xea\x37\x16"
        "\xf8\x7c\x17\x62\x35\x95\x83\xa5\xf3\x15\x22\xf8\x3f\x78\x33\xbe"
        "\xc3\x0f\x1f\x47\xd1\x45\x40\x41\x7d\xd4\x63\xf5\xd2\x58\xcd\x4a";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 80.
 */
BEGIN_TEST_F(hash_80)
    const char INPUT[] =
        "\xe8\x81\xe3\x28\x4c\x79\xd8\xf5\x23\x7e\x69\x9e\x4f\xbc\xa8\x40"
        "\x90\xc6\x64\xbb\x53\x22\x9f\x58\xcb\x08\x42\xb0\x43\x67\x10\xc9"
        "\xb3\x29\xd9\x81\x91\xb8\xf0\x30\xe9\xc1\xdf\x89\xb0\x38\x58\xc1"
        "\x56\x9c\x6f\xf4\x9a\x7c\x07\xc4\xa2\x3a\x8a\x43\x4b\x0f\xde\x13"
        "\xbe\x4f\x94\xcb\x44\xee\x62\x9d\x5b\x44\xd3\x36\x09\x0d\x3d\xe6";
    const char EXPECTED_HASH[] =
        "\x14\x7d\x80\x71\xc7\x87\x1e\xf9\x25\x6c\xff\x32\xaa\x63\xea\x03"
        "\x14\x04\xfa\x5e\xe4\xec\x09\xc5\x6a\xfd\xd5\xda\x91\x9b\x0c\xc8"
        "\x4a\x9d\x35\xd1\x42\xc4\x17\x71\x52\x03\x31\x60\x11\xcc\x62\x0c"
        "\xd6\x85\x5b\xb1\x17\x06\x3a\x5e\x52\x86\x7f\xac\xc6\x80\xd5\xf4";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 81.
 */
BEGIN_TEST_F(hash_81)
    const char INPUT[] =
        "\xe5\x85\x21\x09\x89\x11\x50\x3d\xe8\x43\x11\x38\x7d\x37\x5c\x25"
        "\x92\x9e\x6e\x55\x07\x6e\xb6\x93\x4f\xd8\xf2\xb1\xbb\x7b\x96\x67"
        "\xfb\xd7\x6d\x5e\xe2\x04\x82\x87\x69\xa3\x41\xb1\xf7\x16\xda\x5b"
        "\xdf\xec\xe6\xc6\x2a\x9f\x4d\x4f\x98\x82\x67\xfc\xe1\xf5\x61\x55"
        "\x40\xdb\xe3\x75\x32\x4e\xef\x60\x7c\x91\x0d\x97\x6b\x45\xa5\xea"
        "\x5f";
    const char EXPECTED_HASH[] =
        "\xf9\x7b\xa0\x56\xfa\x41\xf4\x3b\x8e\x19\x87\x07\x2a\x09\xe8\x28"
        "\xc7\x1c\x5f\xf6\xad\x4e\x37\xf9\xab\x6b\x89\xe2\xa0\x78\x93\x3d"
        "\xd2\x30\x52\xfa\x72\xc6\x61\x5b\x61\x39\x04\x25\x9e\x9f\xf9\xb5"
        "\x5e\xf7\xb9\x23\xb8\x9b\xc8\x75\x2f\x6b\xab\xdd\xd2\x56\xe1\x17";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 82.
 */
BEGIN_TEST_F(hash_82)
    const char INPUT[] =
        "\x37\x96\xcf\x51\xb8\x72\x66\x52\xa4\x20\x47\x33\xb8\xfb\xb0\x47"
        "\xcf\x00\xfb\x91\xa9\x83\x7e\x22\xec\x22\xb1\xa2\x68\xf8\x8e\x2c"
        "\x9f\x13\x3e\x5f\x85\x27\xf1\xb1\x84\x83\x0e\x07\xc3\x45\x8c\x83"
        "\xa8\xca\x9f\x9d\x9c\x69\x98\x76\x0e\x61\x06\x68\xba\x0f\x22\xe2"
        "\x2b\x65\x6a\x73\x7e\x97\x8b\x24\x6a\x17\x84\x0b\x7d\xc4\x09\x1d"
        "\xa8\x5f";
    const char EXPECTED_HASH[] =
        "\xc8\xa4\x66\x19\x9a\xcb\xcb\xc9\x3f\x2c\xe0\x42\x96\x85\x08\xc0"
        "\x46\x90\x16\x31\xe3\x11\x8a\x2d\x0b\xf3\x9a\x9b\x42\xb4\x19\x7a"
        "\x37\x9b\x3a\x86\xcd\xec\xa9\xdf\x2d\xe1\xa3\xeb\x71\xb7\x9a\xe9"
        "\xbf\x2d\x65\x75\xea\xdf\x18\x78\x02\x9c\x40\x93\x13\x3f\x54\xd3";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 83.
 */
BEGIN_TEST_F(hash_83)
    const char INPUT[] =
        "\x9a\xf6\x08\xd0\x31\xcc\xf3\x09\xd7\x27\x3c\x60\x7a\x8e\x5e\x36"
        "\x84\x0d\x44\x9b\x55\xdb\x5b\x13\xf0\x3a\xeb\x9a\xf4\x9f\xa7\xe7"
        "\xcf\x13\x83\xee\x2e\xd9\xc5\xa8\xb7\x51\x5f\x16\xfb\x1c\x7c\x84"
        "\xa6\x81\x59\x0b\xf9\x0f\x56\x59\x7b\x84\x4d\xb5\xeb\xee\x22\x3d"
        "\x78\x10\x9b\x72\x35\x07\x72\xf7\xc7\x2e\xa9\x96\x60\x3e\x1e\x84"
        "\xf2\xba\x5f";
    const char EXPECTED_HASH[] =
        "\xf0\xde\xd9\x49\x5b\x4f\x64\xca\xc5\x85\xbe\x8a\x73\x7c\xfa\x14"
        "\x24\x7a\x4a\x81\xcd\xf7\xf0\x1e\xbc\xb1\x34\xac\xe7\x1f\x5a\x83"
        "\xdf\x2c\xd7\x2e\x77\x73\xfe\xa1\xe8\x2b\xea\xe1\x7e\x13\x85\x73"
        "\x72\x79\x2c\x82\x31\xe2\xab\x9f\xbe\xb6\x33\xe3\x99\xd5\xf0\xae";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 84.
 */
BEGIN_TEST_F(hash_84)
    const char INPUT[] =
        "\xd0\xdf\x1b\xdf\x1d\xf6\x20\x32\x41\x72\x2f\xb9\xc9\xc1\xcf\x74"
        "\x05\x01\x74\x97\xae\x15\x45\x38\xcc\xf9\x22\x4a\xd7\x52\xe6\xce"
        "\x1d\x4a\xe9\x48\x63\x9a\xca\x70\xcf\xe8\x6b\x2b\x06\x54\x3c\xb9"
        "\x91\x4e\xbd\x30\x85\xaa\x3e\x29\x63\xf6\xe9\xb9\x3d\x0b\x03\xa3"
        "\x1a\xe2\x6f\xcb\x9c\xa9\x74\xee\xe0\x16\xc0\x91\xa6\xfc\xac\x37"
        "\xb2\x1c\xc1\xd7";
    const char EXPECTED_HASH[] =
        "\xc2\xda\x3e\xa3\xc8\xa3\xfd\x88\xa5\xbc\x5d\xea\x2b\xc0\x76\xf8"
        "\x61\xab\xed\xef\xae\x5a\x5f\xbd\x94\x1d\xdf\xd1\xc4\x1c\xc3\x31"
        "\x2e\xb2\xdc\x82\x6c\x2c\x0f\x65\x41\x4f\xe7\x2e\xbe\xe4\x47\xd2"
        "\xf9\xb1\xa6\xa5\x63\x02\x66\x0d\x1f\x86\x63\x2e\xe8\x0a\x17\x5f";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 85.
 */
BEGIN_TEST_F(hash_85)
    const char INPUT[] =
        "\x8c\xbc\x94\x80\x55\x3a\xce\xf7\xbc\xdb\xa9\x71\x6e\xa8\xd6\x6b"
        "\x41\x31\x78\x09\x17\xde\x2b\x0b\x04\x80\x45\xfc\xb3\x2b\x5c\xac"
        "\x05\x48\x08\xe1\xfc\xe6\xe9\x4a\xd8\x51\xec\xb4\x7f\xe6\xcb\x80"
        "\x22\x25\xd3\x55\x1e\x08\xea\x12\x20\x93\xd0\x07\x8d\xad\xa5\x64"
        "\x21\x2e\xac\xf1\xd6\x39\x4e\x00\x07\xcc\x62\xa1\xd5\x95\xab\x14"
        "\xca\x08\xa2\x84\xbc";
    const char EXPECTED_HASH[] =
        "\x63\xb3\x9b\x88\xce\xb8\x48\x18\x8b\x37\x31\x6e\x04\x56\x0e\x75"
        "\xa5\x34\x0a\xb8\xd4\x17\x93\x2d\x23\x1c\x99\x7e\x89\x2b\x41\xda"
        "\xa6\x9d\x9f\xe3\xe9\xa1\x4d\xd1\x9c\xcf\xbb\xfa\x01\x48\x8c\x20"
        "\x8e\x7b\x94\x6c\xfa\xf1\x6c\xa2\xb1\xbf\x7c\x8d\x8d\xa4\xe6\xb2";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 86.
 */
BEGIN_TEST_F(hash_86)
    const char INPUT[] =
        "\x38\xf1\x84\x44\x8f\x3c\xf8\x2a\x54\xca\xfc\x55\x6a\xff\x33\x6f"
        "\x23\xf9\x14\x9e\x61\x21\x34\xb3\xfc\x00\xc8\xa5\x64\x55\x65\x3d"
        "\x88\x64\x0b\x12\xf6\x90\x62\xb8\x43\x2c\x43\x35\xad\x8f\x7a\xb4"
        "\xff\x66\xcb\x7e\xb5\x4f\x33\x25\x61\xa3\x6f\x02\x4d\x92\xc3\xe2"
        "\x62\x76\xf4\xfd\x48\x61\x96\x28\xcf\xf8\x8e\x4b\x8e\x85\xcf\x14"
        "\xca\x47\x67\xed\x99\x0d";
    const char EXPECTED_HASH[] =
        "\x9a\x49\x26\x5f\xc6\x41\xc5\x9f\x1a\x91\x87\x2c\xda\xe4\x90\xd3"
        "\xda\x73\xc0\xc6\x0f\xd5\x96\x48\xe1\xd1\x7d\xba\x1a\x64\x7a\x5b"
        "\x95\x62\x93\x92\xbb\x4f\xf5\x16\x3d\x1a\x3c\xb4\x54\x27\xc1\x43"
        "\x7a\x3b\x2e\x1d\x9f\x03\x0c\x0a\x8b\xcc\x5e\xd2\x2d\xa9\xe2\xed";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 87.
 */
BEGIN_TEST_F(hash_87)
    const char INPUT[] =
        "\x70\x90\x06\x18\xb1\xe9\xe9\xdb\x62\x29\x6f\xb6\xc6\x59\x0c\x9f"
        "\x10\xb0\xa6\x32\x76\x5c\x48\x9c\x88\x7f\x1a\xb7\xc0\x77\x91\x76"
        "\x5a\x62\xe3\x84\x65\xe1\xbe\x28\x1b\x1d\x39\x6c\x6e\x08\x0b\x7e"
        "\xe3\xe6\xfa\x56\xa3\x0b\x97\x99\xd0\xe6\x29\xbe\x15\x3e\xe7\x6f"
        "\x81\xbc\x6a\x32\x95\xaa\x61\x48\x9b\xfa\x87\xd5\x3a\x8a\xd2\x42"
        "\x48\xa6\xed\xe0\xdf\xcf\xe9";
    const char EXPECTED_HASH[] =
        "\x1c\x8c\x33\x57\xff\x1f\x8d\x6a\xc4\xde\xfb\x3a\xf4\x62\xa7\x3e"
        "\x09\x15\x9e\x3a\x20\xc6\x50\x6e\xdd\x8c\xd3\x05\x2d\xf9\x41\xc8"
        "\x1f\x68\xc5\xfb\xb8\x93\x91\x26\x19\xe2\x86\x40\x97\x7f\xe8\xea"
        "\xae\x8e\x9d\x5d\x4e\x7d\x5f\x13\x25\x52\xce\xfa\xb4\x54\x0b\xac";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 88.
 */
BEGIN_TEST_F(hash_88)
    const char INPUT[] =
        "\x4e\x6d\xda\xe0\xd8\x05\xaf\xcd\x10\xa0\x55\xbc\xe5\x84\xc8\x48"
        "\xd0\x50\xfb\x29\xfe\x8f\x1c\x64\xb1\x8e\x1a\xbf\xe4\x6b\x65\x78"
        "\x2e\x6f\xf5\x36\xe8\x9d\x8d\x40\x92\x8b\x41\xed\x73\x71\x36\x5c"
        "\x80\x80\xa9\x64\x7f\x75\x32\xce\x6c\x6d\x4a\xc2\x1c\xfb\x0c\x80"
        "\x20\x78\x38\x51\xec\x9a\x7d\xbc\x39\x48\xf8\xfc\xa7\xad\xf8\xb2"
        "\xa7\x8c\x04\xd8\x98\xd3\x1f\xf6";
    const char EXPECTED_HASH[] =
        "\x5c\x2f\x99\x6c\x77\x9b\x91\xb3\xc4\x63\x93\x11\xf5\x4f\xab\xbd"
        "\xde\x7e\x22\x12\xb5\x3d\xba\xe4\x82\x8c\x83\x99\x58\x8f\xc0\x0d"
        "\x3b\x2a\xe6\x09\x18\xaa\xaf\x6b\xb4\x8b\xc7\x57\xe5\x2b\x2b\xce"
        "\xa8\x4f\x5d\x15\xbf\x4e\xc2\x5d\x55\x19\xfb\x54\xf6\xf2\x6e\x1b";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 89.
 */
BEGIN_TEST_F(hash_89)
    const char INPUT[] =
        "\x69\x68\x25\xf6\xd6\xea\x81\x73\xec\x47\xd0\x95\x9a\x40\x1c\x4d"
        "\xdf\x69\xf8\xf0\x8d\xdd\x67\x8a\x4d\x2f\xf9\x76\xe3\xa4\x37\x2b"
        "\xb3\x9f\x41\x59\x84\x5c\xb6\x35\x85\xe1\xd4\x10\x8d\x32\xe1\x2f"
        "\xa7\xc5\xc9\xd7\xce\x35\x08\xa7\xf5\x3a\xca\x2b\x4b\xd9\x51\xad"
        "\xbc\xd8\x98\x4e\xbb\x75\x36\x56\x3f\x58\x84\xc9\x0b\xc5\x02\x3b"
        "\x33\x16\xf7\xe4\xdc\x69\x58\xf7\x43";
    const char EXPECTED_HASH[] =
        "\x3c\xe9\x40\xca\x96\xb0\x00\x11\x37\x5d\xaa\x95\xc6\x5f\x66\x90"
        "\x7d\x69\xb3\xeb\x3b\x8d\x77\x9e\x6f\xc9\x71\xaf\xcc\x05\xe9\x90"
        "\xbc\x4c\x54\x1f\x43\x45\x90\xf6\xb1\x8b\x68\xc0\x80\xd0\xf2\x44"
        "\x75\xa3\xe7\x64\xe9\xcb\x85\x34\x33\x01\x31\x4e\xe2\xfb\x66\x1e";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 90.
 */
BEGIN_TEST_F(hash_90)
    const char INPUT[] =
        "\x79\xec\xdf\xd4\x7a\x29\xa7\x42\x20\xa5\x28\x19\xce\x45\x89\x74"
        "\x7f\x2b\x30\xb3\x64\xd0\x85\x2c\xce\x52\xf9\x1e\x4f\x0f\x48\xe6"
        "\x1c\x72\xfa\x76\xb6\x0d\x30\x02\xca\xe8\x9d\xfc\x55\x19\xd3\x43"
        "\x0b\x95\xc0\x98\xfa\x46\x78\x51\x6b\x5e\x35\x51\x09\xea\x9b\x37"
        "\x45\xaa\x41\xd6\xf8\x20\x6e\xe6\x4a\xe7\x20\xf8\xd4\x46\x53\xb0"
        "\x01\x05\x7f\x2e\xba\x7f\x63\xcd\x42\xf9";
    const char EXPECTED_HASH[] =
        "\xba\x3d\x0f\xe0\x44\x70\xf4\xcf\x8f\x08\xc4\x6d\x82\xae\x3a\xfd"
        "\x1c\xae\xa8\xc1\x3b\xeb\xbe\x02\x6b\x5c\x17\x77\xaa\x59\x86\x0a"
        "\xf2\xe3\xda\x77\x51\x84\x4e\x0b\xe2\x40\x72\xaf\x48\xbc\x8a\x6f"
        "\xd7\x76\x78\xaa\xee\x04\xe0\x8f\x63\x39\x5f\x5c\x8a\x46\x57\x63";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 91.
 */
BEGIN_TEST_F(hash_91)
    const char INPUT[] =
        "\x92\x63\xfe\x75\xe8\xf6\xc7\xd5\xd6\x42\xe2\xca\x6a\x6e\xea\x4f"
        "\x44\xe9\xa0\xf2\x49\x51\x3e\xd7\x9c\x94\x09\xff\xca\x55\x26\xca"
        "\x44\x91\xae\xbb\x13\x82\x05\x7c\xc7\xc3\x67\x22\xb0\xb6\xc3\xb1"
        "\x51\x23\xcd\xe3\x12\x21\x4f\x25\x35\x3a\xbf\xe3\x0b\xca\x17\x05"
        "\x68\xa8\xe1\xba\x54\x08\x91\x74\x03\xa0\x18\x34\x08\x0a\xb6\x07"
        "\xc5\x6a\x10\xd0\x26\x50\x82\x49\x8f\xe0\xb6";
    const char EXPECTED_HASH[] =
        "\x77\x36\xd7\xa7\xfc\x1e\xb0\x58\x57\xce\x7d\x88\xab\xff\xfa\x87"
        "\xf5\x8c\x67\x0b\xfd\xfc\x0a\x80\x31\xf6\x0f\x37\x9e\x4b\x6a\xd9"
        "\x4a\xc8\xf1\x3f\xfe\x28\xc6\x97\x80\x9b\x5c\xfa\xc7\xf1\x3b\xe0"
        "\x1e\x74\x96\xa8\x52\x37\xc4\x02\x55\x39\x05\x1f\xb2\xe3\x2f\xb6";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 92.
 */
BEGIN_TEST_F(hash_92)
    const char INPUT[] =
        "\x78\xc1\x7b\xfe\x0e\x02\xeb\x52\x6d\x1a\x44\xa1\xac\x12\x7b\xe0"
        "\x82\x18\x14\x52\xb6\x25\x39\x4b\xd6\xdc\x09\x3a\x2c\xb4\x32\xe6"
        "\xee\x59\xc2\xf8\xb5\x50\x3a\xba\x30\xda\xe4\x1e\x1a\x1c\x67\x02"
        "\x69\x7c\x99\xb2\xc9\x4e\x94\xaf\x48\xb0\x0c\xaf\x53\xb2\xe0\xe4"
        "\xe1\xbb\xee\x81\xee\x28\x2c\x7b\x2b\x35\xf5\x8c\xf4\x21\xa0\x7e"
        "\x82\x8d\x57\xa6\x62\x26\x26\xaf\x25\x83\x53\x99";
    const char EXPECTED_HASH[] =
        "\xb5\x6b\x6e\x34\x31\x66\x32\x85\x23\xe0\xd1\x69\x3e\x51\x74\xda"
        "\x64\x3a\xe8\x3c\xf6\x9c\x85\xa7\xb3\xc3\xbe\xe2\x47\xb7\x7b\x84"
        "\x70\x20\x69\xd9\xe6\xb4\xca\xb0\x3b\xf1\x7f\xe6\x12\x00\x9b\xf4"
        "\x23\x96\x83\xca\x78\xca\x7e\x87\x6a\xca\x7d\x07\x60\x3b\xa7\x14";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 93.
 */
BEGIN_TEST_F(hash_93)
    const char INPUT[] =
        "\x29\x8b\xb3\x04\xa9\x20\xf9\x60\x44\x7d\x8f\xd3\x8b\x06\x1b\xf8"
        "\xfe\x4a\xc1\xf8\x71\xd8\xa0\xfe\xb4\x54\x9f\xeb\x72\xca\x69\x4a"
        "\x5a\x41\xb6\x86\x7d\x94\xcd\x5a\xf7\x7d\x46\x8a\xd2\xf3\x15\xd1"
        "\x27\xb6\xc4\x1a\x86\x28\x00\xf3\x98\x5e\x57\x3e\x03\x77\x40\x29"
        "\x8e\x2c\x5c\x61\x86\xa9\xfb\x83\x60\x9b\xe2\xd4\x9f\x8b\x4c\x31"
        "\xf9\x6a\x2e\x49\xb5\x6d\xbf\x09\x57\x1b\x38\x58\x7f";
    const char EXPECTED_HASH[] =
        "\x34\xe3\x87\x86\x27\x90\x4f\xfb\xbb\xd8\x52\x66\xcc\x97\x3c\x34"
        "\xf9\x31\xe3\xca\xb5\xd4\xc3\x1f\x84\x1c\x55\x3d\xd6\x9f\x84\x83"
        "\x82\x06\x06\x7d\xf4\xf9\xf3\xb9\x10\x20\x01\xbe\x19\x26\x71\x51"
        "\xe6\x73\xf5\xc2\xd4\xc2\xf8\x43\x8a\x69\x99\xa0\xa3\x25\x48\x7d";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 94.
 */
BEGIN_TEST_F(hash_94)
    const char INPUT[] =
        "\xa3\xcf\x71\x4b\xf1\x12\x64\x7e\x72\x7e\x8c\xfd\x46\x49\x9a\xcd"
        "\x35\xa6\x40\xdd\x39\x3d\xdd\x26\x3c\xd8\x5c\xf6\x22\x5f\x59\x89"
        "\x0a\x06\x86\xda\xd1\xc5\x4e\xb8\xd8\x09\xb8\x1c\x08\xa9\x8d\xba"
        "\x13\x1b\xbd\xd6\xfc\xe8\xff\x59\xd9\x5d\xb8\x24\xd8\x83\x1e\xa4"
        "\x80\x52\x9d\xa7\x39\x22\x7a\x6e\x0f\x62\xb6\x03\xb3\x8c\x35\xcd"
        "\xc2\x58\x1f\x61\x4a\x31\x87\x9b\x8b\xe5\x4a\xee\xfa\xa0";
    const char EXPECTED_HASH[] =
        "\x6f\x23\x0a\xe4\x90\x3d\xdb\xef\x0b\xa3\x84\xc2\xe3\x50\x6e\xab"
        "\x31\x8b\xfd\x1a\x46\xea\x76\x09\x9f\x65\xa3\xfd\x52\x9c\x91\xbc"
        "\x28\x65\xb9\xfd\x94\x3e\x34\x6d\xe6\x46\x26\xb8\x52\x9f\x9d\xb1"
        "\x37\x7b\xf2\xc5\xe0\x12\x9c\x66\xb5\x0c\x6a\x5c\xfb\x36\x4b\x3a";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 95.
 */
BEGIN_TEST_F(hash_95)
    const char INPUT[] =
        "\x0a\x42\x7a\xe5\x5e\xf3\xa7\xe6\x04\x4a\x08\xcf\x61\x28\xcb\xaa"
        "\xab\xfd\x77\x6c\x4e\x93\x74\x70\x8f\x2e\xce\x24\x6f\xd7\x36\x03"
        "\xd2\xf5\x4a\xc3\xe0\x1d\x16\xcf\xac\x2b\xda\xf7\x13\x92\x0d\x66"
        "\xe8\xf0\xa3\xd5\x4e\xe6\x8c\xff\x64\x26\x7d\x55\x28\xcd\xf2\xf2"
        "\x95\xf4\x74\xd1\x0f\x81\x17\x3e\x01\x43\x48\x8a\xc5\x3f\xc5\x03"
        "\xc4\x44\xed\x23\xde\xc6\x3a\x08\x0c\xe9\x0c\x24\x43\xdb\xa8";
    const char EXPECTED_HASH[] =
        "\xf6\xbb\xe5\xd0\xcf\x13\xdd\xf4\x1c\x14\x36\x74\x8a\x5d\x1c\xca"
        "\xe2\x94\x85\x47\xb4\x52\xc2\x17\x1c\x7c\x8e\x8b\x66\xc6\xae\x4d"
        "\xe3\xc0\xe8\xb2\x96\x2b\xcb\x60\xd3\xde\x36\x08\x47\x9f\x80\xe4"
        "\x55\xc9\x02\x4d\x97\x16\xc3\x8f\x6f\x12\x06\x86\x1a\xb1\xea\xac";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 96.
 */
BEGIN_TEST_F(hash_96)
    const char INPUT[] =
        "\x2c\xbb\xb8\x75\x11\xf4\x94\x8e\xfe\xc3\xa6\x1b\x51\x1e\xde\xdb"
        "\x1d\xda\x8b\x6e\xcf\xc0\x21\x0c\x11\xe4\x3a\x77\xee\x32\xdc\x2e"
        "\x37\x4a\xfa\xe4\x26\x8e\x3d\x30\x42\x78\x04\x86\x82\x32\xa9\x66"
        "\xb5\x60\x06\xd3\x21\x40\x37\x07\x6b\xf6\xa2\x65\xb7\x21\x35\xaf"
        "\x0f\xb2\xef\x79\x09\xfe\xa2\xde\xa4\x12\xf7\x71\x74\x46\xb2\x76"
        "\xff\x15\x37\x53\x66\x2b\x4d\x41\x48\xc0\x23\x47\xe3\x25\x91\x69";
    const char EXPECTED_HASH[] =
        "\x76\x89\x7b\x87\xa8\xa1\xcf\x83\x5c\x43\x4f\x6d\x39\x1c\x9e\x52"
        "\x27\x35\x1a\xf9\xd3\xe2\x0a\x33\x89\xc7\x96\xb9\x8b\x42\x42\x81"
        "\xa5\x90\x68\xd9\xc8\xd5\x67\xec\x2b\xeb\xc4\x35\xb0\x12\x6b\x05"
        "\x9e\x2d\x86\x39\x4a\x98\x54\xd6\x61\x1e\x1c\x92\x2f\x38\x54\x96";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 97.
 */
BEGIN_TEST_F(hash_97)
    const char INPUT[] =
        "\x2b\x23\x32\x4c\x99\x92\xf6\x0a\x7f\xc0\x10\x15\x9a\x03\xcb\x9a"
        "\x2b\x29\x0d\xf4\xfa\x6a\x82\x35\x9b\x9a\xf6\x02\xf0\xa4\x03\xa5"
        "\xef\x33\xed\x5d\xa5\xb2\xca\xf8\x7b\x77\xe6\xa4\xb9\x3b\x65\x03"
        "\x48\xce\x2a\x7d\xbc\x08\xf8\xda\x92\x03\xd7\x10\xb5\x87\xba\x59"
        "\x47\xc6\x5e\x89\x9f\x4a\x75\x9f\x8e\x2b\x04\x9a\xe7\x85\x0a\x8e"
        "\x3e\x29\x62\xf6\xef\x93\xea\x4c\x63\x1d\xe5\xd7\x8e\x72\x9e\xc5"
        "\xbc";
    const char EXPECTED_HASH[] =
        "\x3b\xee\xa0\xb3\x73\xed\x09\xcf\x1c\x91\x9c\x51\xd8\x6d\x64\x2c"
        "\x91\x25\xe0\xee\x81\x69\x8d\xc4\xcb\xad\xf0\x2e\x9e\x69\x25\xef"
        "\xb5\x62\xfd\x9b\x87\x30\x1a\x63\x77\xca\x19\x2b\xe7\x9c\x41\x18"
        "\xde\xab\xc4\x50\xb5\x46\x39\x00\x0c\x2e\x31\x29\x45\x45\x1f\xb5";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 98.
 */
BEGIN_TEST_F(hash_98)
    const char INPUT[] =
        "\x40\x22\xf9\x30\xc7\x03\x3b\x00\xd9\x86\xc6\x5f\xf6\xbb\xbd\xf9"
        "\xeb\xd0\xe5\x8c\x52\x84\x4f\xf6\x58\xdf\x38\x93\xc3\x20\x2d\xc5"
        "\x33\xf8\x73\xd4\xa7\xf5\xa5\xf9\x44\x41\x9f\xb5\x52\x8c\x9b\x67"
        "\x88\x47\x9a\x1e\x89\x13\x06\xac\xae\x79\x95\xfc\x06\xdb\x70\xa5"
        "\x9b\xaa\x95\xbe\xf7\xda\x79\xf5\xe7\x93\xf2\xdb\x7f\x2a\x55\x82"
        "\x5e\x4f\xdb\x4a\x34\x88\x4a\xf8\x81\xde\xd1\x08\x9f\xd5\x33\x45"
        "\x02\xa2";
    const char EXPECTED_HASH[] =
        "\x03\x58\x77\x5b\xbb\x73\x3c\xcc\x49\xe7\x8f\x54\x4a\xee\xe5\x12"
        "\x37\x0d\x48\x0d\x0e\x13\xc7\xe8\xd5\xc4\x44\xc4\x23\xe5\x92\x14"
        "\x6b\x45\xfd\xb9\x1a\x1b\x69\x4d\x35\xe3\x6b\x60\xe4\xbc\x83\x97"
        "\xfc\xa8\xbb\x97\x90\xe6\x19\x33\x97\x78\xb9\xcd\x1a\xbe\x3f\xe9";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 99.
 */
BEGIN_TEST_F(hash_99)
    const char INPUT[] =
        "\x1c\xb7\x7b\xa4\x3c\xe7\x7e\x23\x6b\x9f\xc9\x25\xf5\x89\xb1\xc0"
        "\x70\x78\x0a\x84\xf9\x9e\x8f\x50\xc1\xff\x84\x6a\xc9\x25\x99\xcf"
        "\xe9\x16\x12\xc8\x17\x83\x25\xbe\xe6\x42\xa3\x4f\x4d\xff\xdb\xa2"
        "\xaa\x2e\xbc\xf7\x06\x43\x39\x82\x9b\x26\xf2\x79\x93\xe1\x10\x6c"
        "\x13\x9c\x70\xd5\x78\xcc\x05\xf0\xe1\xa7\x77\xcc\xed\xdb\x10\xa2"
        "\xc6\x7f\xd9\x67\x5e\x4a\x00\x9d\xf8\x03\x7d\x6e\xeb\x38\xf5\xfb"
        "\xa2\x33\xdf";
    const char EXPECTED_HASH[] =
        "\x65\x02\xf4\x65\x51\xa3\xfa\xb3\xa9\x64\x28\xfb\x97\x80\x1d\x7a"
        "\x4a\xa2\xf1\x7f\xef\x66\x03\x23\x8d\xf8\x4e\x17\xc7\x43\x09\xed"
        "\x3d\x94\x89\xc8\xb1\x6a\x93\x84\xee\x63\x4a\x3f\x86\xd0\xb3\xba"
        "\x9a\x4d\xbc\x9c\x51\xec\x8b\xd4\xbf\x8d\x61\xde\x6d\x3d\x87\xd7";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 100.
 */
BEGIN_TEST_F(hash_100)
    const char INPUT[] =
        "\x52\x16\x7d\xe2\xd6\xc5\x02\xd9\x9f\xa1\x0c\x27\xb2\xab\x62\x03"
        "\xbd\xeb\xc2\xca\xfb\xbf\xde\xf1\x58\x72\xa4\x3d\xd6\x10\xc2\x36"
        "\x2f\x79\x6a\xd9\xbc\xb5\x52\x8d\x95\x87\x00\x58\xfa\x45\x44\x53"
        "\xf1\xe6\x06\x5b\x31\x5d\x41\x0a\x3f\x26\x50\xe5\xd7\x1e\x69\xd7"
        "\x8d\x97\x67\xdf\xb4\xac\xcc\x05\x7f\xd2\x06\x92\x66\xb0\xf1\x80"
        "\xcb\x31\x9e\x30\xde\xd7\x53\x5b\xbe\x52\xd2\x4b\xe1\x51\xde\x4b"
        "\xb5\x98\xfc\x5c";
    const char EXPECTED_HASH[] =
        "\x25\xcb\x3e\xd3\x98\x3a\x91\xb4\xcf\x37\xa6\x51\x93\x91\x6c\x5e"
        "\x3e\x21\x1b\x63\xe9\x43\xe2\xf7\xb5\x0a\x85\xd3\x49\xa4\x63\xb9"
        "\x41\xaa\xd3\x3e\xff\x16\x56\x1b\xdf\xdc\x92\xfd\xa0\x6a\x4e\x1d"
        "\x94\xb1\x62\xde\x48\xf0\x6d\x3c\x62\x69\x40\xb3\x10\x20\x92\x5f";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 101.
 */
BEGIN_TEST_F(hash_101)
    const char INPUT[] =
        "\xce\xde\x66\x97\xd4\x22\xdd\xaa\x78\xe2\xd5\x5a\xe0\x80\xb8\xb9"
        "\xe9\x35\x6c\x69\xbc\x55\x82\x01\xa2\xd4\xb0\xb3\x19\x0a\x81\x2c"
        "\x27\xb3\x4b\xbc\xee\x3a\x62\xb7\x81\x37\x8b\x1b\xf6\x36\xb3\x72"
        "\xbc\xba\xe1\xfa\x2f\x81\x6a\x04\x6a\x0a\x64\x9a\x5c\x55\x5c\x64"
        "\x1f\xea\x4c\xcd\x84\x1c\xc7\x61\xf3\x8f\x77\x79\x72\xf8\xc9\x1b"
        "\x03\x24\xe7\x1c\x33\x3c\xe7\x87\xf0\x47\x41\x43\x9b\xf0\x87\xef"
        "\x5e\x89\x50\x11\xc0";
    const char EXPECTED_HASH[] =
        "\x0b\xe4\x2a\x25\xd7\x7a\xc6\xad\x99\x5c\x6b\xe4\x8e\x78\x33\x80"
        "\xba\xd2\x5a\x61\x73\x2f\x87\xce\xfb\x0c\xce\x1a\x76\x9c\xd6\x90"
        "\x81\xf4\x94\xa1\xa1\x2d\x65\x76\x64\xef\x2b\x4d\x9c\x41\xf2\xee"
        "\x83\xf6\xe9\xa8\x43\x27\xd8\x75\x6a\xf9\xf9\x85\x59\x5e\x7d\x3b";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 102.
 */
BEGIN_TEST_F(hash_102)
    const char INPUT[] =
        "\x56\xd1\x8d\x3e\x2e\x49\x64\x40\xd0\xa5\xc9\xe1\xbc\xb4\x64\xfa"
        "\xf5\xbc\x70\xa8\xb5\x62\x12\x4f\x5f\xc9\xe9\xde\xb5\xfe\xe6\x54"
        "\x4b\x94\x5e\x83\x3b\x8b\x5d\x13\x1b\x77\x3e\xcb\x2c\xdd\x78\x0c"
        "\xd4\xe1\xbb\x9e\x4f\x1e\x3c\xb0\xa1\xd6\x4d\x19\xcf\x4b\x30\xe4"
        "\x4e\x6c\x2d\x0c\xbc\xb4\xe2\x84\xce\x50\xdb\x7a\x8a\x80\x62\xdd"
        "\xb6\x3f\x98\x1d\x90\x26\xc5\x32\xbf\x8e\xed\xdf\x8a\xf5\xa4\x38"
        "\x48\xa3\x22\x62\x17\x8c";
    const char EXPECTED_HASH[] =
        "\x98\x2d\xc6\x1c\x91\xa9\x37\x70\x58\x2e\xee\x80\x25\xaa\x55\xda"
        "\x8e\x9e\xdb\x96\x6b\xf5\xcf\x70\xd4\xa6\x53\x4c\x0d\x53\xa2\x78"
        "\x9a\x8c\x4f\xb6\x5b\x7f\xed\x47\x8c\xda\x02\xed\x1e\x0d\x19\x8d"
        "\x85\xc5\xc7\x35\xb2\x41\x7c\x5f\xab\x5d\x34\xe9\x69\xfc\x8e\x7e";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 103.
 */
BEGIN_TEST_F(hash_103)
    const char INPUT[] =
        "\x25\xa7\x32\x0d\xfa\xec\x5a\xf6\x5d\xa4\xd0\xf8\x68\x8e\x29\xe8"
        "\xe9\x55\x32\xec\xc1\x66\x79\xea\x8a\xff\x0f\x40\x7d\x89\x8d\xb6"
        "\x92\x28\x55\xb0\xe8\x90\x1a\xa9\x68\x1a\xa3\xdc\xa6\x17\xcb\x44"
        "\x07\x64\xcd\xc7\x29\x3f\xbe\xaf\x7f\x58\x5b\x59\x3c\x2b\x05\x31"
        "\x73\x8e\x0a\xde\x7c\x86\x26\xb9\x99\x5f\x4a\x84\xd9\xfc\x9b\x59"
        "\x3d\x6b\xbe\xe0\x1a\xbc\x53\xc5\xbe\x14\xbf\x69\x56\xfd\x2f\xd8"
        "\x10\x00\xda\xfc\x7c\x76\x86";
    const char EXPECTED_HASH[] =
        "\x74\x9c\x92\x8c\x3d\x55\x10\x92\x5b\xfe\x98\x65\x90\x25\xb0\xed"
        "\x7c\x01\xac\xd4\xd5\x9a\x9b\xf1\xc5\x48\x63\xa0\x88\x09\x17\x71"
        "\xdc\x9d\x40\x7b\xdb\xf8\x3b\x0f\x44\xb0\x90\x2e\x10\x34\x9b\xa7"
        "\x9c\x84\xd0\x98\x1d\x5e\x8c\x4f\x5c\x73\x3a\x11\x7f\xed\x07\x90";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 104.
 */
BEGIN_TEST_F(hash_104)
    const char INPUT[] =
        "\x3d\x71\x77\xb2\x8f\xfd\x91\x6e\x7e\x06\x34\x89\x58\x33\xba\x0b"
        "\xd9\xe0\x65\x3d\xf2\xcc\x42\x02\xc8\x11\x53\x6a\x00\x5a\xec\x85"
        "\x3a\x50\x5e\x75\xdb\x55\xd3\xc7\x10\x75\x79\x04\x10\x99\xe3\x82"
        "\xa1\xfe\xac\x80\xdd\xe6\x5d\x72\x36\x8e\x90\x9a\xb8\x5f\x56\xd8"
        "\x8e\x68\xd7\xc3\xc8\x0c\x38\xf8\x5b\xf8\xc2\xb3\x69\x59\x40\x9c"
        "\xc3\x4b\xa8\xe3\xad\x94\xfe\x8e\xe1\x92\x76\x12\xd6\x72\xd9\x21"
        "\x41\xa3\x29\xc4\xdd\x8a\x88\xa9";
    const char EXPECTED_HASH[] =
        "\x14\xa3\x31\x50\x8c\xd7\xd9\x4f\xcc\xe5\x6a\x66\xbf\x65\xf2\x08"
        "\x70\xa2\x81\xc8\x44\x2f\x8d\xbd\x4c\x23\x71\x45\x4a\x2b\x66\xf8"
        "\xd0\x99\x4a\x0b\x67\x69\x2e\x77\x1e\xfc\x6a\x5e\x0b\x88\x7a\xca"
        "\xe7\xd6\xf4\xec\x73\x38\xe1\xaa\x89\xf2\xab\xc7\x03\x4c\x4e\x4c";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 105.
 */
BEGIN_TEST_F(hash_105)
    const char INPUT[] =
        "\xc0\x33\xe4\xa5\x12\x29\x7c\xae\xcd\xbe\xad\x89\x2b\x11\xa9\xf7"
        "\x00\x7a\xf9\xa7\x4b\xca\xb8\x9e\x0b\xd4\xff\xdd\x54\x2c\xa0\x3e"
        "\xa1\x2e\x17\xa0\x6c\x42\xbd\x43\xfc\x5f\x3f\x75\x7f\xce\x4f\x6f"
        "\x58\x31\x99\x7a\xba\xc3\xf9\x56\x76\xe1\xeb\xdb\x11\xca\x43\xe1"
        "\x1a\xa3\x1e\x5e\xba\xbe\x18\xce\x8d\x1b\xbf\xd8\xb0\x2f\x48\x2e"
        "\x1c\xe5\x81\xb5\x32\xe3\x07\xe6\x96\x0e\xb9\x74\x41\x50\x6c\x2e"
        "\xd2\x99\xe1\x28\x25\x23\xf4\x15\x27";
    const char EXPECTED_HASH[] =
        "\x95\xac\x9b\x7d\x22\xaa\x45\x89\x21\x87\x4c\x4b\x43\x31\xe7\xd6"
        "\x47\x61\x85\x32\x17\xc3\xf8\x3c\x60\x1a\xbc\xbc\xcd\x7e\x2e\xaa"
        "\x6c\xa6\xce\x9a\x22\xeb\xcf\xe5\x04\x6d\x52\xf8\xa0\x90\x97\xf0"
        "\x43\xab\x8b\xc5\x92\x43\xfd\x77\x00\x90\xbb\x43\x2c\x31\x55\xe9";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 106.
 */
BEGIN_TEST_F(hash_106)
    const char INPUT[] =
        "\x69\xff\xf0\xf1\xa3\xdb\xfb\x36\xe3\x2f\x02\x58\x19\xfa\x99\xea"
        "\x9a\x0e\xda\xef\x73\x14\x5b\xf7\xfc\xd0\x5d\x8b\xb0\xa6\x46\xcb"
        "\x3b\x5d\x52\x56\xd5\x24\x85\x6a\xcf\xd2\xe4\x4d\x6b\x72\xe4\xeb"
        "\xf1\xff\x23\xc0\xff\x6c\x56\xf8\x21\xe7\x82\xd5\xa1\x5f\x70\x52"
        "\xa1\x44\x5b\x06\x66\x8e\xeb\x4a\xf7\x00\x67\x9e\xe7\xae\x26\x49"
        "\x6f\xbd\x46\x40\xc0\x6a\xa1\x49\x96\x4d\xfd\x60\x11\xdf\x83\x5a"
        "\xc1\x3b\x73\xc8\xff\x21\x15\x1e\x84\x40";
    const char EXPECTED_HASH[] =
        "\x45\xd4\xda\xa6\x52\x55\x8d\x1c\x12\xbe\xb0\xf5\x66\x2c\x71\x2f"
        "\x32\x5b\x4c\x80\x2f\xc6\xeb\x9e\xe0\x39\xc9\x49\xd0\x02\xbb\x78"
        "\x6f\x1a\x73\x27\x12\xbe\x94\x1f\x9c\x5c\x79\xb3\xe5\xc4\x30\x64"
        "\xd6\x3a\x38\x57\x8e\x5a\x54\xee\x52\x6a\xcb\x73\x5b\x9a\xd4\x5f";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 107.
 */
BEGIN_TEST_F(hash_107)
    const char INPUT[] =
        "\xb2\xc4\x39\xc9\x7a\xb7\xc6\x37\x36\xb3\x79\x63\x24\xd6\x8e\xeb"
        "\x7a\x47\x1e\xd1\x42\xbd\x96\x22\x68\x41\x67\xd6\x12\x34\xff\xf8"
        "\x2f\x93\xf9\x07\x53\x7a\x90\x9b\xc2\xe7\x5a\x4b\xcb\xc1\x33\xcf"
        "\x57\x19\x76\x62\xc1\xaf\x74\x6a\xe8\xb8\x1e\x5b\x83\xde\x05\xd9"
        "\xb5\x89\x85\x1d\xe2\x5d\x3c\x99\xc0\x04\xc1\xdf\xb1\x2d\x93\xbf"
        "\x50\xd4\x50\xaf\x49\xc4\x28\x71\x6f\x5b\x90\xef\x08\x8e\x3b\x6a"
        "\x6b\x2c\x46\xd3\xce\x67\xb3\x79\x59\x90\x18";
    const char EXPECTED_HASH[] =
        "\xc4\x8e\xc8\x3b\xe5\xfa\x66\x9e\x6e\xc8\xdb\x90\xac\xa9\x67\x6c"
        "\xfe\x2e\xc0\xd5\xe8\xe7\xa2\x43\x16\x87\xbb\x95\x3c\x0a\x30\x0b"
        "\xe3\xdb\x40\x75\xcc\xa3\xba\xc4\xdf\xa4\xd9\x71\xba\xf0\xfa\x1a"
        "\xff\x46\x63\x9d\xb4\xb2\x38\x85\x6f\xf3\x6d\x1d\xfc\xd5\x20\xf1";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 108.
 */
BEGIN_TEST_F(hash_108)
    const char INPUT[] =
        "\xc0\x16\xf5\x22\xf2\x6b\x74\x70\xe9\x22\xb9\xa2\x87\xe6\xd4\x5f"
        "\x6c\x28\x81\x3b\x68\xc1\x45\x7e\x36\xd9\xba\x26\x67\x08\x27\x2f"
        "\x9c\xbc\x54\x11\xf8\xdb\x9d\x8b\xd5\xa9\x44\x9f\xb6\xeb\x0c\xde"
        "\x7d\x4d\x03\xe5\xdf\x01\x9f\x28\x14\xa9\x0c\xee\xd3\x77\xc5\x9d"
        "\x7d\x92\x62\x38\x99\xbc\xb0\x26\x80\x33\x07\x35\x59\xd4\xd8\xde"
        "\x48\x86\x86\xcb\xe3\xd6\x77\x96\xe6\xdf\x6a\xd4\x27\x6d\x0b\x52"
        "\xcc\x62\xc4\x9e\xbb\x58\xd7\xc9\x52\x87\xaa\x6c";
    const char EXPECTED_HASH[] =
        "\x74\x02\xf1\xa9\x9b\x47\xe1\x02\xb3\xb7\x31\x40\xc6\x77\x1b\x07"
        "\xee\x6c\x33\xb3\x71\x5e\x9c\x40\x27\xc4\x41\xbe\xe4\x05\x11\xb7"
        "\x35\xd9\x5e\x50\x8b\xae\xa7\x8d\xa2\x6f\xde\xd9\xb7\x03\x8e\x9a"
        "\x53\xde\xfa\x58\x44\x8a\xba\x40\xdc\x1e\x62\xd7\xec\x59\x21\x07";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 109.
 */
BEGIN_TEST_F(hash_109)
    const char INPUT[] =
        "\xa7\x66\xb2\xa7\xef\x91\x67\x21\xf4\x67\x7b\x67\xdb\xc6\x5e\xf9"
        "\xb4\xd1\xbd\xa1\xad\x4e\x53\xfc\x85\x4b\x02\x36\x44\x08\x22\x15"
        "\x2a\x11\x19\x39\xe5\xab\x2b\xa2\x07\x71\x94\x72\xb6\x3f\xd4\xf4"
        "\xa5\x4f\x4b\xde\x44\xa2\x05\xd3\x34\xa2\xd7\x2c\xfe\x05\xab\xf8"
        "\x04\xf4\x18\x41\xb8\x6d\x36\x92\x0b\xe6\xb0\xb5\x29\x33\x1a\xc1"
        "\x63\xa9\x85\x55\x6c\x84\x51\x1e\xc9\x86\x43\x9f\x83\xe1\xd7\x31"
        "\x1f\x57\xd8\x48\xcf\xa0\x2d\xf9\xea\x0c\xf6\xb9\x9a";
    const char EXPECTED_HASH[] =
        "\xdd\xd6\x0f\x93\xa3\xba\xbc\x78\x29\x9c\xf7\x63\xe7\x91\x9d\x45"
        "\xac\x6f\x47\x97\x00\xe1\xad\xb0\x5a\xb1\x37\xac\xdf\x89\xc1\x52"
        "\x1e\xcb\x9d\xfe\xac\xd0\x91\xe5\x8c\xa5\x7a\x1d\xb9\x64\xa9\xc3"
        "\xcd\x1f\xa3\x91\x92\xcc\x1e\x9f\x73\x4c\xaa\x1c\x5f\xa6\x29\x75";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 110.
 */
BEGIN_TEST_F(hash_110)
    const char INPUT[] =
        "\x10\xf2\xbe\x77\xa4\x05\x57\x71\xa6\x70\x07\xcd\x86\x30\xe3\x23"
        "\x0e\x38\x28\x84\x99\xcb\x16\x03\x80\x29\x01\x74\xd6\x6d\xa5\x74"
        "\x55\xb6\xba\xaa\x97\x85\xc8\x4c\x8a\x66\x3d\xe4\x1e\xd3\xbd\x54"
        "\x40\x55\xb9\x17\x0c\xec\x43\xcb\x3e\xb1\x20\xec\xea\xba\x1f\xe3"
        "\x6e\x3e\xaa\x3f\xa4\xf9\x9b\x42\x5c\xd2\x51\x9f\x09\xbc\x02\x82"
        "\xba\xda\x52\xd1\x4c\xe6\x25\xb1\xde\xd3\xb2\x4d\x86\xb1\xda\xd3"
        "\x42\xd2\xb7\xbe\x32\x2b\x77\x5b\x04\xfc\x6b\x86\xaf\xb4";
    const char EXPECTED_HASH[] =
        "\xa8\x72\xfa\x33\xd4\x63\xb3\x34\x3c\xec\x57\xc2\x0c\x66\x97\x9c"
        "\x33\xe1\xad\x06\x7b\xfc\x70\x34\x54\x69\x6a\xab\x5d\xd0\x00\x3b"
        "\xc1\x94\x31\x8f\x4a\x8e\xbb\xc7\x45\x03\xfe\xb7\x21\x1a\x47\x2d"
        "\xad\xee\x99\x1e\xfe\x3e\x38\xf2\x1a\x13\x10\xf8\xa7\x6e\xac\x80";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 111.
 */
BEGIN_TEST_F(hash_111)
    const char INPUT[] =
        "\x32\x45\x33\xe6\x85\xf1\x85\x2e\x35\x8e\xea\x8e\xa8\xb8\x1c\x28"
        "\x8b\x3f\x3b\xeb\x1f\x2b\xc2\xb8\xd3\xfd\xba\xc3\x18\x38\x2e\x3d"
        "\x71\x20\xde\x30\xc9\xc2\x37\xaa\x0a\x34\x83\x1d\xeb\x1e\x5e\x06"
        "\x0a\x79\x69\xcd\x3a\x97\x42\xec\x1e\x64\xb3\x54\xf7\xeb\x29\x0c"
        "\xba\x1c\x68\x1c\x66\xcc\x7e\xa9\x94\xfd\xf5\x61\x4f\x60\x4d\x1a"
        "\x27\x18\xaa\xb5\x81\xc1\xc9\x49\x31\xb1\x38\x7e\x4b\x7d\xc7\x36"
        "\x35\xbf\x3a\x73\x01\x17\x40\x75\xfa\x70\xa9\x22\x7d\x85\xd3";
    const char EXPECTED_HASH[] =
        "\x3b\x26\xc5\x17\x07\x29\xd0\x81\x41\x53\xbe\xcb\x95\xf1\xb6\x5c"
        "\xd4\x2f\x9a\x6d\x06\x49\xd9\x14\xe4\xf6\x9d\x93\x8b\x5e\x9d\xc0"
        "\x41\xcd\x0f\x5c\x8d\xa0\xb4\x84\xd7\xc7\xbc\x7b\x1b\xde\xfb\x08"
        "\xfe\x8b\x1b\xfe\xdc\x81\x10\x93\x45\xbc\x9e\x9a\x39\x9f\xee\xdf";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 112.
 */
BEGIN_TEST_F(hash_112)
    const char INPUT[] =
        "\x51\x89\x85\x97\x7e\xe2\x1d\x2b\xf6\x22\xa2\x05\x67\x12\x4f\xcb"
        "\xf1\x1c\x72\xdf\x80\x53\x65\x83\x5a\xb3\xc0\x41\xf4\xa9\xcd\x8a"
        "\x0a\xd6\x3c\x9d\xee\x10\x18\xaa\x21\xa9\xfa\x37\x20\xf4\x7d\xc4"
        "\x80\x06\xf1\xaa\x3d\xba\x54\x49\x50\xf8\x7e\x62\x7f\x36\x9b\xc2"
        "\x79\x3e\xde\x21\x22\x32\x74\x49\x2c\xce\xb7\x7b\xe7\xee\xa5\x0e"
        "\x5a\x50\x90\x59\x92\x9a\x16\xd3\x3a\x9f\x54\x79\x6c\xde\x57\x70"
        "\xc7\x4b\xd3\xec\xc2\x53\x18\x50\x3f\x1a\x41\x97\x64\x07\xaf\xf2";
    const char EXPECTED_HASH[] =
        "\xc0\x09\x26\xa3\x74\xcd\xe5\x5b\x8f\xbd\x77\xf5\x0d\xa1\x36\x3d"
        "\xa1\x97\x44\xd3\xf4\x64\xe0\x7c\xe3\x17\x94\xc5\xa6\x1b\x6f\x9c"
        "\x85\x68\x9f\xa1\xcf\xe1\x36\x55\x35\x27\xfd\x87\x6b\xe9\x16\x73"
        "\xc2\xca\xc2\xdd\x15\x7b\x2d\xef\xea\x36\x08\x51\xb6\xd9\x2c\xf4";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 113.
 */
BEGIN_TEST_F(hash_113)
    const char INPUT[] =
        "\x91\x59\x76\x72\x75\xba\x6f\x79\xcb\xb3\xd5\x8c\x01\x08\x33\x9d"
        "\x8c\x6a\x41\x13\x89\x91\xab\x7a\xa5\x8b\x14\x79\x3b\x54\x5b\x04"
        "\xbd\xa6\x1d\xd2\x55\x12\x7b\x12\xcc\x50\x1d\x5a\xaa\xd4\x76\xe0"
        "\x9f\xa1\x4a\xec\x21\x62\x6e\x8d\x57\xb7\xd0\x8c\x36\xcd\xb7\x9e"
        "\xea\x31\x4b\xdd\x77\xe6\x57\x79\xa0\xb5\x4e\xab\x08\xc4\x8c\xeb"
        "\x97\x6a\xdf\x63\x1f\x42\x46\xa3\x3f\x7e\xf8\x96\x88\x7e\xa8\xb5"
        "\xdf\xa2\x08\x7a\x22\x5c\x8c\x18\x0f\x89\x70\x69\x61\x01\xfc\x28"
        "\x3b";
    const char EXPECTED_HASH[] =
        "\x3c\xd3\x38\x0a\x90\x86\x8d\xe1\x7d\xee\x4b\xd4\xd7\xf9\x0d\x75"
        "\x12\x69\x6f\x0a\x92\xb2\xd0\x89\x24\x0d\x61\xa9\xd2\x0c\xd3\xaf"
        "\x09\x4c\x78\xbf\x46\x6c\x2d\x40\x4d\xd2\xf6\x62\xec\x5f\x4a\x29"
        "\x9b\xe2\xad\xea\xdf\x62\x7b\x98\xe5\x0e\x1c\x07\x2b\x76\x9d\x62";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 114.
 */
BEGIN_TEST_F(hash_114)
    const char INPUT[] =
        "\xfe\x2d\x8a\xe2\x00\xe6\x65\x7f\xdc\x74\x94\xaf\x5a\x12\xb2\xae"
        "\x94\x03\x48\xf1\xf9\x83\xf0\xba\x98\xfe\xbb\xe9\x9c\x80\xd1\x15"
        "\x12\x6d\x57\xdb\xf3\x72\x96\x76\x5e\xbb\x59\x90\x25\x66\x96\x58"
        "\x8b\x38\x51\xd5\x4c\x8f\xbe\x7a\xde\x98\xa6\xfa\xf7\xc2\x0b\x5e"
        "\x4f\x73\x0f\x54\xa7\xf9\x12\xca\x0a\xc3\x1b\xbb\x53\xd1\x79\x49"
        "\xef\x69\xaa\x0d\xe4\x0c\x7b\xab\x12\xa8\x71\xa9\xb9\x0f\x68\x81"
        "\x3c\xa8\x7a\xf4\x25\x64\x22\xa2\x68\xf4\xa1\xd8\xec\x3a\xa1\xa9"
        "\x47\xfd";
    const char EXPECTED_HASH[] =
        "\x80\x25\xa8\x60\x8d\xf0\xf6\xa0\x1c\x34\xcd\xec\x01\x2d\x4c\xb2"
        "\x58\x52\xe1\xb1\x00\xb6\x81\x72\xfc\x4e\x86\xac\x8b\x71\x26\xb6"
        "\x48\x59\xcb\x9e\x76\x7a\x7e\x59\x06\x09\x89\xce\xdb\xd9\x25\xaf"
        "\xc4\x75\xca\x73\x69\xbd\x43\xf8\x5a\xe5\x90\xe2\x24\xe0\x36\xdd";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 115.
 */
BEGIN_TEST_F(hash_115)
    const char INPUT[] =
        "\xdc\x28\x48\x4e\xbf\xd2\x93\xd6\x2a\xc7\x59\xd5\x75\x4b\xdf\x50"
        "\x24\x23\xe4\xd4\x19\xfa\x79\x02\x08\x05\x13\x4b\x2c\xe3\xdf\xf7"
        "\x38\xc7\x55\x6c\x91\xd8\x10\xad\xba\xd8\xdd\x21\x0f\x04\x12\x96"
        "\xb7\x3c\x21\x85\xd4\x64\x6c\x97\xfc\x0a\x5b\x69\xed\x49\xac\x8c"
        "\x7c\xed\x0b\xd1\xcf\xd7\xe3\xc3\xcc\xa4\x73\x74\xd1\x89\x24\x7d"
        "\xa6\x81\x1a\x40\xb0\xab\x09\x70\x67\xed\x4a\xd4\x0a\xde\x2e\x47"
        "\x91\xe3\x92\x04\xe3\x98\xb3\x20\x49\x71\x44\x58\x22\xa1\xbe\x0d"
        "\xd9\x3a\xf8";
    const char EXPECTED_HASH[] =
        "\x61\x51\x15\xd2\xe8\xb6\x2e\x34\x5a\xda\xa4\xbd\xb9\x53\x95\xa3"
        "\xb4\xfe\x27\xd7\x1c\x4a\x11\x1b\x86\xc1\x84\x14\x63\xc5\xf0\x3d"
        "\x6b\x20\xd1\x64\xa3\x99\x48\xab\x08\xae\x06\x07\x20\xd0\x5c\x10"
        "\xf6\x02\x2e\x5c\x8c\xaf\x2f\xa3\xbc\xa2\xe0\x4d\x9c\x53\x9d\xed";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 116.
 */
BEGIN_TEST_F(hash_116)
    const char INPUT[] =
        "\x5a\xf8\xc0\xf2\x6d\xb4\xe9\x9b\x47\xec\x2e\x4a\x01\xa7\x86\xe7"
        "\x78\x99\xe4\x6d\x46\x4a\xc3\x37\xf1\x75\x02\x7b\x61\xae\xf3\x14"
        "\x98\x48\xaf\x84\x9d\x76\xac\x39\xb9\xb0\x91\x0f\xe6\x59\x48\x17"
        "\x85\x9e\x55\x97\x4f\xa1\x67\x51\x8e\xd7\x2d\x08\x8d\xae\x6b\x41"
        "\x4d\x74\x4d\x47\x79\x74\xfb\x71\x9c\x62\x6d\xa7\x92\xf9\x81\x23"
        "\x3d\xe2\x4b\x75\x79\xd8\xac\xca\x51\x0a\x26\x6d\x73\xc0\xee\x8e"
        "\xe1\x42\x43\x43\xea\xf6\xff\xcc\x59\xc8\x6c\x1b\xec\xce\x58\x94"
        "\x07\x2c\x6c\x11";
    const char EXPECTED_HASH[] =
        "\x09\xda\x28\x4d\x5b\x65\x56\x50\x8b\xe5\x4c\x8a\xb6\xc9\x7b\xbd"
        "\x47\x29\x95\xc6\xbb\xd5\x85\x91\x7e\xcd\xb5\x4e\xa9\x16\x72\x08"
        "\xda\xaa\x07\x0a\x7b\x2b\x7d\x8e\x93\xce\x13\x15\xf0\xd1\xef\x8d"
        "\x69\x66\x74\x29\xc4\x4d\xc5\xee\x14\x99\xde\x57\xb2\x29\xa3\x98";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 117.
 */
BEGIN_TEST_F(hash_117)
    const char INPUT[] =
        "\x49\xcd\x0b\xa0\xdf\x5b\xb3\xf4\x3f\x68\x46\x4e\x3e\x83\xe9\xcb"
        "\xd5\xd5\xee\x07\x7f\xfa\x55\x91\xe3\x0f\x93\x9c\xb3\x0c\x93\xf7"
        "\xd4\x54\xfb\x3f\xbf\x8b\xb0\x53\x27\xa8\x9c\x08\xdc\x4b\xaf\x1e"
        "\xef\x50\x23\x73\x17\xa4\x05\x77\x53\x57\xf1\xe0\xd1\xf3\x1d\x9f"
        "\x0f\x0d\x98\x12\x40\x19\xd4\x7b\xf1\x83\x63\xb1\xec\xfb\xfe\x15"
        "\x5c\x10\xcb\xc8\x33\x00\xe0\x1b\xc9\xce\x03\x47\xc5\x96\xb3\x5f"
        "\x41\x1e\x6d\x82\x29\xad\x28\x55\xe4\x20\x22\xb0\x37\x3a\xde\x98"
        "\x66\x3c\x6d\x6e\x9c";
    const char EXPECTED_HASH[] =
        "\x30\xcb\xf0\x67\x9a\x97\xc8\x71\x57\x4d\x2f\xc0\x5d\x7a\xa7\x60"
        "\xc6\xbc\x8a\x86\x4b\x7d\x24\x6c\x39\xb9\xe8\x12\xf9\xb7\xff\x7b"
        "\x4e\xf5\x19\x7d\xd5\xb6\x94\x93\x30\x66\x88\xb8\x56\x4d\xe1\xad"
        "\x47\xd7\x55\x05\xc9\x13\xba\x6a\x78\x78\x8f\x8c\xaf\x57\x88\xbd";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 118.
 */
BEGIN_TEST_F(hash_118)
    const char INPUT[] =
        "\xa8\xa3\x7d\xfc\x08\x3a\xd2\xf4\x7f\xff\x46\x87\x38\xbf\x8b\x72"
        "\x8e\xb7\xf1\x90\x7e\x42\x7f\xa1\x5c\xb4\x42\x4b\xc6\x85\xe5\x5e"
        "\xd7\xb2\x82\x5c\x9c\x60\xb8\x39\xcc\xc2\xfe\x5f\xb3\x3e\x36\xf5"
        "\x70\xcb\x86\x61\x60\x9e\x63\x0b\xda\x05\xee\x64\x1d\x93\x84\x28"
        "\x86\x7d\x90\xe0\x07\x44\xa4\xaa\xd4\x94\xc9\x3c\x5f\x6d\x13\x27"
        "\x87\x80\x78\x59\x0c\xdc\xe1\xe6\x47\xc9\x82\x08\x18\xf4\x67\x64"
        "\x1f\xcd\x50\x8e\x2f\x2e\xbf\xd0\xff\x3d\x4f\x27\x23\x93\x47\x8f"
        "\x3b\x9e\x6f\x80\x6b\x43";
    const char EXPECTED_HASH[] =
        "\x8e\x1c\x91\x72\x9b\xe8\xeb\x40\x22\x6f\x6c\x58\xa0\x29\x38\x0e"
        "\xf7\xed\xb9\xdc\x16\x6a\x5c\x3c\xdb\xce\xfe\x90\xbd\x30\xd8\x5c"
        "\xb7\xc4\xb2\x48\xe6\x6a\xbf\x0a\x3a\x4c\x84\x22\x81\x29\x9b\xef"
        "\x6d\xb8\x88\x58\xd9\xe5\xab\x52\x44\xf7\x0b\x79\x69\xe1\xc0\x72";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 119.
 */
BEGIN_TEST_F(hash_119)
    const char INPUT[] =
        "\x36\xaf\x17\x59\x54\x94\xef\x79\x3c\x42\xf4\x84\x10\x24\x6d\xf0"
        "\x7d\x05\x93\x6a\x91\x8a\xfe\x74\xcd\x00\x5e\x53\x7c\x58\x6b\x28"
        "\x43\x70\x1f\x5d\xf8\x95\x22\x42\xb7\x45\x86\xf8\x33\x39\xb4\x8f"
        "\x4b\xa3\xa6\x6b\xde\xb4\x57\xec\xdf\x61\x78\x4e\xac\x67\x65\xcd"
        "\x9b\x8c\x57\x0d\xd6\x28\xdb\xba\x6a\xe5\x83\x6b\x9a\xc3\xdb\xcd"
        "\x79\x5f\x9e\xfd\xb8\x74\x2a\x35\xbc\xa2\x32\xab\xf3\x6e\xb3\xb6"
        "\x69\x8b\x29\x33\x96\x58\x02\x27\x7b\xa9\x53\xa6\xed\xca\xca\xf3"
        "\x30\xc1\xe4\xe8\xc7\xd4\x5f";
    const char EXPECTED_HASH[] =
        "\x15\x8b\xfc\x34\x8a\x30\xb4\xfa\xbb\xe3\x55\xa7\xd4\x4b\xdc\x21"
        "\x22\xa4\xc8\x50\x44\x4c\x03\xf2\x89\x00\x3c\xe0\x1b\xfc\x1e\xbf"
        "\x3e\xcc\x0f\xeb\xb6\xa8\xff\x52\x3d\x25\xdb\x76\x81\xb0\x5b\xdc"
        "\xe0\x48\xd1\x19\x43\xab\x47\x6c\x19\x67\xcf\x65\x56\xc4\xa1\x20";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 120.
 */
BEGIN_TEST_F(hash_120)
    const char INPUT[] =
        "\x42\xd6\x6e\xdc\x5f\x22\xe0\xc1\x3c\x25\x50\x4c\x51\x01\xa5\xd1"
        "\x72\xd2\xdb\x72\x09\xe4\x61\xef\xa3\x23\xc0\xbf\xae\xd2\x7e\x5f"
        "\x80\x80\x42\xea\x9c\x38\x38\xea\x31\xf9\xb7\x6d\xe4\x65\x22\x5c"
        "\xcf\xbd\x0c\x09\xca\x0d\x9f\x07\xe9\xa4\x3e\x3e\x46\xc7\x69\x3e"
        "\x00\xa7\xe1\xd4\x83\x90\x0d\xdb\x0a\x62\x9d\x55\x63\x45\x6d\xbb"
        "\xf2\x99\xac\x91\xf9\x2c\x3d\x3c\x17\xb0\x5d\x18\x0e\x6c\x87\xc6"
        "\xc9\x31\x94\xc3\x9d\x90\x27\x3f\xcf\x4a\x48\x2c\x56\x08\x4f\x95"
        "\xe3\x4c\x04\x31\x1f\xa8\x04\x38";
    const char EXPECTED_HASH[] =
        "\x06\x1a\xfb\x11\x9a\x3c\x60\x87\x6e\x04\xc1\x0f\x12\xad\x0f\x4b"
        "\x97\x75\x93\xdc\x5a\x2d\x21\x09\x6a\x57\xe7\xd3\xf7\xd4\xd4\x4f"
        "\xde\xf9\x34\xb2\xc1\x7d\x75\x30\x67\x4e\x4f\x4a\x1c\x17\x6d\xbd"
        "\xcc\x54\x81\x1a\x22\xe1\xb8\x71\x2e\x41\x92\xfc\x2d\x4b\xf8\xe8";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 121.
 */
BEGIN_TEST_F(hash_121)
    const char INPUT[] =
        "\xf9\x1b\xb2\xe1\xa9\xc4\xcd\x96\xbf\x25\x04\x26\xb3\xa6\xaf\xd9"
        "\xb8\x7a\xc5\x1e\x93\x25\x4d\x2d\xae\x3b\x16\xec\x68\x6b\xa8\x0f"
        "\xb0\xbd\x7a\x84\xd2\x18\x66\x0e\x90\x07\x59\x30\x75\xbc\x4f\x4c"
        "\x66\x56\x7f\x0c\x7a\x5f\xd2\x01\x0c\x99\x9a\x8a\x0e\xfa\x81\xf8"
        "\x9f\xf5\xbf\xef\xe0\xfb\x91\x0f\x04\x42\xe6\xd4\xa7\xc5\x5b\xbb"
        "\x61\x8c\x69\xa7\x9a\x2d\xdd\x82\xa0\x93\x89\x27\xf6\xfe\x3a\x80"
        "\xf0\x4b\xea\xeb\x7c\x76\x36\xe3\x43\x5d\x12\xdc\xf1\xc6\xbb\x6e"
        "\xd0\xa4\xed\xb6\x9c\x96\x57\xfa\x93";
    const char EXPECTED_HASH[] =
        "\x6e\x69\x2c\x8c\x69\x4e\xe0\xa3\x56\x5f\x37\xa2\x99\xe0\x00\x6b"
        "\x85\xab\x4a\x82\x1b\x20\xe7\x67\x98\x22\x02\x29\xf6\x56\xef\xc6"
        "\xa2\x02\x11\xa4\xe7\xe4\xed\x77\xfa\xcd\xe0\xd7\x0e\x4d\x5d\x95"
        "\xbc\x8e\xd1\xd7\xa5\x6d\x8d\xf1\x44\x6d\x56\x2f\x04\x4b\x34\x4c";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 122.
 */
BEGIN_TEST_F(hash_122)
    const char INPUT[] =
        "\xd1\xeb\x96\x1c\xa6\xa8\xf6\x7c\x49\xb6\x1e\x4d\x3c\xea\xa2\xa1"
        "\xde\x6f\x0e\xa9\x27\xb1\x32\xbf\x98\x7a\xbd\xaa\x72\x5b\x0e\x1e"
        "\x27\x4e\x46\x83\x0e\x99\xa2\xf7\x5a\xf6\x08\x96\x4d\xf0\xdf\xf9"
        "\xa9\x90\x24\xfc\x68\x39\xba\xc5\xac\xd1\x02\x02\xf9\x21\xac\x71"
        "\xa2\x7f\xcd\xa6\x81\xaa\x31\x09\xeb\xf5\xf2\x1e\xe3\xa8\x49\x09"
        "\x8e\xa3\xa5\x51\xe8\x44\xfa\xe4\xb4\x8b\x5c\x5b\xb9\x7c\xcc\x80"
        "\x2b\xc5\x52\x0d\x68\xa1\x4c\xb7\xe5\xfc\x05\x6b\x67\xd8\x89\xd8"
        "\x76\xef\xb8\x2d\x0e\x9a\x9a\x24\x99\xf1";
    const char EXPECTED_HASH[] =
        "\x39\xb2\xc7\x6e\xc2\x07\x12\x0d\xe4\xb3\x20\xc7\xfe\x06\x9e\x60"
        "\x2c\x9c\x38\xf2\x57\x59\x6d\xa7\x36\x93\x95\xe8\x7e\xb6\x4b\x3a"
        "\xcf\xf9\x88\xc1\x83\x9a\xc2\x69\xd5\x01\x2c\x09\x3f\x9e\xdd\x4b"
        "\x7c\xab\xf1\x3b\xde\xa7\xd4\x2e\x96\x9a\xb1\x08\x26\x9c\x6a\xb0";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 123.
 */
BEGIN_TEST_F(hash_123)
    const char INPUT[] =
        "\xad\xf2\x26\x32\x00\xf3\x76\x88\x6b\xa7\xb6\xf5\xe4\x41\x1d\x5f"
        "\x07\xf7\xd9\xd1\x01\x59\x0c\x73\xac\xe1\x14\xba\xfb\xcb\x0f\xdc"
        "\x99\x26\x9e\x87\xcd\x2c\xea\xd2\xa1\xcf\xe5\x74\x43\x94\xd3\x33"
        "\xab\xa4\x08\xa0\x7e\x21\xf3\x02\x33\xb6\x5b\x90\x74\x72\xe9\xe3"
        "\xc7\xd6\xe7\xaa\x6d\x2c\x47\xa0\x8a\x1b\xe7\xbb\x87\x79\x13\xa6"
        "\xb5\x60\x4c\x72\x33\x84\x47\x89\x11\xc3\x39\xe3\xb5\xfe\x52\x7c"
        "\x7e\x28\x87\x05\xa8\x9c\x95\xd9\x70\xb4\x43\x34\x78\x97\xe7\x9f"
        "\x6c\x52\x2b\xaf\xe6\x2b\x11\xef\x8f\x31\x35";
    const char EXPECTED_HASH[] =
        "\x3c\x23\xd2\xd8\xcf\x4d\xb6\xac\x6a\x42\xe2\x72\x08\x18\x0f\x37"
        "\x66\x8b\xef\x5e\xe0\xa3\xf8\x79\x48\x3c\x8e\x60\x4e\x7f\x42\x58"
        "\x3f\x20\x20\x37\xb8\xd2\x42\xc0\x4a\x87\x34\x5b\x8b\xe6\xdc\x8b"
        "\x12\x1d\x64\x84\xb9\xed\xad\x0d\x73\xc8\x94\xc1\x28\x8f\x5c\xae";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 124.
 */
BEGIN_TEST_F(hash_124)
    const char INPUT[] =
        "\x18\xe7\x5b\x47\xd8\x98\xac\x62\x9c\x48\xe8\x0d\xbf\xb7\x5d\xae"
        "\x1e\x17\x00\xb7\x71\x16\x5e\xcc\xdb\x18\xd6\x28\xbf\xc4\x06\x3d"
        "\xd6\xc3\x83\x9a\x7e\xc4\xcd\x12\x55\xc4\x82\x1b\x07\x8c\xd1\x74"
        "\x64\x7b\x32\x0b\xb6\x85\x54\x1d\x51\x7c\x57\x9f\x6b\x8e\x3c\xdd"
        "\x2e\x10\x9a\x61\x0c\x7a\x92\x16\x53\xb2\x04\xad\x01\x8d\x03\x40"
        "\xd9\x93\x87\x35\xb6\x02\x62\x66\x20\x16\x76\x7e\x1d\x88\x24\xa6"
        "\x49\x54\x08\x62\x29\xc0\xe3\xb5\xbd\x9a\xd8\x8c\x54\xc1\xdc\x5a"
        "\xa4\xe7\x68\xff\x1a\x94\x70\xee\x6f\x6e\x99\x8f";
    const char EXPECTED_HASH[] =
        "\x01\xc7\x56\xb7\xc2\x0b\x5f\x95\xfd\x2b\x07\x9a\xb6\xa5\x0f\x28"
        "\xb9\x46\xfb\x16\x26\x6b\x07\xc6\x06\x09\x45\xdc\x4f\xe9\xe0\xd2"
        "\x79\xc5\xb1\x50\x5b\x9e\xc7\xd8\xf8\xf3\xc9\xeb\xf0\xc5\xee\x93"
        "\x65\xae\xc0\x8c\xf2\x78\xd6\x5b\x64\xda\xec\xcc\x19\xd3\xcb\xf4";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 125.
 */
BEGIN_TEST_F(hash_125)
    const char INPUT[] =
        "\xc2\x96\x33\x42\xcf\xaa\x88\xcc\xd1\x02\xa2\x58\xe6\xd6\x29\xf6"
        "\xb0\xd3\x67\xdd\x55\x11\x65\x02\xca\x44\x51\xea\x52\x36\x23\xbc"
        "\x41\x75\x81\x9a\x06\x48\xdf\x31\x68\xe8\xea\x8f\x10\xed\x27\x35"
        "\x48\x07\xd7\x6e\x02\xee\x1f\xdf\x1c\x9c\x65\x5e\xe2\xb9\xfd\x08"
        "\xd5\x57\x05\x8d\xab\xdf\x8d\xcf\x96\x4b\xfc\xac\xc9\x96\xae\x17"
        "\x39\x71\xe2\x6e\xa0\x38\xd4\x07\xc8\x24\x26\x0d\x06\xc2\x84\x8a"
        "\x04\xa4\x88\xc4\xc4\x56\xdb\xcd\xe2\x93\x9e\x56\x1a\xb9\x08\xc4"
        "\x09\x7b\x50\x86\x38\xd6\xcd\xa5\x56\x46\x5c\x9c\xc5";
    const char EXPECTED_HASH[] =
        "\xa4\xd2\xf5\x93\x93\xa5\xfe\xa6\x12\xc3\xc7\x45\xf4\xbb\x9f\x41"
        "\xaa\xf3\xa3\xce\x16\x79\xaa\x8a\xfc\x1a\x62\xba\xa4\xed\x45\x28"
        "\x19\x41\x8c\x8a\xe1\xa1\xe6\x58\x75\x79\x76\x69\x23\x90\xfc\x43"
        "\xd4\xde\xcf\x7d\x85\x5c\xd8\xb4\x98\xb6\xdc\x60\xca\xe0\x5a\x90";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 126.
 */
BEGIN_TEST_F(hash_126)
    const char INPUT[] =
        "\x85\x36\x0c\x3d\x42\x57\xd9\x87\x8e\x2f\x5c\x16\xd3\xcd\x7d\x07"
        "\x47\xdf\x3d\x23\x1e\x1a\x8f\x63\xfd\xdc\x69\xb3\xb1\x10\x1a\xf7"
        "\x21\x53\xde\x4c\x81\x54\xb0\x90\xc9\x81\x5f\x24\x66\xe0\xe4\xf0"
        "\x2f\x3a\xf3\xa8\x9a\x7f\xd0\x4e\x30\x66\x64\xf9\x3e\x54\x90\xd4"
        "\xce\x7f\xc1\x69\xd5\x53\xc5\x20\xae\x15\xdd\x02\xc7\xc6\x13\xc3"
        "\x9b\x4a\xcd\x00\xe0\xc9\xa3\xc5\x01\x56\x6e\x52\xce\xce\xa1\x1f"
        "\x73\x03\xdd\x1d\xa6\x1a\xbf\x3f\x25\x32\xfd\x39\x60\x47\xb1\x88"
        "\x72\x55\xf4\xb2\x56\xc0\xaf\xcf\x58\xf3\xae\x48\xc9\x47";
    const char EXPECTED_HASH[] =
        "\xe8\x35\x2d\xdc\xac\x59\xe3\x77\xea\x0f\x9c\x32\xbb\xb4\x3d\xfd"
        "\x1b\x6c\x82\x9f\xad\x19\x54\x24\x0c\x41\xb7\xc4\x5b\x0b\x09\xdb"
        "\x11\x06\x4b\x64\xe2\x44\x2a\x96\xf6\x53\x0a\xac\x2c\x4a\xbf\x3b"
        "\xeb\x1e\xae\x77\xf2\xbc\xe4\xef\xe8\x8f\xee\x1a\x70\xcf\x54\x23";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 127.
 */
BEGIN_TEST_F(hash_127)
    const char INPUT[] =
        "\xc1\x3e\x6c\xa3\xab\xb8\x93\xaa\x5f\x82\xc4\xa8\xef\x75\x44\x60"
        "\x62\x8a\xf6\xb7\x5a\xf0\x21\x68\xf4\x5b\x72\xf8\xf0\x9e\x45\xed"
        "\x12\x7c\x20\x3b\xc7\xbb\x80\xff\x0c\x7b\xd9\x6f\x8c\xc6\xd8\x11"
        "\x08\x68\xeb\x2c\xfc\x01\x03\x7d\x80\x58\x99\x2a\x6c\xf2\xef\xfc"
        "\xbf\xe4\x98\xc8\x42\xe5\x3a\x2e\x68\xa7\x93\x86\x79\x68\xba\x18"
        "\xef\xc4\xa7\x8b\x21\xcd\xf6\xa1\x1e\x5d\xe8\x21\xdc\xab\xab\x14"
        "\x92\x1d\xdb\x33\x62\x5d\x48\xa1\x3b\xaf\xfa\xd6\xfe\x82\x72\xdb"
        "\xdf\x44\x33\xbd\x0f\x7b\x81\x3c\x98\x12\x69\xc3\x88\xf0\x01";
    const char EXPECTED_HASH[] =
        "\x6e\x56\xf7\x7f\x68\x83\xd0\xbd\x4f\xac\xe8\xb8\xd5\x57\xf1\x44"
        "\x66\x19\x89\xf6\x6d\x51\xb1\xfe\x4b\x8f\xc7\x12\x4d\x66\xd9\xd2"
        "\x02\x18\x61\x6f\xea\x1b\xcf\x86\xc0\x8d\x63\xbf\x8f\x2f\x21\x84"
        "\x5a\x3e\x51\x90\x83\xb9\x37\xe7\x0a\xa7\xc3\x58\x31\x0b\x5a\x7c";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to hash test vector 128.
 */
BEGIN_TEST_F(hash_128)
    const char INPUT[] =
        "\xfd\x22\x03\xe4\x67\x57\x4e\x83\x4a\xb0\x7c\x90\x97\xae\x16\x45"
        "\x32\xf2\x4b\xe1\xeb\x5d\x88\xf1\xaf\x77\x48\xce\xff\x0d\x2c\x67"
        "\xa2\x1f\x4e\x40\x97\xf9\xd3\xbb\x4e\x9f\xbf\x97\x18\x6e\x0d\xb6"
        "\xdb\x01\x00\x23\x0a\x52\xb4\x53\xd4\x21\xf8\xab\x9c\x9a\x60\x43"
        "\xaa\x32\x95\xea\x20\xd2\xf0\x6a\x2f\x37\x47\x0d\x8a\x99\x07\x5f"
        "\x1b\x8a\x83\x36\xf6\x22\x8c\xf0\x8b\x59\x42\xfc\x1f\xb4\x29\x9c"
        "\x7d\x24\x80\xe8\xe8\x2b\xce\x17\x55\x40\xbd\xfa\xd7\x75\x2b\xc9"
        "\x5b\x57\x7f\x22\x95\x15\x39\x4f\x3a\xe5\xce\xc8\x70\xa4\xb2\xf8";
    const char EXPECTED_HASH[] =
        "\xa2\x1b\x10\x77\xd5\x2b\x27\xac\x54\x5a\xf6\x3b\x32\x74\x6c\x6e"
        "\x3c\x51\xcb\x0c\xb9\xf2\x81\xeb\x9f\x35\x80\xa6\xd4\x99\x6d\x5c"
        "\x99\x17\xd2\xa6\xe4\x84\x62\x7a\x9d\x5a\x06\xfa\x1b\x25\x32\x7a"
        "\x9d\x71\x0e\x02\x73\x87\xfc\x3e\x07\xd7\xc4\xd1\x4c\x60\x86\xcc";
    vccrypt_hash_options_t options;
    vccrypt_hash_context_t context;
    vccrypt_buffer_t md;

    TEST_ASSERT(0 ==
        vccrypt_hash_options_init(&options, &fixture.alloc_opts,
            VCCRYPT_HASH_ALGORITHM_SHA_2_512));

    TEST_ASSERT(0 ==
        vccrypt_buffer_init(&md, &fixture.alloc_opts, options.hash_size));

    TEST_ASSERT(0 ==
        vccrypt_hash_init(&options, &context));

    TEST_ASSERT(0 ==
        vccrypt_hash_digest(&context, (const uint8_t*)INPUT, sizeof(INPUT) - 1));

    TEST_ASSERT(0 ==
        vccrypt_hash_finalize(&context, &md));

    TEST_ASSERT(0 == memcmp(md.data, EXPECTED_HASH, 64));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&md);
    dispose((disposable_t*)&options);
END_TEST_F()
