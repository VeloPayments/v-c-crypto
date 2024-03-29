/**
 * \file test_vccrypt_hmac512_ref.cpp
 *
 * Unit tests for the reference HMAC-SHA-512 implementation.
 *
 * \copyright 2017-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <string.h>
#include <vccrypt/mac.h>
#include <vpr/allocator/malloc_allocator.h>

class vccrypt_hmac512_ref_test {
public:
    void setUp()
    {
        //make sure HMAC-512 has been registered
        vccrypt_mac_register_SHA_2_512_HMAC();

        hmac_init_result =
            vccrypt_mac_options_init(
                &options, &alloc_opts, VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC);

        malloc_allocator_options_init(&alloc_opts);

        //create a dummy key
        buffer_init_result =
            vccrypt_buffer_init(&dummyKey, &alloc_opts, 64);
        if (buffer_init_result == 0)
            memset(dummyKey.data, 0, dummyKey.size);
    }

    void tearDown()
    {
        if (buffer_init_result == 0)
            dispose((disposable_t*)&dummyKey);

        if (hmac_init_result == 0)
            dispose((disposable_t*)&options);

        dispose((disposable_t*)&alloc_opts);
    }

    int buffer_init_result;
    int hmac_init_result;
    vccrypt_mac_options_t options;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t dummyKey;
};

TEST_SUITE(vccrypt_hmac512_ref_test);

#define BEGIN_TEST_F(name) \
TEST(name) \
{ \
    vccrypt_hmac512_ref_test fixture; \
    fixture.setUp();

#define END_TEST_F() \
    fixture.tearDown(); \
}

/**
 * SHA-512-HMAC should have been successfully initialized.
 */
BEGIN_TEST_F(options_init)
    TEST_ASSERT(0 == fixture.hmac_init_result);
END_TEST_F()

/**
 * We should be able to create an HMAC context.
 */
BEGIN_TEST_F(init)
    vccrypt_mac_context_t context;

    TEST_ASSERT(
        0 == vccrypt_mac_init(&fixture.options, &context, &fixture.dummyKey));

    dispose((disposable_t*)&context);
END_TEST_F()

/**
 * We should be able to HMAC RFC-4231 Test Case 1.
 */
BEGIN_TEST_F(test_case_1)
    const uint8_t KEY[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b
    };
    const uint8_t DATA[] = {
        0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65
    };
    const uint8_t EXPECTED_HMAC[] = {
        0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d,
        0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0,
        0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78,
        0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde,
        0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02,
        0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
        0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
        0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54
    };

    vccrypt_buffer_t keybuf, outbuf;
    vccrypt_mac_context_t context;

    //create key buffer
    TEST_ASSERT(
        0 == vccrypt_buffer_init(&keybuf, &fixture.alloc_opts, sizeof(KEY)));
    memcpy(keybuf.data, KEY, sizeof(KEY));

    //initialize MAC
    TEST_ASSERT(0 == vccrypt_mac_init(&fixture.options, &context, &keybuf));

    //digest input
    TEST_ASSERT(0 == vccrypt_mac_digest(&context, DATA, sizeof(DATA)));

    //create output buffer
    TEST_ASSERT(
        0
            == vccrypt_buffer_init(
                    &outbuf, &fixture.alloc_opts, fixture.options.mac_size));

    //finalize hmac
    TEST_ASSERT(0 == vccrypt_mac_finalize(&context, &outbuf));

    //the HMAC output should match our expected HMAC
    TEST_ASSERT(0 == memcmp(outbuf.data, EXPECTED_HMAC, sizeof(EXPECTED_HMAC)));

    //clean up
    dispose((disposable_t*)&outbuf);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&keybuf);
END_TEST_F()

/**
 * We should be able to HMAC RFC-4231 Test Case 2.
 */
BEGIN_TEST_F(test_case_2)
    const uint8_t KEY[] = {
        0x4a, 0x65, 0x66, 0x65
    };
    const uint8_t DATA[] = {
        0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20,
        0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20,
        0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
        0x69, 0x6e, 0x67, 0x3f
    };
    const uint8_t EXPECTED_HMAC[] = {
        0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2,
        0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56, 0xe0, 0xa3,
        0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6,
        0x10, 0x27, 0x0c, 0xd7, 0xea, 0x25, 0x05, 0x54,
        0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99, 0x4a,
        0x6d, 0x03, 0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd,
        0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b,
        0x63, 0x6e, 0x07, 0x0a, 0x38, 0xbc, 0xe7, 0x37
    };

    vccrypt_buffer_t keybuf, outbuf;
    vccrypt_mac_context_t context;

    //create key buffer
    TEST_ASSERT(
        0 == vccrypt_buffer_init(&keybuf, &fixture.alloc_opts, sizeof(KEY)));
    memcpy(keybuf.data, KEY, sizeof(KEY));

    //initialize MAC
    TEST_ASSERT(0 == vccrypt_mac_init(&fixture.options, &context, &keybuf));

    //digest input
    TEST_ASSERT(0 == vccrypt_mac_digest(&context, DATA, sizeof(DATA)));

    //create output buffer
    TEST_ASSERT(
        0
            == vccrypt_buffer_init(
                    &outbuf, &fixture.alloc_opts, fixture.options.mac_size));

    //finalize hmac
    TEST_ASSERT(0 == vccrypt_mac_finalize(&context, &outbuf));

    //the HMAC output should match our expected HMAC
    TEST_ASSERT(0 == memcmp(outbuf.data, EXPECTED_HMAC, sizeof(EXPECTED_HMAC)));

    //clean up
    dispose((disposable_t*)&outbuf);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&keybuf);
END_TEST_F()

/**
 * We should be able to HMAC RFC-4231 Test Case 3.
 */
BEGIN_TEST_F(test_case_3)
    const uint8_t KEY[] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa
    };
    const uint8_t DATA[] = {
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd
    };
    const uint8_t EXPECTED_HMAC[] = {
        0xfa, 0x73, 0xb0, 0x08, 0x9d, 0x56, 0xa2, 0x84,
        0xef, 0xb0, 0xf0, 0x75, 0x6c, 0x89, 0x0b, 0xe9,
        0xb1, 0xb5, 0xdb, 0xdd, 0x8e, 0xe8, 0x1a, 0x36,
        0x55, 0xf8, 0x3e, 0x33, 0xb2, 0x27, 0x9d, 0x39,
        0xbf, 0x3e, 0x84, 0x82, 0x79, 0xa7, 0x22, 0xc8,
        0x06, 0xb4, 0x85, 0xa4, 0x7e, 0x67, 0xc8, 0x07,
        0xb9, 0x46, 0xa3, 0x37, 0xbe, 0xe8, 0x94, 0x26,
        0x74, 0x27, 0x88, 0x59, 0xe1, 0x32, 0x92, 0xfb
    };

    vccrypt_buffer_t keybuf, outbuf;
    vccrypt_mac_context_t context;

    //create key buffer
    TEST_ASSERT(
        0 == vccrypt_buffer_init(&keybuf, &fixture.alloc_opts, sizeof(KEY)));
    memcpy(keybuf.data, KEY, sizeof(KEY));

    //initialize MAC
    TEST_ASSERT(0 == vccrypt_mac_init(&fixture.options, &context, &keybuf));

    //digest input
    TEST_ASSERT(0 == vccrypt_mac_digest(&context, DATA, sizeof(DATA)));

    //create output buffer
    TEST_ASSERT(
        0
            == vccrypt_buffer_init(
                    &outbuf, &fixture.alloc_opts, fixture.options.mac_size));

    //finalize hmac
    TEST_ASSERT(0 == vccrypt_mac_finalize(&context, &outbuf));

    //the HMAC output should match our expected HMAC
    TEST_ASSERT(0 == memcmp(outbuf.data, EXPECTED_HMAC, sizeof(EXPECTED_HMAC)));

    //clean up
    dispose((disposable_t*)&outbuf);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&keybuf);
END_TEST_F()

/**
 * We should be able to HMAC RFC-4231 Test Case 4.
 */
BEGIN_TEST_F(test_case_4)
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
        0xb0, 0xba, 0x46, 0x56, 0x37, 0x45, 0x8c, 0x69,
        0x90, 0xe5, 0xa8, 0xc5, 0xf6, 0x1d, 0x4a, 0xf7,
        0xe5, 0x76, 0xd9, 0x7f, 0xf9, 0x4b, 0x87, 0x2d,
        0xe7, 0x6f, 0x80, 0x50, 0x36, 0x1e, 0xe3, 0xdb,
        0xa9, 0x1c, 0xa5, 0xc1, 0x1a, 0xa2, 0x5e, 0xb4,
        0xd6, 0x79, 0x27, 0x5c, 0xc5, 0x78, 0x80, 0x63,
        0xa5, 0xf1, 0x97, 0x41, 0x12, 0x0c, 0x4f, 0x2d,
        0xe2, 0xad, 0xeb, 0xeb, 0x10, 0xa2, 0x98, 0xdd
    };

    vccrypt_buffer_t keybuf, outbuf;
    vccrypt_mac_context_t context;

    //create key buffer
    TEST_ASSERT(
        0 == vccrypt_buffer_init(&keybuf, &fixture.alloc_opts, sizeof(KEY)));
    memcpy(keybuf.data, KEY, sizeof(KEY));

    //initialize MAC
    TEST_ASSERT(0 == vccrypt_mac_init(&fixture.options, &context, &keybuf));

    //digest input
    TEST_ASSERT(0 == vccrypt_mac_digest(&context, DATA, sizeof(DATA)));

    //create output buffer
    TEST_ASSERT(
        0
            == vccrypt_buffer_init(
                    &outbuf, &fixture.alloc_opts, fixture.options.mac_size));

    //finalize hmac
    TEST_ASSERT(0 == vccrypt_mac_finalize(&context, &outbuf));

    //the HMAC output should match our expected HMAC
    TEST_ASSERT(0 == memcmp(outbuf.data, EXPECTED_HMAC, sizeof(EXPECTED_HMAC)));

    //clean up
    dispose((disposable_t*)&outbuf);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&keybuf);
END_TEST_F()

/* test case 5 intentionally skipped; it's meaningless to us. */

/**
 * We should be able to HMAC RFC-4231 Test Case 6.
 */
BEGIN_TEST_F(test_case_6)
    const uint8_t KEY[] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa
    };
    const uint8_t DATA[] = {
        0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69,
        0x6e, 0x67, 0x20, 0x4c, 0x61, 0x72, 0x67, 0x65,
        0x72, 0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x42,
        0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a,
        0x65, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x2d, 0x20,
        0x48, 0x61, 0x73, 0x68, 0x20, 0x4b, 0x65, 0x79,
        0x20, 0x46, 0x69, 0x72, 0x73, 0x74
    };
    const uint8_t EXPECTED_HMAC[] = {
        0x80, 0xb2, 0x42, 0x63, 0xc7, 0xc1, 0xa3, 0xeb,
        0xb7, 0x14, 0x93, 0xc1, 0xdd, 0x7b, 0xe8, 0xb4,
        0x9b, 0x46, 0xd1, 0xf4, 0x1b, 0x4a, 0xee, 0xc1,
        0x12, 0x1b, 0x01, 0x37, 0x83, 0xf8, 0xf3, 0x52,
        0x6b, 0x56, 0xd0, 0x37, 0xe0, 0x5f, 0x25, 0x98,
        0xbd, 0x0f, 0xd2, 0x21, 0x5d, 0x6a, 0x1e, 0x52,
        0x95, 0xe6, 0x4f, 0x73, 0xf6, 0x3f, 0x0a, 0xec,
        0x8b, 0x91, 0x5a, 0x98, 0x5d, 0x78, 0x65, 0x98
    };

    vccrypt_buffer_t keybuf, outbuf;
    vccrypt_mac_context_t context;

    //create key buffer
    TEST_ASSERT(
        0 == vccrypt_buffer_init(&keybuf, &fixture.alloc_opts, sizeof(KEY)));
    memcpy(keybuf.data, KEY, sizeof(KEY));

    //initialize MAC
    TEST_ASSERT(0 == vccrypt_mac_init(&fixture.options, &context, &keybuf));

    //digest input
    TEST_ASSERT(0 == vccrypt_mac_digest(&context, DATA, sizeof(DATA)));

    //create output buffer
    TEST_ASSERT(
        0
            == vccrypt_buffer_init(
                    &outbuf, &fixture.alloc_opts, fixture.options.mac_size));

    //finalize hmac
    TEST_ASSERT(0 == vccrypt_mac_finalize(&context, &outbuf));

    //the HMAC output should match our expected HMAC
    TEST_ASSERT(0 == memcmp(outbuf.data, EXPECTED_HMAC, sizeof(EXPECTED_HMAC)));

    //clean up
    dispose((disposable_t*)&outbuf);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&keybuf);
END_TEST_F()

/**
 * We should be able to HMAC RFC-4231 Test Case 7.
 */
BEGIN_TEST_F(test_case_7)
    const uint8_t KEY[] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa
    };
    const uint8_t DATA[] = {
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x75,
        0x73, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x20, 0x6c,
        0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68,
        0x61, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
        0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x6b, 0x65,
        0x79, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x20,
        0x6c, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74,
        0x68, 0x61, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63,
        0x6b, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x64,
        0x61, 0x74, 0x61, 0x2e, 0x20, 0x54, 0x68, 0x65,
        0x20, 0x6b, 0x65, 0x79, 0x20, 0x6e, 0x65, 0x65,
        0x64, 0x73, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65,
        0x20, 0x68, 0x61, 0x73, 0x68, 0x65, 0x64, 0x20,
        0x62, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x20, 0x62,
        0x65, 0x69, 0x6e, 0x67, 0x20, 0x75, 0x73, 0x65,
        0x64, 0x20, 0x62, 0x79, 0x20, 0x74, 0x68, 0x65,
        0x20, 0x48, 0x4d, 0x41, 0x43, 0x20, 0x61, 0x6c,
        0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e
    };
    const uint8_t EXPECTED_HMAC[] = {
        0xe3, 0x7b, 0x6a, 0x77, 0x5d, 0xc8, 0x7d, 0xba,
        0xa4, 0xdf, 0xa9, 0xf9, 0x6e, 0x5e, 0x3f, 0xfd,
        0xde, 0xbd, 0x71, 0xf8, 0x86, 0x72, 0x89, 0x86,
        0x5d, 0xf5, 0xa3, 0x2d, 0x20, 0xcd, 0xc9, 0x44,
        0xb6, 0x02, 0x2c, 0xac, 0x3c, 0x49, 0x82, 0xb1,
        0x0d, 0x5e, 0xeb, 0x55, 0xc3, 0xe4, 0xde, 0x15,
        0x13, 0x46, 0x76, 0xfb, 0x6d, 0xe0, 0x44, 0x60,
        0x65, 0xc9, 0x74, 0x40, 0xfa, 0x8c, 0x6a, 0x58
    };

    vccrypt_buffer_t keybuf, outbuf;
    vccrypt_mac_context_t context;

    //create key buffer
    TEST_ASSERT(
        0 == vccrypt_buffer_init(&keybuf, &fixture.alloc_opts, sizeof(KEY)));
    memcpy(keybuf.data, KEY, sizeof(KEY));

    //initialize MAC
    TEST_ASSERT(0 == vccrypt_mac_init(&fixture.options, &context, &keybuf));

    //digest input
    TEST_ASSERT(0 == vccrypt_mac_digest(&context, DATA, sizeof(DATA)));

    //create output buffer
    TEST_ASSERT(
        0
            == vccrypt_buffer_init(
                    &outbuf, &fixture.alloc_opts, fixture.options.mac_size));

    //finalize hmac
    TEST_ASSERT(0 == vccrypt_mac_finalize(&context, &outbuf));

    //the HMAC output should match our expected HMAC
    TEST_ASSERT(0 == memcmp(outbuf.data, EXPECTED_HMAC, sizeof(EXPECTED_HMAC)));

    //clean up
    dispose((disposable_t*)&outbuf);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&keybuf);
END_TEST_F()

/**
 * Key exactly equals block size.
 */
BEGIN_TEST_F(test_key_block_size)
    const uint8_t KEY[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    const uint8_t DATA[] = {
        't', 'e', 's', 't'
    };
    const uint8_t EXPECTED_HMAC[] = {
        0xfb, 0x73, 0x32, 0xeb, 0xa8, 0xf7, 0xd2, 0x55,
        0x77, 0xf7, 0x6e, 0x13, 0x7a, 0x4e, 0xaf, 0xa2,
        0x60, 0xf4, 0x0d, 0xc6, 0xcc, 0x7a, 0xf5, 0xdf,
        0x95, 0x24, 0x32, 0xdc, 0xff, 0x27, 0x37, 0x99,
        0xd6, 0xc8, 0xc4, 0xff, 0x59, 0x00, 0x7b, 0xc7,
        0x85, 0xee, 0x6b, 0x52, 0x1a, 0x39, 0xe0, 0x36,
        0x21, 0x5c, 0x8d, 0x15, 0x7d, 0xdc, 0x62, 0xea,
        0x30, 0x13, 0x0d, 0xf9, 0x8a, 0x4d, 0xdd, 0x9a
    };

    vccrypt_buffer_t keybuf, outbuf;
    vccrypt_mac_context_t context;

    //create key buffer
    TEST_ASSERT(
        0 == vccrypt_buffer_init(&keybuf, &fixture.alloc_opts, sizeof(KEY)));
    memcpy(keybuf.data, KEY, sizeof(KEY));

    //initialize MAC
    TEST_ASSERT(0 == vccrypt_mac_init(&fixture.options, &context, &keybuf));

    //digest input
    TEST_ASSERT(0 == vccrypt_mac_digest(&context, DATA, sizeof(DATA)));

    //create output buffer
    TEST_ASSERT(
        0
            == vccrypt_buffer_init(
                    &outbuf, &fixture.alloc_opts, fixture.options.mac_size));

    //finalize hmac
    TEST_ASSERT(0 == vccrypt_mac_finalize(&context, &outbuf));

    //the HMAC output should match our expected HMAC
    TEST_ASSERT(0 == memcmp(outbuf.data, EXPECTED_HMAC, sizeof(EXPECTED_HMAC)));

    //clean up
    dispose((disposable_t*)&outbuf);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&keybuf);
END_TEST_F()

/**
 * Simple hash to re-use in the suite.
 */
BEGIN_TEST_F(test_case_8)
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

    vccrypt_buffer_t keybuf, outbuf;
    vccrypt_mac_context_t context;

    //create key buffer
    TEST_ASSERT(
        0 == vccrypt_buffer_init(&keybuf, &fixture.alloc_opts, sizeof(KEY)));
    memcpy(keybuf.data, KEY, sizeof(KEY));

    //initialize MAC
    TEST_ASSERT(0 == vccrypt_mac_init(&fixture.options, &context, &keybuf));

    //digest input
    TEST_ASSERT(0 == vccrypt_mac_digest(&context, DATA, sizeof(DATA)));

    //create output buffer
    TEST_ASSERT(
        0
            == vccrypt_buffer_init(
                    &outbuf, &fixture.alloc_opts, fixture.options.mac_size));

    //finalize hmac
    TEST_ASSERT(0 == vccrypt_mac_finalize(&context, &outbuf));

    //the HMAC output should match our expected HMAC
    TEST_ASSERT(0 == memcmp(outbuf.data, EXPECTED_HMAC, sizeof(EXPECTED_HMAC)));

    //clean up
    dispose((disposable_t*)&outbuf);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&keybuf);
END_TEST_F()
