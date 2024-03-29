/**
 * \file test_vccrypt_buffer_read_base64.cpp
 *
 * Unit tests for vccrypt_buffer_read_base64.
 *
 * \copyright 2017-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <iostream>
#include <minunit/minunit.h>
#include <string.h>
#include <vpr/allocator/malloc_allocator.h>
#include <vccrypt/buffer.h>

using namespace std;

class vccrypt_buffer_read_base64_test {
public:
    void setUp()
    {
        malloc_allocator_options_init(&alloc_opts);
    }

    void tearDown()
    {
        dispose((disposable_t*)&alloc_opts);
    }

    allocator_options_t alloc_opts;
};

TEST_SUITE(vccrypt_buffer_read_base64_test);

#define BEGIN_TEST_F(name) \
TEST(name) \
{ \
    vccrypt_buffer_read_base64_test fixture; \
    fixture.setUp();

#define END_TEST_F() \
    fixture.tearDown(); \
}

/**
 * Test that we can read base64 values.
 */
BEGIN_TEST_F(simple_test)
    bool failFlag = false;
    const char* OUTPUTS[] = {
        "f",
        "fo",
        "foo",
        "foob",
        "fooba",
        "foobar",
        "\x14\xfb\x9c\x03\xd9\x7e",
        "\x14\xfb\x9c\x03\xd9",
        "\x14\xfb\x9c\x03"
    };
    size_t OUTPUT_LENS[] = {
        1,
        2,
        3,
        4,
        5,
        6,
        6,
        5,
        4
    };
    const char* INPUTS[] = {
        "Zg==",
        "Zm8=",
        "Zm9v",
        "Zm9vYg==",
        "Zm9vYmE=",
        "Zm9vYmFy",
        "FPucA9l+",
        "FPucA9k=",
        "FPucAw=="
    };
    size_t INPUT_LENS[] = {
        4,
        4,
        4,
        8,
        8,
        8,
        8,
        8,
        8
    };
    vccrypt_buffer_t source, dest;

    for (size_t i = 0; i < sizeof(INPUTS) / sizeof(const char*); ++i)
    {
        size_t outlen = 0;

        //create source buffer
        TEST_ASSERT(
            0
                == vccrypt_buffer_init(
                        &source, &fixture.alloc_opts, INPUT_LENS[i]));

        //set data in source buffer
        memcpy(source.data, INPUTS[i], INPUT_LENS[i]);

        //create destination buffer
        TEST_ASSERT(
            0
                == vccrypt_buffer_init(
                        &dest, &fixture.alloc_opts, INPUT_LENS[i]));

        //read Base64 data from input buffer.
        TEST_ASSERT(
            0 == vccrypt_buffer_read_base64(&dest, &source, &outlen));

        //the number of written bytes should match what we expect
        TEST_EXPECT(OUTPUT_LENS[i] == outlen);

        //the output buffer should match what we expect
        if (memcmp(dest.data, OUTPUTS[i], OUTPUT_LENS[i]))
        {
            cout << "Array values differ for test " << i + 1 << ".  Expected '";
            cout.write(OUTPUTS[i], dest.size);
            cout << "' but got '";
            cout.write((const char*)dest.data, dest.size);
            cout << "'" << endl;

            failFlag = true;
        }

        //dispose buffers
        dispose((disposable_t*)&source);
        dispose((disposable_t*)&dest);
    }

    if (failFlag)
        TEST_FAILURE();
END_TEST_F()

/**
 * Test that we can read base64 values, ignoring non-Base64 data.
 */
BEGIN_TEST_F(ignore_non_base64)
    bool failFlag = false;
    const char* OUTPUTS[] = {
        "f",
        "fo",
        "foo",
        "foob",
        "fooba",
        "foobar",
        "\x14\xfb\x9c\x03\xd9\x7e",
        "\x14\xfb\x9c\x03\xd9",
        "\x14\xfb\x9c\x03"
    };
    size_t OUTPUT_LENS[] = {
        1,
        2,
        3,
        4,
        5,
        6,
        6,
        5,
        4
    };
    const char* INPUTS[] = {
        "Zg\n==",
        "Zm8 =",
        "\tZm9v",
        "--Zm9vYg==",
        "Z m9v,YmE=",
        "Zm9vY\vmFy",
        "FPucA\r9l+",
        "FPuc A9k=",
        "FPucAw== "
    };
    size_t INPUT_LENS[] = {
        5,
        5,
        5,
        10,
        10,
        9,
        9,
        9,
        9
    };
    vccrypt_buffer_t source, dest;

    for (size_t i = 0; i < sizeof(INPUTS) / sizeof(const char*); ++i)
    {
        size_t outlen = 0;

        //create source buffer
        TEST_ASSERT(
            0
                == vccrypt_buffer_init(
                        &source, &fixture.alloc_opts, INPUT_LENS[i]));

        //set data in source buffer
        memcpy(source.data, INPUTS[i], INPUT_LENS[i]);

        //create destination buffer
        TEST_ASSERT(
            0
                == vccrypt_buffer_init(
                        &dest, &fixture.alloc_opts, INPUT_LENS[i]));

        //read Base64 data from input buffer.
        TEST_ASSERT(0 == vccrypt_buffer_read_base64(&dest, &source, &outlen));

        //the number of written bytes should match what we expect
        TEST_EXPECT(OUTPUT_LENS[i] == outlen);

        //the output buffer should match what we expect
        if (memcmp(dest.data, OUTPUTS[i], OUTPUT_LENS[i]))
        {
            cout << "Array values differ for test " << i + 1 << ".  Expected '";
            cout.write(OUTPUTS[i], dest.size);
            cout << "' but got '";
            cout.write((const char*)dest.data, dest.size);
            cout << "'" << endl;

            failFlag = true;
        }

        //dispose buffers
        dispose((disposable_t*)&source);
        dispose((disposable_t*)&dest);
    }

    if (failFlag)
        TEST_FAILURE();
END_TEST_F()

/**
 * Test that a size mismatch results in an error.
 */
BEGIN_TEST_F(size_mismatch)
    size_t outlen;
    vccrypt_buffer_t source, dest;

    //create source buffer
    TEST_ASSERT(0 == vccrypt_buffer_init(&source, &fixture.alloc_opts, 32));

    //create destination buffer
    TEST_ASSERT(0 == vccrypt_buffer_init(&dest, &fixture.alloc_opts, 3));

    //fail.
    TEST_ASSERT(0 != vccrypt_buffer_read_base64(&dest, &source, &outlen));

    dispose((disposable_t*)&source);
    dispose((disposable_t*)&dest);
END_TEST_F()
