/**
 * \file test_vccrypt_buffer_write_base64.cpp
 *
 * Unit tests for vccrypt_buffer_write_base64.
 *
 * \copyright 2017-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <iostream>
#include <minunit/minunit.h>
#include <string.h>
#include <vpr/allocator/malloc_allocator.h>
#include <vccrypt/buffer.h>

using namespace std;

class vccrypt_buffer_write_base64_test {
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

TEST_SUITE(vccrypt_buffer_write_base64_test);

#define BEGIN_TEST_F(name) \
TEST(name) \
{ \
    vccrypt_buffer_write_base64_test fixture; \
    fixture.setUp();

#define END_TEST_F() \
    fixture.tearDown(); \
}

/**
 * Test that we can write base64 values.
 */
BEGIN_TEST_F(simple_test)
    bool failFlag = false;
    const char* INPUTS[] = {
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
    size_t INPUT_LENS[] = {
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
    const char* OUTPUTS[] = {
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
    vccrypt_buffer_t source, dest;

    for (size_t i = 0; i < sizeof(INPUTS) / sizeof(const char*); ++i)
    {
        //create source buffer
        TEST_ASSERT(
            0 == vccrypt_buffer_init(
                    &source, &fixture.alloc_opts, INPUT_LENS[i]));

        //set data in source buffer
        memcpy(source.data, INPUTS[i], INPUT_LENS[i]);

        //create destination buffer
        TEST_ASSERT(
            0
                == vccrypt_buffer_init_for_base64_serialization(
                        &dest, &fixture.alloc_opts, INPUT_LENS[i]));

        //write Base64 data to output buffer.
        //buffer.
        TEST_ASSERT(0 == vccrypt_buffer_write_base64(&dest, &source));

        if (memcmp(dest.data, OUTPUTS[i], dest.size))
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
    vccrypt_buffer_t source, dest;

    //create source buffer
    TEST_ASSERT(0 == vccrypt_buffer_init(&source, &fixture.alloc_opts, 32));

    //create destination buffer
    TEST_ASSERT(
        0
            == vccrypt_buffer_init_for_base64_serialization(
                    &dest, &fixture.alloc_opts, 30));

    //the base64 write fails, because dest.size is too small.
    TEST_EXPECT(0 != vccrypt_buffer_write_base64(&dest, &source));

    //dispose buffers
    dispose((disposable_t*)&source);
    dispose((disposable_t*)&dest);
END_TEST_F()
