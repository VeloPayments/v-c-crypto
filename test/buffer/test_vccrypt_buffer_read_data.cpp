/**
 * \file test_vccrypt_buffer_read_data.cpp
 *
 * Unit tests for vccrypt_buffer_read_data.
 *
 * \copyright 2017-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <string.h>
#include <vpr/allocator/malloc_allocator.h>
#include <vccrypt/buffer.h>

class vccrypt_buffer_read_data_test {
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

TEST_SUITE(vccrypt_buffer_read_data_test);

#define BEGIN_TEST_F(name) \
TEST(name) \
{ \
    vccrypt_buffer_read_data_test fixture; \
    fixture.setUp();

#define END_TEST_F() \
    fixture.tearDown(); \
}

/**
 * Test that we can read a C array into a buffer.
 */
BEGIN_TEST_F(simple_test)
    size_t BUFFER_SIZE = 16;
    vccrypt_buffer_t source, dest;

    //create source buffer
    TEST_ASSERT(
        0 == vccrypt_buffer_init(&source, &fixture.alloc_opts, BUFFER_SIZE));

    //set data in source buffer
    memset(source.data, 0xF7, BUFFER_SIZE);

    //create destination buffer
    TEST_ASSERT(
        0 == vccrypt_buffer_init(&dest, &fixture.alloc_opts, BUFFER_SIZE));

    //set data in destination
    memset(dest.data, 0x1A, BUFFER_SIZE);

    //the two buffers do not match
    TEST_ASSERT(0 != memcmp(dest.data, source.data, BUFFER_SIZE));

    //copy the source data to the dest buffer, treating the source buffer as a C
    //array.
    TEST_ASSERT(0 == vccrypt_buffer_read_data(&dest, source.data, BUFFER_SIZE));

    //the two buffers should now match
    TEST_EXPECT(0 == memcmp(dest.data, source.data, BUFFER_SIZE));

    //dispose buffers
    dispose((disposable_t*)&source);
    dispose((disposable_t*)&dest);
END_TEST_F()

/**
 * Test that attempting to copy more data than in the destination buffer results
 * in an error.
 */
BEGIN_TEST_F(size_mismatch)
    size_t BUFFER_SIZE = 16;
    vccrypt_buffer_t source, dest;

    //create source buffer
    TEST_ASSERT(
        0
            == vccrypt_buffer_init(
                    &source, &fixture.alloc_opts, BUFFER_SIZE + 1));

    //create destination buffer
    TEST_ASSERT(
        0 == vccrypt_buffer_init(&dest, &fixture.alloc_opts, BUFFER_SIZE));

    //the data read should fail.
    TEST_EXPECT(
        0 != vccrypt_buffer_read_data(&dest, source.data, BUFFER_SIZE + 1));

    //dispose buffers
    dispose((disposable_t*)&source);
    dispose((disposable_t*)&dest);
END_TEST_F()
