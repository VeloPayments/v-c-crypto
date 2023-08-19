/**
 * \file test_vccrypt_prng_os.cpp
 *
 * Sanity test of the OS PRNG instance.
 *
 * \copyright 2017-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <string.h>
#include <vccrypt/prng.h>
#include <vpr/allocator/malloc_allocator.h>

class vccrypt_prng_os_test {
public:
    void setUp()
    {
        //make sure the OS PRNG has been registered
        vccrypt_prng_register_source_operating_system();

        malloc_allocator_options_init(&alloc_opts);
    }

    void tearDown()
    {
        dispose((disposable_t*)&alloc_opts);
    }

    allocator_options_t alloc_opts;
};

TEST_SUITE(vccrypt_prng_os_test);

#define BEGIN_TEST_F(name) \
TEST(name) \
{ \
    vccrypt_prng_os_test fixture; \
    fixture.setUp();

#define END_TEST_F() \
    fixture.tearDown(); \
}

/**
 * We should be able to get the OS PRNG source options.
 */
BEGIN_TEST_F(options_init)
    vccrypt_prng_options_t options;

    //options initialization should succeed
    TEST_ASSERT(
        0
            == vccrypt_prng_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM));

    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to initialize the OS PRNG.
 */
BEGIN_TEST_F(init)
    vccrypt_prng_options_t options;
    vccrypt_prng_context_t context;

    //options initialization should succeed
    TEST_ASSERT(
        0
            == vccrypt_prng_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM));

    //instance initialization should succeed
    TEST_ASSERT(0 == vccrypt_prng_init(&options, &context));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to read cryptographically random bytes from the OS PRNG.
 */
BEGIN_TEST_F(read)
    uint8_t zero_bytes[32] = { 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0 };

    vccrypt_prng_options_t options;
    vccrypt_prng_context_t context;
    vccrypt_buffer_t buffer;

    //options initialization should succeed
    TEST_ASSERT(
        0
            == vccrypt_prng_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM));

    //instance initialization should succeed
    TEST_ASSERT(0 == vccrypt_prng_init(&options, &context));

    //buffer creation should succeed
    TEST_ASSERT(0 == vccrypt_buffer_init(&buffer, &fixture.alloc_opts, 32));

    //PRECONDITION: set the buffer to all zeroes to cause the assertion below to
    //fail if the read does nothing
    memset(buffer.data, 0, 32);

    //prng read should succeed
    TEST_ASSERT(0 == vccrypt_prng_read(&context, &buffer, 32));

    //the data read should be random.  There's no good way to test for
    //randomness, so let's at least ensure that something was written, and it's
    //highly improbable that all zeros would have been written
    TEST_ASSERT(0 != memcmp(buffer.data, zero_bytes, 32));

    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
END_TEST_F()

/**
 * We should be able to read a uuid from the OS.
 */
BEGIN_TEST_F(read_uuid)
    vccrypt_prng_options_t options;
    vccrypt_prng_context_t context;
    vpr_uuid uuid;

    //options initialization should succeed
    TEST_ASSERT(
        0
            == vccrypt_prng_options_init(
                    &options, &fixture.alloc_opts,
                    VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM));

    //instance initialization should succeed
    TEST_ASSERT(0 == vccrypt_prng_init(&options, &context));

    //prng read uuid should succeed
    TEST_ASSERT(0 == vccrypt_prng_read_uuid(&context, &uuid));

    //clean up
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
END_TEST_F()
