/**
 * \file test_vccrypt_prng_os.cpp
 *
 * Sanity test of the OS PRNG instance.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vccrypt/prng.h>
#include <vpr/allocator/malloc_allocator.h>

class vccrypt_prng_os_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        //make sure the OS PRNG has been registered
        vccrypt_prng_register_source_operating_system();

        malloc_allocator_options_init(&alloc_opts);
    }

    void TearDown() override
    {
        dispose((disposable_t*)&alloc_opts);
    }

    allocator_options_t alloc_opts;
};

/**
 * We should be able to get the OS PRNG source options.
 */
TEST_F(vccrypt_prng_os_test, options_init)
{
    vccrypt_prng_options_t options;

    //options initialization should succeed
    ASSERT_EQ(0,
        vccrypt_prng_options_init(
            &options, &alloc_opts, VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM));

    dispose((disposable_t*)&options);
}

/**
 * We should be able to initialize the OS PRNG.
 */
TEST_F(vccrypt_prng_os_test, init)
{
    vccrypt_prng_options_t options;
    vccrypt_prng_context_t context;

    //options initialization should succeed
    ASSERT_EQ(0,
        vccrypt_prng_options_init(
            &options, &alloc_opts, VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM));

    //instance initialization should succeed
    ASSERT_EQ(0,
        vccrypt_prng_init(
            &options, &context));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
}

/**
 * We should be able to read cryptographically random bytes from the OS PRNG.
 */
TEST_F(vccrypt_prng_os_test, read)
{
    uint8_t zero_bytes[32] = { 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0 };

    vccrypt_prng_options_t options;
    vccrypt_prng_context_t context;
    vccrypt_buffer_t buffer;

    //options initialization should succeed
    ASSERT_EQ(0,
        vccrypt_prng_options_init(
            &options, &alloc_opts, VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM));

    //instance initialization should succeed
    ASSERT_EQ(0,
        vccrypt_prng_init(
            &options, &context));

    //buffer creation should succeed
    ASSERT_EQ(0,
        vccrypt_buffer_init(&buffer, &alloc_opts, 32));

    //PRECONDITION: set the buffer to all zeroes to cause the assertion below to
    //fail if the read does nothing
    memset(buffer.data, 0, 32);

    //prng read should succeed
    ASSERT_EQ(0,
        vccrypt_prng_read(&context, &buffer, 32));

    //the data read should be random.  There's no good way to test for
    //randomness, so let's at least ensure that something was written, and it's
    //highly improbable that all zeros would have been written
    ASSERT_NE(0,
        memcmp(buffer.data, zero_bytes, 32));

    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
}

/**
 * We should be able to read a uuid from the OS.
 */
TEST_F(vccrypt_prng_os_test, read_uuid)
{
    vccrypt_prng_options_t options;
    vccrypt_prng_context_t context;
    vpr_uuid uuid;

    //options initialization should succeed
    ASSERT_EQ(0,
        vccrypt_prng_options_init(
            &options, &alloc_opts, VCCRYPT_PRNG_SOURCE_OPERATING_SYSTEM));

    //instance initialization should succeed
    ASSERT_EQ(0,
        vccrypt_prng_init(
            &options, &context));

    //prng read uuid should succeed
    ASSERT_EQ(0,
        vccrypt_prng_read_uuid(&context, &uuid));

    //clean up
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
}
