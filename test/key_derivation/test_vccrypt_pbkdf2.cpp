/**
 * \file test_vccrypt_pbkdf2.cpp
 *
 * Unit tests for pbkdf2
 *
 * \copyright 2019 Velo-Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vpr/parameters.h>
#include <vpr/allocator/malloc_allocator.h>
#include <vccrypt/key_derivation.h>
#include <vccrypt/mac.h>

#include "../../src/key_derivation/pbkdf2/pbkdf2.h"

static void key_derivation_test(allocator_options_t* alloc_opts,
    uint32_t hmac_algorithm, const char* password, const char* salt,
    int iterations, const char* expected);

static void to_hex(uint8_t vals[], size_t vals_len, char** hex);

using namespace std;

class vccrypt_pbkdf2_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        //make sure our key derivation algorithm has been registered
        vccrypt_key_derivation_register_pbkdf2();

        malloc_allocator_options_init(&alloc_opts);
    }

    void TearDown() override
    {
        dispose((disposable_t*)&alloc_opts);
    }

    allocator_options_t alloc_opts;
};


/**
 * We should be able to get pbkdf2 options using SHA-512 if it has been
 * registered.
 */
TEST_F(vccrypt_pbkdf2_test, options_init_sha512)
{
    vccrypt_key_derivation_options_t options;

    //we should be able to initialize options for this algorithm
    ASSERT_EQ(0,
        vccrypt_key_derivation_options_init(
            &options, &alloc_opts,
            VCCRYPT_KEY_DERIVATION_ALGORITHM_PBKDF2,
            VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC));

    EXPECT_EQ((unsigned int)VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC,
        options.hmac_algorithm);
    EXPECT_EQ(64u, options.hmac_digest_length);

    dispose((disposable_t*)&options);
}

/**
 * We should be able to get pbkdf2 options using SHA-512/256 if it has been
 * registered.
 */
TEST_F(vccrypt_pbkdf2_test, options_init_sha512_256)
{
    vccrypt_key_derivation_options_t options;

    //we should be able to initialize options for this algorithm
    ASSERT_EQ(0,
        vccrypt_key_derivation_options_init(
            &options, &alloc_opts,
            VCCRYPT_KEY_DERIVATION_ALGORITHM_PBKDF2,
            VCCRYPT_MAC_ALGORITHM_SHA_2_512_256_HMAC));

    EXPECT_EQ((unsigned int)VCCRYPT_MAC_ALGORITHM_SHA_2_512_256_HMAC,
        options.hmac_algorithm);
    EXPECT_EQ(32u, options.hmac_digest_length);

    dispose((disposable_t*)&options);
}

/**
 * We should be able to create a pbkdf2 instance.
 */
TEST_F(vccrypt_pbkdf2_test, init)
{
    vccrypt_key_derivation_options_t options;
    vccrypt_key_derivation_context_t context;

    //we should be able to initialize options for this algorithm
    ASSERT_EQ(0,
        vccrypt_key_derivation_options_init(
            &options, &alloc_opts,
            VCCRYPT_KEY_DERIVATION_ALGORITHM_PBKDF2,
            VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC));

    //we should be able to create an algorithm instance
    ASSERT_EQ(0, vccrypt_key_derivation_init(&context, &options));

    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
}

/**
 * Verify the derived key matches expected results.  At the time these
 * were written there doesn't appear to be an "official" set of published
 * tests.  These were taken from
 * https://stackoverflow.com/questions/15593184/pbkdf2-hmac-sha-512-test-vectors
 */
TEST_F(vccrypt_pbkdf2_test, sha512_test_vector_1)
{
    const char* password = "password";

    const char* salt = "salt";

    const char* expected = "0x"
                           "867F70CF1ADE02CF"
                           "F3752599A3A53DC4"
                           "AF34C7A669815AE5"
                           "D513554E1C8CF252"
                           "C02D470A285A0501"
                           "BAD999BFE943C08F"
                           "050235D7D68B1DA5"
                           "5E63F73B60A57FCE";

    key_derivation_test(
        &alloc_opts, VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC, password, salt,
        1, expected);
}

TEST_F(vccrypt_pbkdf2_test, sha512_test_vector_2)
{
    const char* password = "password";

    const char* salt = "salt";

    const char* expected = "0x"
                           "E1D9C16AA681708A"
                           "45F5C7C4E215CEB6"
                           "6E011A2E9F004071"
                           "3F18AEFDB866D53C"
                           "F76CAB2868A39B9F"
                           "7840EDCE4FEF5A82"
                           "BE67335C77A6068E"
                           "04112754F27CCF4E";

    key_derivation_test(
        &alloc_opts, VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC, password, salt,
        2, expected);
}

TEST_F(vccrypt_pbkdf2_test, sha512_test_vector_3)
{
    const char* password = "password";

    const char* salt = "salt";

    const char* expected = "0x"
                           "D197B1B33DB0143E"
                           "018B12F3D1D1479E"
                           "6CDEBDCC97C5C0F8"
                           "7F6902E072F457B5"
                           "143F30602641B3D5"
                           "5CD335988CB36B84"
                           "376060ECD532E039"
                           "B742A239434AF2D5";

    key_derivation_test(
        &alloc_opts, VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC, password, salt,
        4096, expected);
}

TEST_F(vccrypt_pbkdf2_test, sha512_test_vector_4)
{
    const char* password = "passwordPASSWORDpassword";

    const char* salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt";

    const char* expected = "0x"
                           "8C0511F4C6E597C6"
                           "AC6315D8F0362E22"
                           "5F3C501495BA23B8"
                           "68C005174DC4EE71"
                           "115B59F9E60CD953"
                           "2FA33E0F75AEFE30"
                           "225C583A186CD82B"
                           "D4DAEA9724A3D3B8";

    key_derivation_test(
        &alloc_opts, VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC, password, salt,
        4096, expected);
}

TEST_F(vccrypt_pbkdf2_test, sha512_test_vector_5)
{
    const char* password = "passDATAb00AB7YxDTT";

    const char* salt = "saltKEYbcTcXHCBxtjD";

    const char* expected = "0x"
                           "CBE6088AD4359AF4"
                           "2E603C2A33760EF9"
                           "D4017A7B2AAD10AF"
                           "46F992C660A0B461"
                           "ECB0DC2A79C25709"
                           "41BEA6A08D15D688"
                           "7E79F32B132E1C13"
                           "4E9525EEDDD744FA";

    key_derivation_test(
        &alloc_opts, VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC, password, salt,
        1, expected);
}

TEST_F(vccrypt_pbkdf2_test, sha512_test_vector_6)
{
    const char* password = "passDATAb00AB7YxDTT";

    const char* salt = "saltKEYbcTcXHCBxtjD";

    const char* expected = "0x"
                           "ACCDCD8798AE5CD8"
                           "5804739015EF2A11"
                           "E32591B7B7D16F76"
                           "819B30B0D49D80E1"
                           "ABEA6C9822B80A1F"
                           "DFE421E26F5603EC"
                           "A8A47A64C9A004FB"
                           "5AF8229F762FF41F";

    key_derivation_test(
        &alloc_opts, VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC, password, salt,
        100000, expected);
}

TEST_F(vccrypt_pbkdf2_test, sha512_test_vector_7)
{
    const char* password =
        "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5";

    const char* salt =
        "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe";

    const char* expected = "0x"
                           "07447401C85766E4"
                           "AED583DE2E6BF5A6"
                           "75EABE4F3618281C"
                           "95616F4FC1FDFE6E"
                           "CBC1C3982789D4FD"
                           "941D6584EF534A78"
                           "BD37AE02555D9455"
                           "E8F089FDB4DFB6BB";

    key_derivation_test(
        &alloc_opts, VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC, password, salt,
        100000, expected);
}

TEST_F(vccrypt_pbkdf2_test, sha512_test_vector_8)
{
    const char* password =
        "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un"
        "4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0";

    const char* salt =
        "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkU"
        "RWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy";

    const char* expected = "0x"
                           "16226C85E4F8D604"
                           "573008BFE61C10B6"
                           "947B53990450612D"
                           "D4A3077F7DEE2116"
                           "229E68EFD1DF6D73"
                           "BD3C6D07567790EE"
                           "A1E8B2AE9A1B046B"
                           "E593847D9441A1B7";

    key_derivation_test(
        &alloc_opts, VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC, password, salt,
        1, expected);
}

TEST_F(vccrypt_pbkdf2_test, sha512_test_vector_9)
{
    const char* password =
        "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un"
        "4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U";

    const char* salt =
        "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkU"
        "RWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P";

    const char* expected = "0x"
                           "2575B485AFDF37C2"
                           "60B8F3386D33A60E"
                           "D929993C9D48AC51"
                           "6EC66B87E06BE54A"
                           "DE7E7C8CB3417C81"
                           "603B080A8EEFC560"
                           "72811129737CED96"
                           "236B9364E22CE3A5";

    key_derivation_test(
        &alloc_opts, VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC, password, salt,
        100000, expected);
}

TEST_F(vccrypt_pbkdf2_test, sha512_test_vector_10)
{
    const char* password = "passDATAb00AB";

    const char* salt = "saltKEYbcTcX";

    const char* expected = "0x"
                           "C8CB4B4B498B32CD"
                           "E191159866A8E86B"
                           "4C9D84EF1D0A37CF"
                           "7B9BDC7872EDD5F0"
                           "2242AA7D83172C77"
                           "8EF64C788D622ACB"
                           "CD4317C4B63A2EDE"
                           "184CB2A5F6B94815";

    key_derivation_test(
        &alloc_opts, VCCRYPT_MAC_ALGORITHM_SHA_2_512_HMAC, password, salt,
        2097152, expected);
}

/**
 * TODO: we don't have a test vector for SHA-512/256, but we can at least
 * verify the algorithm produced something that looks sane.
 */
TEST_F(vccrypt_pbkdf2_test, sha512_256_test_vector_1)
{
    const char* password = "password";

    const char* salt = "salt";

    const char* expected = NULL;

    key_derivation_test(
        &alloc_opts, VCCRYPT_MAC_ALGORITHM_SHA_2_512_256_HMAC,
        password, salt, 10, expected);
}


/**
 * Test utility function to DRY up matching against test vectors
 *
 * expected is optional.  if unknown, pass NULL and the test will simply
 * assert the derived key is not all 0's.
 */
static void key_derivation_test(allocator_options_t* alloc_opts,
    uint32_t hmac_algorithm, const char* password, const char* salt,
    int iterations, const char* expected)
{
    vccrypt_key_derivation_options_t options;
    vccrypt_key_derivation_context_t context;

    ASSERT_EQ(0,
        vccrypt_key_derivation_options_init(
            &options, alloc_opts,
            VCCRYPT_KEY_DERIVATION_ALGORITHM_PBKDF2,
            hmac_algorithm));

    ASSERT_EQ(0, vccrypt_key_derivation_init(&context, &options));

    // construct a buffer for the password
    vccrypt_buffer_t password_buffer;
    ASSERT_EQ(0,
        vccrypt_buffer_init(
            &password_buffer, alloc_opts, strlen(password)));
    memcpy(password_buffer.data, password, strlen(password));


    // construct a buffer for the salt
    vccrypt_buffer_t salt_buffer;
    ASSERT_EQ(0,
        vccrypt_buffer_init(
            &salt_buffer, alloc_opts, strlen(salt)));
    memcpy(salt_buffer.data, salt, strlen(salt));


    // construct a buffer for the derived key
    vccrypt_buffer_t dk_buffer;
    ASSERT_EQ(0,
        vccrypt_buffer_init(
            &dk_buffer, alloc_opts, options.hmac_digest_length));

    ASSERT_EQ(0,
        vccrypt_key_derivation_derive_key(&dk_buffer,
            &context, &password_buffer, &salt_buffer, iterations));

    if (NULL != expected)
    {
        char* hex;
        to_hex((uint8_t*)dk_buffer.data, dk_buffer.size, &hex);

        EXPECT_EQ(0, memcmp(hex, expected, strlen(expected)));
        free(hex);
    }
    else
    {
        uint8_t test_block[dk_buffer.size];
        memset(test_block, 0, sizeof(test_block));

        EXPECT_NE(0, memcmp(dk_buffer.data, test_block, sizeof(test_block)));
    }


    dispose((disposable_t*)&dk_buffer);
    dispose((disposable_t*)&salt_buffer);
    dispose((disposable_t*)&password_buffer);
    dispose((disposable_t*)&context);
    dispose((disposable_t*)&options);
}

/**
 * Convert an array of uint8_t values to a hex string.
 * e.g. 0x1EF3
 */
static void to_hex(uint8_t vals[], size_t vals_len, char** hex)
{
    // allocate enough space for two characters per (hex) value,
    // plus the preceding "0x" and trailing terminator.
    char* cp = (char*)malloc((vals_len * 2 + 3) * sizeof(char));
    *hex = cp;

    sprintf(cp, "0x");

    for (unsigned int i = 0; i < vals_len; i++)
    {
        cp += 2;
        sprintf(cp, "%02X", vals[i]);
    }
}
