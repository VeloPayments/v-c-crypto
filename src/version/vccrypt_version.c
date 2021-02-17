/**
 * \file version/vccrypt_version.c
 *
 * Return the version of vccrypt as a constant string.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <config.h>
#include <vccrypt/version.h>

/**
 * \brief Return the version string for the vccrypt library.
 *
 * \returns a const version string for this library.
 */
const char* vccrypt_version()
{
    return VCCRYPT_VERSION;
}
