/**
 * \file os.h
 *
 * Operating system checks.
 *
 * This header file defines a set of macros that can be used to determine some
 * OS characteristics needed for managing OS resources upon which the crypto
 * library might depend.
 */

#ifndef VCCRYPT_OS_HEADER_GUARD
#define VCCRYPT_OS_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/* The VCCRYPT_OS_UNIX macro is defined for Unix-like systems. */
#if defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
#define VCCRYPT_OS_UNIX
#else
#undef VCCRYPT_OS_UNIX
#endif

/* The VCCRYPT_OS_WINDOWS macro is defined for Windows-like systems. */
#if defined(_WIN32) || defined(_WIN64)
#define VCCRYPT_OS_WINDOWS
#else
#undef VCCRYPT_OS_WINDOWS
#endif

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCRYPT_OS_HEADER_GUARD
