/**
 * \file inline_support.h
 *
 * \brief Provide inline support through macros.
 *
 * Debug mode turns off inlining, and in that case, it must be possible to grab
 * the definitions for inline functions.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

/* At the beginning of this header, remove previous macro definitions. */
#undef VCCRYPT_INLINE
#undef VCCRYPT_INLINE_DEFINITION

/* The concrete definition is defined in the concrete_impl file for a module.
 * In that case, inline functions become concrete.
 */
#if defined(VCCRYPT_CONCRETE_IMPLEMENTATION)
# define VCCRYPT_INLINE
# define VCCRYPT_INLINE_DEFINITION(x) x

/* Otherwise, in debug mode, inline is meaningless, so fall back to decls;
 * The definitions will be resolved at link time, using the concrete_impl file
 * for each module.
 */
#elif defined(DEBUG)
# define VCCRYPT_INLINE
# define VCCRYPT_INLINE_DEFINITION(x) ;

/* In release mode, the compiler will inline functions. */
#else
# define VCCRYPT_INLINE inline
# define VCCRYPT_INLINE_DEFINITION(x) x
#endif
